// Package webhookegress registers HTTPS webhook endpoints, signs payloads, and
// delivers events with bounded concurrency and per-owner rate limits.
//
// Status: CANDIDATE. Capability: delivery.webhook-egress.
package webhookegress

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	ErrInvalid  = errors.New("webhookegress: invalid input")
	ErrNotFound = errors.New("webhookegress: not found")
	ErrExists   = errors.New("webhookegress: already exists")
	ErrDenied   = errors.New("webhookegress: denied")
)

const (
	StatusPending     = "pending"
	StatusDelivered   = "delivered"
	StatusFailed      = "failed"
	StatusRateLimited = "rate_limited"

	defaultMaxConcurrent = 10
	defaultMaxPerHour    = 100
	secretBytes          = 32
	SignatureHeader      = "X-AMSL-Signature"
)

// Endpoint is a registered destination.
type Endpoint struct {
	ID        string
	OwnerID   string
	URL       string
	Secret    string // plaintext only at create; stores hold digest+reveal once
	SecretDigest [32]byte
	Events    []string
	Active    bool
	CreatedAt time.Time
}

// Delivery is one outbound attempt record.
type Delivery struct {
	ID         string
	OwnerID    string
	EndpointID string
	EventType  string
	Payload    []byte
	Status     string
	Attempts   int
	LastError  string
	CreatedAt  time.Time
	DeliveredAt time.Time
}

// Store persists endpoints and deliveries.
type Store interface {
	CreateEndpoint(context.Context, Endpoint) error
	LookupEndpoint(context.Context, string) (Endpoint, error)
	ListEndpointsByEvent(ctx context.Context, ownerID, eventType string) ([]Endpoint, error)
	PutDelivery(context.Context, Delivery) error
	UpdateDelivery(context.Context, Delivery) error
}

// Config for the dispatcher.
type Config struct {
	MaxConcurrent     int
	MaxDeliveriesHour int
	HTTPClient        *http.Client
}

// Dispatcher emits and delivers signed webhooks.
type Dispatcher struct {
	cfg    Config
	store  Store
	http   *http.Client
	sem    chan struct{}
	limit  *ownerLimiter
	now    func() time.Time
	idFn   func() (string, error)
}

// New constructs a Dispatcher.
func New(cfg Config, store Store) (*Dispatcher, error) {
	if store == nil {
		return nil, ErrInvalid
	}
	if cfg.MaxConcurrent <= 0 {
		cfg.MaxConcurrent = defaultMaxConcurrent
	}
	if cfg.MaxDeliveriesHour <= 0 {
		cfg.MaxDeliveriesHour = defaultMaxPerHour
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	return &Dispatcher{
		cfg: cfg, store: store, http: hc,
		sem: make(chan struct{}, cfg.MaxConcurrent),
		limit: newOwnerLimiter(cfg.MaxDeliveriesHour, time.Hour),
		now: time.Now, idFn: randomID,
	}, nil
}

// CreateEndpointInput registers an endpoint. Secret is returned once.
type CreateEndpointInput struct {
	OwnerID string
	URL     string
	Events  []string
}

// CreateEndpointResult includes the plaintext signing secret once.
type CreateEndpointResult struct {
	Endpoint Endpoint
	Secret   string
}

// CreateEndpoint validates https URL and stores hashed secret.
func (d *Dispatcher) CreateEndpoint(ctx context.Context, in CreateEndpointInput) (CreateEndpointResult, error) {
	if err := ctx.Err(); err != nil {
		return CreateEndpointResult{}, err
	}
	if in.OwnerID == "" || len(in.Events) == 0 {
		return CreateEndpointResult{}, ErrInvalid
	}
	if err := validateHTTPSURL(in.URL); err != nil {
		return CreateEndpointResult{}, err
	}
	secret, err := randomToken(secretBytes)
	if err != nil {
		return CreateEndpointResult{}, err
	}
	id, err := d.idFn()
	if err != nil {
		return CreateEndpointResult{}, err
	}
	now := d.now().UTC()
	ep := Endpoint{
		ID: id, OwnerID: in.OwnerID, URL: in.URL,
		SecretDigest: sha256.Sum256([]byte(secret)),
		Events: append([]string(nil), in.Events...),
		Active: true, CreatedAt: now,
	}
	if err := d.store.CreateEndpoint(ctx, ep); err != nil {
		return CreateEndpointResult{}, err
	}
	ep.Secret = secret
	return CreateEndpointResult{Endpoint: ep, Secret: secret}, nil
}

// Emit queues deliveries for matching endpoints. secretByEndpoint supplies
// plaintext secrets (caller vault); if empty, signing uses only digest check
// skip — callers must pass secrets map from their secure store.
func (d *Dispatcher) Emit(ctx context.Context, ownerID, eventType string, payload []byte, secrets map[string]string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if ownerID == "" || eventType == "" || len(payload) == 0 {
		return ErrInvalid
	}
	eps, err := d.store.ListEndpointsByEvent(ctx, ownerID, eventType)
	if err != nil {
		return err
	}
	for _, ep := range eps {
		if !ep.Active {
			continue
		}
		status := StatusPending
		if !d.limit.allow(ownerID) {
			status = StatusRateLimited
		}
		id, err := d.idFn()
		if err != nil {
			return err
		}
		now := d.now().UTC()
		del := Delivery{
			ID: id, OwnerID: ownerID, EndpointID: ep.ID, EventType: eventType,
			Payload: append([]byte(nil), payload...), Status: status, CreatedAt: now,
		}
		if err := d.store.PutDelivery(ctx, del); err != nil {
			return err
		}
		if status == StatusRateLimited {
			continue
		}
		secret := secrets[ep.ID]
		go d.deliver(ep, del, secret)
	}
	return nil
}

func (d *Dispatcher) deliver(ep Endpoint, del Delivery, secret string) {
	d.sem <- struct{}{}
	defer func() { <-d.sem }()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	del.Attempts++
	if secret == "" {
		del.Status = StatusFailed
		del.LastError = "missing signing secret"
		_ = d.store.UpdateDelivery(ctx, del)
		return
	}
	ts := strconv.FormatInt(d.now().UTC().Unix(), 10)
	sig := Sign(secret, ts, del.Payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ep.URL, bytes.NewReader(del.Payload))
	if err != nil {
		del.Status = StatusFailed
		del.LastError = err.Error()
		_ = d.store.UpdateDelivery(ctx, del)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(SignatureHeader, fmt.Sprintf("t=%s,v1=%s", ts, sig))
	resp, err := d.http.Do(req)
	if err != nil {
		del.Status = StatusFailed
		del.LastError = err.Error()
		_ = d.store.UpdateDelivery(ctx, del)
		return
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		del.Status = StatusDelivered
		del.DeliveredAt = d.now().UTC()
		del.LastError = ""
	} else {
		del.Status = StatusFailed
		del.LastError = fmt.Sprintf("status %d", resp.StatusCode)
	}
	_ = d.store.UpdateDelivery(ctx, del)
}

// Sign returns hex HMAC-SHA256 of ts + "." + body.
func Sign(secret, ts string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(ts))
	_, _ = mac.Write([]byte("."))
	_, _ = mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// Verify checks a signature header within skew.
func Verify(secret, header string, body []byte, skew time.Duration, now time.Time) bool {
	tStr, v1, ok := parseSigHeader(header)
	if !ok {
		return false
	}
	ts, err := strconv.ParseInt(tStr, 10, 64)
	if err != nil {
		return false
	}
	if skew <= 0 {
		skew = 5 * time.Minute
	}
	diff := now.UTC().Unix() - ts
	if diff < 0 {
		diff = -diff
	}
	if diff > int64(skew.Seconds()) {
		return false
	}
	expected := Sign(secret, tStr, body)
	return hmac.Equal([]byte(expected), []byte(v1))
}

func parseSigHeader(h string) (t, v1 string, ok bool) {
	parts := strings.Split(h, ",")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if strings.HasPrefix(p, "t=") {
			t = strings.TrimPrefix(p, "t=")
		}
		if strings.HasPrefix(p, "v1=") {
			v1 = strings.TrimPrefix(p, "v1=")
		}
	}
	return t, v1, t != "" && v1 != ""
}

func validateHTTPSURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Fragment != "" || u.Host == "" {
		return fmt.Errorf("%w: URL must be absolute without fragment", ErrInvalid)
	}
	if u.Scheme == "https" {
		return nil
	}
	if u.Scheme == "http" {
		h := u.Hostname()
		if h == "localhost" || h == "127.0.0.1" || h == "::1" {
			return nil
		}
	}
	return fmt.Errorf("%w: URL must be https (or http loopback)", ErrInvalid)
}

func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func randomID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

type ownerLimiter struct {
	mu      sync.Mutex
	max     int
	window  time.Duration
	hits    map[string][]time.Time
}

func newOwnerLimiter(max int, window time.Duration) *ownerLimiter {
	return &ownerLimiter{max: max, window: window, hits: map[string][]time.Time{}}
}

func (l *ownerLimiter) allow(owner string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	cut := now.Add(-l.window)
	arr := l.hits[owner]
	j := 0
	for _, t := range arr {
		if t.After(cut) {
			arr[j] = t
			j++
		}
	}
	arr = arr[:j]
	if len(arr) >= l.max {
		l.hits[owner] = arr
		return false
	}
	l.hits[owner] = append(arr, now)
	return true
}
