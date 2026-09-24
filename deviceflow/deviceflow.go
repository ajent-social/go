// Package deviceflow coordinates the OAuth 2.0 device authorization grant
// (RFC 8628) against a configured authorization server.
//
// Status: CANDIDATE. Capability: identity.device-flow.
package deviceflow

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var (
	ErrInvalid = errors.New("deviceflow: invalid input")
	ErrDenied  = errors.New("deviceflow: denied")
	ErrPending = errors.New("deviceflow: authorization pending")
	ErrExpired = errors.New("deviceflow: expired")
	ErrSlowDown = errors.New("deviceflow: slow down")
)

// Config binds device and token endpoints. URLs are configured absolutes.
type Config struct {
	ClientID      string
	DeviceAuthURL string
	TokenURL      string
	Scopes        []string
	HTTPClient    *http.Client
}

// DeviceCode is returned by Request.
type DeviceCode struct {
	DeviceCode              string
	UserCode                string
	VerificationURI         string
	VerificationURIComplete string
	ExpiresIn               int
	Interval                int
}

// Token is returned after the user authorizes.
type Token struct {
	AccessToken  string
	TokenType    string
	RefreshToken string
	Scope        string
	ExpiresIn    int
}

// Client polls a device-flow authorization server.
type Client struct {
	cfg  Config
	http *http.Client
}

// New validates config.
func New(cfg Config) (*Client, error) {
	if cfg.ClientID == "" {
		return nil, ErrInvalid
	}
	for _, u := range []string{cfg.DeviceAuthURL, cfg.TokenURL} {
		if err := validateURL(u); err != nil {
			return nil, err
		}
	}
	hc := cfg.HTTPClient
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	return &Client{cfg: cfg, http: hc}, nil
}

func validateURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" || u.Fragment != "" {
		return fmt.Errorf("%w: URL must be absolute without fragment", ErrInvalid)
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		h := u.Hostname()
		if h == "localhost" || h == "127.0.0.1" || h == "::1" {
			return nil
		}
		return fmt.Errorf("%w: http only on loopback", ErrInvalid)
	default:
		return fmt.Errorf("%w: unsupported scheme", ErrInvalid)
	}
}

// Request starts the device authorization.
func (c *Client) Request(ctx context.Context) (DeviceCode, error) {
	if err := ctx.Err(); err != nil {
		return DeviceCode{}, err
	}
	form := url.Values{"client_id": {c.cfg.ClientID}}
	if len(c.cfg.Scopes) > 0 {
		form.Set("scope", strings.Join(c.cfg.Scopes, " "))
	}
	body, err := c.postForm(ctx, c.cfg.DeviceAuthURL, form)
	if err != nil {
		return DeviceCode{}, err
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return DeviceCode{}, fmt.Errorf("%w: invalid device JSON", ErrDenied)
	}
	dc := DeviceCode{
		DeviceCode:              jsonString(raw, "device_code"),
		UserCode:                jsonString(raw, "user_code"),
		VerificationURI:         jsonString(raw, "verification_uri"),
		VerificationURIComplete: jsonString(raw, "verification_uri_complete"),
		ExpiresIn:               jsonInt(raw, "expires_in"),
		Interval:                jsonInt(raw, "interval"),
	}
	if dc.DeviceCode == "" || dc.UserCode == "" || dc.VerificationURI == "" {
		return DeviceCode{}, fmt.Errorf("%w: incomplete device response", ErrDenied)
	}
	if dc.Interval <= 0 {
		dc.Interval = 5
	}
	return dc, nil
}

// Poll waits until the user authorizes or the context is cancelled.
func (c *Client) Poll(ctx context.Context, deviceCode DeviceCode) (Token, error) {
	interval := time.Duration(deviceCode.Interval) * time.Second
	deadline := time.Now().Add(time.Duration(deviceCode.ExpiresIn) * time.Second)
	if deviceCode.ExpiresIn <= 0 {
		deadline = time.Now().Add(15 * time.Minute)
	}
	for {
		if err := ctx.Err(); err != nil {
			return Token{}, err
		}
		if time.Now().After(deadline) {
			return Token{}, ErrExpired
		}
		tok, err := c.tokenOnce(ctx, deviceCode.DeviceCode)
		if err == nil {
			return tok, nil
		}
		switch {
		case errors.Is(err, ErrPending):
			// continue
		case errors.Is(err, ErrSlowDown):
			interval += 5 * time.Second
		default:
			return Token{}, err
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return Token{}, ctx.Err()
		case <-timer.C:
		}
	}
}

func (c *Client) tokenOnce(ctx context.Context, deviceCode string) (Token, error) {
	form := url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code": {deviceCode},
		"client_id":   {c.cfg.ClientID},
	}
	body, err := c.postForm(ctx, c.cfg.TokenURL, form)
	if err != nil {
		return Token{}, err
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return Token{}, fmt.Errorf("%w: invalid token JSON", ErrDenied)
	}
	if errCode := jsonString(raw, "error"); errCode != "" {
		switch errCode {
		case "authorization_pending":
			return Token{}, ErrPending
		case "slow_down":
			return Token{}, ErrSlowDown
		case "expired_token":
			return Token{}, ErrExpired
		case "access_denied":
			return Token{}, ErrDenied
		default:
			return Token{}, fmt.Errorf("%w: %s", ErrDenied, errCode)
		}
	}
	tok := Token{
		AccessToken:  jsonString(raw, "access_token"),
		TokenType:    jsonString(raw, "token_type"),
		RefreshToken: jsonString(raw, "refresh_token"),
		Scope:        jsonString(raw, "scope"),
		ExpiresIn:    jsonInt(raw, "expires_in"),
	}
	if tok.AccessToken == "" {
		return Token{}, fmt.Errorf("%w: missing access_token", ErrDenied)
	}
	return tok, nil
}

func (c *Client) postForm(ctx context.Context, endpoint string, form url.Values) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: request failed", ErrDenied)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	// Device flow returns 400 for pending; still parse body.
	return body, nil
}

func jsonString(m map[string]json.RawMessage, key string) string {
	v, ok := m[key]
	if !ok {
		return ""
	}
	var s string
	if json.Unmarshal(v, &s) != nil {
		return ""
	}
	return s
}

func jsonInt(m map[string]json.RawMessage, key string) int {
	v, ok := m[key]
	if !ok {
		return 0
	}
	var n float64
	if json.Unmarshal(v, &n) != nil {
		return 0
	}
	return int(n)
}
