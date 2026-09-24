// Package tenant coordinates durable per-account instance lifecycle for
// hosted product deployments (slug → provision → ready → upgrade/destroy).
//
// It does not call cloud APIs. Callers supply a Runtime that creates DNS,
// certificates, and containers (typically via Pulumi or a control plane).
// Entitlement checks (paid plan) stay with the application before Request.
//
// Status: CANDIDATE. Capability: infrastructure.tenant-instance.
package tenant

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

var (
	ErrInvalid  = errors.New("tenant: invalid input")
	ErrNotFound = errors.New("tenant: not found")
	ErrExists   = errors.New("tenant: already exists")
	ErrConflict = errors.New("tenant: conflict")
	ErrDenied   = errors.New("tenant: denied")
)

// Status is the durable lifecycle state.
type Status string

const (
	StatusRequested    Status = "requested"
	StatusProvisioning Status = "provisioning"
	StatusReady        Status = "ready"
	StatusUpgrading    Status = "upgrading"
	StatusDestroying   Status = "destroying"
	StatusDestroyed    Status = "destroyed"
	StatusFailed       Status = "failed"
)

var slugRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// Instance is one dedicated deployment for an account.
type Instance struct {
	ID           string
	AccountID    string
	Slug         string // DNS label under product base domain
	ImageDigest  string // sha256:... required when Ready
	Status       Status
	Hostname     string // e.g. example.product.cloud
	LeaseEpoch   uint64
	LastError    string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// Store persists instances. Claim transitions use LeaseEpoch CAS.
type Store interface {
	Create(context.Context, Instance) error
	Lookup(context.Context, string) (Instance, error)
	LookupBySlug(context.Context, string) (Instance, error)
	LookupByAccount(context.Context, string) (Instance, error)
	Apply(ctx context.Context, id string, expectedEpoch uint64, next Instance) error
}

// Runtime performs cloud-side work. Implementations must be idempotent on Retry.
type Runtime interface {
	Provision(ctx context.Context, in Instance) (Hostname string, err error)
	Upgrade(ctx context.Context, in Instance, imageDigest string) error
	Destroy(ctx context.Context, in Instance) error
}

// Service drives the lifecycle state machine.
type Service struct {
	store   Store
	runtime Runtime
	baseDomain string // product.cloud — hostname = slug.baseDomain
	now     func() time.Time
}

// Config for New.
type Config struct {
	BaseDomain string // e.g. zatiti.cloud (no leading *.)
}

// New constructs a Service.
func New(cfg Config, store Store, runtime Runtime) (*Service, error) {
	if store == nil || runtime == nil {
		return nil, ErrInvalid
	}
	d := strings.TrimSpace(strings.ToLower(cfg.BaseDomain))
	if d == "" || strings.Contains(d, "*") || strings.HasPrefix(d, ".") {
		return nil, fmt.Errorf("%w: BaseDomain required without wildcard", ErrInvalid)
	}
	return &Service{store: store, runtime: runtime, baseDomain: d, now: time.Now}, nil
}

// RequestInput asks for a new instance. Caller must have checked entitlement.
type RequestInput struct {
	AccountID   string
	Slug        string
	ImageDigest string // optional until provision; required before Ready
}

// Request creates a requested instance or returns the existing one for the account.
func (s *Service) Request(ctx context.Context, in RequestInput) (Instance, error) {
	if err := ctx.Err(); err != nil {
		return Instance{}, err
	}
	if strings.TrimSpace(in.AccountID) == "" || !validSlug(in.Slug) {
		return Instance{}, ErrInvalid
	}
	if existing, err := s.store.LookupByAccount(ctx, in.AccountID); err == nil {
		if existing.Status != StatusDestroyed {
			return existing, nil
		}
	} else if !errors.Is(err, ErrNotFound) {
		return Instance{}, err
	}
	if _, err := s.store.LookupBySlug(ctx, in.Slug); err == nil {
		return Instance{}, ErrExists
	} else if !errors.Is(err, ErrNotFound) {
		return Instance{}, err
	}
	id, err := randomID()
	if err != nil {
		return Instance{}, err
	}
	now := s.now().UTC()
	inst := Instance{
		ID: id, AccountID: in.AccountID, Slug: in.Slug,
		ImageDigest: in.ImageDigest, Status: StatusRequested,
		Hostname: hostname(in.Slug, s.baseDomain),
		LeaseEpoch: 1, CreatedAt: now, UpdatedAt: now,
	}
	if err := s.store.Create(ctx, inst); err != nil {
		return Instance{}, err
	}
	return inst, nil
}

// Provision moves requested/failed → provisioning → ready via Runtime.
func (s *Service) Provision(ctx context.Context, id string) (Instance, error) {
	inst, err := s.claim(ctx, id, []Status{StatusRequested, StatusFailed}, StatusProvisioning)
	if err != nil {
		return Instance{}, err
	}
	host, err := s.runtime.Provision(ctx, inst)
	if err != nil {
		_ = s.fail(ctx, inst, err)
		return Instance{}, err
	}
	if host == "" {
		host = inst.Hostname
	}
	inst.Hostname = host
	inst.Status = StatusReady
	inst.LastError = ""
	inst.UpdatedAt = s.now().UTC()
	if err := s.store.Apply(ctx, inst.ID, inst.LeaseEpoch, inst); err != nil {
		return Instance{}, err
	}
	inst.LeaseEpoch++
	return inst, nil
}

// Upgrade moves ready → upgrading → ready with a new image digest.
func (s *Service) Upgrade(ctx context.Context, id, imageDigest string) (Instance, error) {
	if !validDigest(imageDigest) {
		return Instance{}, ErrInvalid
	}
	inst, err := s.claim(ctx, id, []Status{StatusReady}, StatusUpgrading)
	if err != nil {
		return Instance{}, err
	}
	if err := s.runtime.Upgrade(ctx, inst, imageDigest); err != nil {
		_ = s.fail(ctx, inst, err)
		return Instance{}, err
	}
	inst.ImageDigest = imageDigest
	inst.Status = StatusReady
	inst.LastError = ""
	inst.UpdatedAt = s.now().UTC()
	if err := s.store.Apply(ctx, inst.ID, inst.LeaseEpoch, inst); err != nil {
		return Instance{}, err
	}
	inst.LeaseEpoch++
	return inst, nil
}

// Destroy moves ready/failed → destroying → destroyed.
func (s *Service) Destroy(ctx context.Context, id string) (Instance, error) {
	inst, err := s.claim(ctx, id, []Status{StatusReady, StatusFailed, StatusRequested}, StatusDestroying)
	if err != nil {
		return Instance{}, err
	}
	if err := s.runtime.Destroy(ctx, inst); err != nil {
		_ = s.fail(ctx, inst, err)
		return Instance{}, err
	}
	inst.Status = StatusDestroyed
	inst.LastError = ""
	inst.UpdatedAt = s.now().UTC()
	if err := s.store.Apply(ctx, inst.ID, inst.LeaseEpoch, inst); err != nil {
		return Instance{}, err
	}
	inst.LeaseEpoch++
	return inst, nil
}

func (s *Service) claim(ctx context.Context, id string, from []Status, to Status) (Instance, error) {
	inst, err := s.store.Lookup(ctx, id)
	if err != nil {
		return Instance{}, err
	}
	ok := false
	for _, st := range from {
		if inst.Status == st {
			ok = true
			break
		}
	}
	if !ok {
		return Instance{}, ErrConflict
	}
	epoch := inst.LeaseEpoch
	inst.Status = to
	inst.UpdatedAt = s.now().UTC()
	if err := s.store.Apply(ctx, id, epoch, inst); err != nil {
		return Instance{}, err
	}
	inst.LeaseEpoch = epoch + 1
	return inst, nil
}

func (s *Service) fail(ctx context.Context, inst Instance, cause error) error {
	inst.Status = StatusFailed
	inst.LastError = cause.Error()
	inst.UpdatedAt = s.now().UTC()
	return s.store.Apply(ctx, inst.ID, inst.LeaseEpoch, inst)
}

func validSlug(s string) bool {
	return slugRE.MatchString(s) && s != "www" && s != "api" && s != "admin"
}

func validDigest(d string) bool {
	return strings.HasPrefix(d, "sha256:") && len(d) == len("sha256:")+64
}

func hostname(slug, base string) string {
	return slug + "." + base
}

func randomID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
