// Package passkey coordinates discoverable, user-verified WebAuthn ceremonies
// around the maintained go-webauthn library.
//
// It is not a login UI, session cookie system, CSRF framework, or user directory.
// Callers authenticate the browser session after Finish*, choose subject IDs from
// trusted policy, and never derive RP ID or origins from request Host headers.
//
// Status: CANDIDATE. Capability: identity.passkeys.
// Provenance: original public implementation. Ceremony consume-before-verify and
// configured-origin RP binding match patterns observed in a restricted product
// (ajent-social human accounts); no private source was copied.
package passkey

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	wa "github.com/go-webauthn/webauthn/webauthn"
)

var (
	ErrInvalid  = errors.New("passkey: invalid input")
	ErrNotFound = errors.New("passkey: not found")
	ErrExists   = errors.New("passkey: already exists")
	ErrDenied   = errors.New("passkey: denied")
	ErrExpired  = errors.New("passkey: expired")
)

const (
	defaultCeremonyTTL = 5 * time.Minute
	maxCeremonyTTL     = 10 * time.Minute
	handleBytes        = 32
)

// Kind classifies a stored ceremony.
type Kind string

const (
	KindRegister Kind = "register"
	KindAdd      Kind = "add"
	KindLogin    Kind = "login"
)

// Config binds the relying party. Origins must be exact; Host is never trusted.
type Config struct {
	RPDisplayName string
	// Origin is the exact browser origin (https://example.com). RPID is its hostname.
	Origin string
	// CeremonyTTL defaults to 5 minutes, max 10.
	CeremonyTTL time.Duration
}

// Subject is the application account handle WebAuthn binds to.
type Subject struct {
	ID          string
	Name        string
	DisplayName string
}

func (s Subject) WebAuthnID() []byte {
	return []byte(s.ID)
}
func (s Subject) WebAuthnName() string {
	if s.Name != "" {
		return s.Name
	}
	return s.ID
}
func (s Subject) WebAuthnDisplayName() string {
	if s.DisplayName != "" {
		return s.DisplayName
	}
	return s.WebAuthnName()
}
func (s Subject) WebAuthnCredentials() []wa.Credential { return nil }

// Ceremony is storage-only. HandleDigest is SHA-256 of the opaque handle cookie.
type Ceremony struct {
	HandleDigest [32]byte
	Kind         Kind
	SubjectID    string
	Name         string
	SessionJSON  []byte
	ExpiresAt    time.Time
}

// CredentialRecord is a persisted authenticator credential for one subject.
type CredentialRecord struct {
	SubjectID  string
	Credential wa.Credential
	CreatedAt  time.Time
}

// Store persists ceremonies and credentials. TakeCeremony must delete and return
// in one atomic step so a ceremony is single-use even on failed verification.
type Store interface {
	PutCeremony(context.Context, Ceremony) error
	TakeCeremony(context.Context, [32]byte) (Ceremony, error)
	PutCredential(context.Context, CredentialRecord) error
	UpdateCredential(context.Context, CredentialRecord) error
	LookupCredential(ctx context.Context, credentialID []byte, subjectID string) (CredentialRecord, error)
	ListCredentials(context.Context, string) ([]CredentialRecord, error)
	CountCredentials(context.Context, string) (int, error)
	DeleteCredential(ctx context.Context, subjectID string, credentialID []byte) error
}

// Service wraps go-webauthn with durable ceremony/credential storage.
type Service struct {
	cfg    Config
	store  Store
	engine *wa.WebAuthn
	now    func() time.Time
}

// New validates cfg and constructs a Service.
func New(cfg Config, store Store) (*Service, error) {
	if store == nil {
		return nil, ErrInvalid
	}
	u, err := url.Parse(cfg.Origin)
	if err != nil || u.Scheme == "" || u.Host == "" || u.Path != "" && u.Path != "/" || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("%w: origin must be an absolute origin URL", ErrInvalid)
	}
	if cfg.RPDisplayName == "" {
		return nil, fmt.Errorf("%w: RPDisplayName required", ErrInvalid)
	}
	ttl := cfg.CeremonyTTL
	if ttl == 0 {
		ttl = defaultCeremonyTTL
	}
	if ttl > maxCeremonyTTL || ttl < time.Minute {
		return nil, fmt.Errorf("%w: CeremonyTTL out of range", ErrInvalid)
	}
	cfg.CeremonyTTL = ttl
	origin := strings.TrimRight(cfg.Origin, "/")
	engine, err := wa.New(&wa.Config{
		RPDisplayName: cfg.RPDisplayName,
		RPID:          u.Hostname(),
		RPOrigins:     []string{origin},
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey:        protocol.ResidentKeyRequirementRequired,
			UserVerification:   protocol.VerificationRequired,
			RequireResidentKey: protocol.ResidentKeyRequired(),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("webauthn config: %w", err)
	}
	cfg.Origin = origin
	return &Service{cfg: cfg, store: store, engine: engine, now: time.Now}, nil
}

// BeginResult is returned to the browser (Options) and as a cookie (Handle).
type BeginResult struct {
	Options any
	Handle  string // opaque; store only its digest
}

// BeginRegistration starts a new-subject or add-credential ceremony.
func (s *Service) BeginRegistration(ctx context.Context, subject Subject, add bool) (BeginResult, error) {
	if err := ctx.Err(); err != nil {
		return BeginResult{}, err
	}
	if strings.TrimSpace(subject.ID) == "" || strings.TrimSpace(subject.Name) == "" {
		return BeginResult{}, ErrInvalid
	}
	n, err := s.store.CountCredentials(ctx, subject.ID)
	if err != nil {
		return BeginResult{}, err
	}
	if add {
		if n == 0 {
			return BeginResult{}, ErrDenied
		}
	} else if n > 0 {
		// New-subject registration must not attach a passkey to an existing subject.
		return BeginResult{}, ErrDenied
	}
	user := subject
	creds, err := s.store.ListCredentials(ctx, subject.ID)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return BeginResult{}, err
	}
	var keys []wa.Credential
	for _, c := range creds {
		keys = append(keys, c.Credential)
	}
	waUser := waSubject{Subject: user, keys: keys}
	options, state, err := s.engine.BeginRegistration(waUser)
	if err != nil {
		return BeginResult{}, err
	}
	kind := KindRegister
	if add {
		kind = KindAdd
	}
	return s.putCeremony(ctx, kind, subject.ID, subject.Name, state, options)
}

// BeginLogin starts a discoverable passkey login (subject unknown until Finish).
func (s *Service) BeginLogin(ctx context.Context) (BeginResult, error) {
	if err := ctx.Err(); err != nil {
		return BeginResult{}, err
	}
	options, state, err := s.engine.BeginDiscoverableLogin()
	if err != nil {
		return BeginResult{}, err
	}
	return s.putCeremony(ctx, KindLogin, "", "", state, options)
}

func (s *Service) putCeremony(ctx context.Context, kind Kind, subjectID, name string, state *wa.SessionData, options any) (BeginResult, error) {
	raw, err := randomHandle()
	if err != nil {
		return BeginResult{}, err
	}
	sessionJSON, err := json.Marshal(state)
	if err != nil {
		return BeginResult{}, err
	}
	now := s.now().UTC()
	rec := Ceremony{
		HandleDigest: sha256.Sum256([]byte(raw)),
		Kind:         kind,
		SubjectID:    subjectID,
		Name:         name,
		SessionJSON:  sessionJSON,
		ExpiresAt:    now.Add(s.cfg.CeremonyTTL),
	}
	if err := s.store.PutCeremony(ctx, rec); err != nil {
		return BeginResult{}, err
	}
	return BeginResult{Options: options, Handle: raw}, nil
}

// FinishResult is the authenticated subject and updated credential.
type FinishResult struct {
	Subject    Subject
	Credential wa.Credential
	Kind       Kind
}

// Finish completes a ceremony. The handle is consumed before verification so
// replays fail closed even when attestation/assertion is invalid.
func (s *Service) Finish(ctx context.Context, handle string, r *http.Request) (FinishResult, error) {
	if err := ctx.Err(); err != nil {
		return FinishResult{}, err
	}
	if handle == "" || r == nil {
		return FinishResult{}, ErrInvalid
	}
	digest := sha256.Sum256([]byte(handle))
	cer, err := s.store.TakeCeremony(ctx, digest)
	if err != nil {
		return FinishResult{}, err
	}
	if !cer.ExpiresAt.After(s.now().UTC()) {
		return FinishResult{}, ErrExpired
	}
	var state wa.SessionData
	if err := json.Unmarshal(cer.SessionJSON, &state); err != nil {
		return FinishResult{}, fmt.Errorf("decode ceremony: %w", err)
	}

	switch cer.Kind {
	case KindRegister, KindAdd:
		sub := Subject{ID: cer.SubjectID, Name: cer.Name, DisplayName: cer.Name}
		creds, _ := s.store.ListCredentials(ctx, sub.ID)
		if cer.Kind == KindRegister && len(creds) > 0 {
			return FinishResult{}, ErrDenied
		}
		var keys []wa.Credential
		for _, c := range creds {
			keys = append(keys, c.Credential)
		}
		cred, err := s.engine.FinishRegistration(waSubject{Subject: sub, keys: keys}, state, r)
		if err != nil || cred == nil || cred.Authenticator.CloneWarning {
			return FinishResult{}, ErrDenied
		}
		rec := CredentialRecord{SubjectID: sub.ID, Credential: *cred, CreatedAt: s.now().UTC()}
		if err := s.store.PutCredential(ctx, rec); err != nil {
			return FinishResult{}, err
		}
		return FinishResult{Subject: sub, Credential: *cred, Kind: cer.Kind}, nil

	case KindLogin:
		user, cred, err := s.engine.FinishPasskeyLogin(func(rawID, userHandle []byte) (wa.User, error) {
			rec, err := s.store.LookupCredential(ctx, rawID, string(userHandle))
			if err != nil {
				return nil, err
			}
			return waSubject{
				Subject: Subject{ID: rec.SubjectID, Name: rec.SubjectID},
				keys:    []wa.Credential{rec.Credential},
			}, nil
		}, state, r)
		if err != nil || cred == nil || cred.Authenticator.CloneWarning {
			return FinishResult{}, ErrDenied
		}
		sub := Subject{ID: string(user.WebAuthnID()), Name: user.WebAuthnName(), DisplayName: user.WebAuthnDisplayName()}
		if err := s.store.UpdateCredential(ctx, CredentialRecord{SubjectID: sub.ID, Credential: *cred, CreatedAt: s.now().UTC()}); err != nil {
			return FinishResult{}, err
		}
		return FinishResult{Subject: sub, Credential: *cred, Kind: KindLogin}, nil
	default:
		return FinishResult{}, ErrInvalid
	}
}

// DeleteCredential removes one credential when more than one remains.
func (s *Service) DeleteCredential(ctx context.Context, subjectID string, credentialID []byte) error {
	n, err := s.store.CountCredentials(ctx, subjectID)
	if err != nil {
		return err
	}
	if n <= 1 {
		return ErrDenied
	}
	return s.store.DeleteCredential(ctx, subjectID, credentialID)
}

type waSubject struct {
	Subject
	keys []wa.Credential
}

func (s waSubject) WebAuthnCredentials() []wa.Credential { return s.keys }

func randomHandle() (string, error) {
	b := make([]byte, handleBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
