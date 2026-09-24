// Package memory is an in-memory passkey.Store for tests and single-process demos.
package memory

import (
	"bytes"
	"context"
	"sync"
	"time"

	"github.com/ajent-social/go/passkey"
)

// Store is a process-local Store.
type Store struct {
	mu          sync.Mutex
	ceremonies  map[[32]byte]passkey.Ceremony
	credentials map[string][]passkey.CredentialRecord // subject -> creds
}

// New returns an empty Store.
func New() *Store {
	return &Store{
		ceremonies:  map[[32]byte]passkey.Ceremony{},
		credentials: map[string][]passkey.CredentialRecord{},
	}
}

func (s *Store) PutCeremony(_ context.Context, c passkey.Ceremony) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.ceremonies[c.HandleDigest]; ok {
		return passkey.ErrExists
	}
	s.ceremonies[c.HandleDigest] = c
	return nil
}

func (s *Store) TakeCeremony(_ context.Context, digest [32]byte) (passkey.Ceremony, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.ceremonies[digest]
	if !ok {
		return passkey.Ceremony{}, passkey.ErrNotFound
	}
	delete(s.ceremonies, digest)
	return c, nil
}

func (s *Store) PutCredential(_ context.Context, rec passkey.CredentialRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, existing := range s.credentials[rec.SubjectID] {
		if bytes.Equal(existing.Credential.ID, rec.Credential.ID) {
			return passkey.ErrExists
		}
	}
	s.credentials[rec.SubjectID] = append(s.credentials[rec.SubjectID], rec)
	return nil
}

func (s *Store) UpdateCredential(_ context.Context, rec passkey.CredentialRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	list := s.credentials[rec.SubjectID]
	for i := range list {
		if bytes.Equal(list[i].Credential.ID, rec.Credential.ID) {
			list[i].Credential = rec.Credential
			s.credentials[rec.SubjectID] = list
			return nil
		}
	}
	return passkey.ErrNotFound
}

func (s *Store) LookupCredential(_ context.Context, credentialID []byte, subjectID string) (passkey.CredentialRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, rec := range s.credentials[subjectID] {
		if bytes.Equal(rec.Credential.ID, credentialID) {
			return rec, nil
		}
	}
	return passkey.CredentialRecord{}, passkey.ErrNotFound
}

func (s *Store) ListCredentials(_ context.Context, subjectID string) ([]passkey.CredentialRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := append([]passkey.CredentialRecord(nil), s.credentials[subjectID]...)
	return out, nil
}

func (s *Store) CountCredentials(_ context.Context, subjectID string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.credentials[subjectID]), nil
}

func (s *Store) DeleteCredential(_ context.Context, subjectID string, credentialID []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	list := s.credentials[subjectID]
	for i, rec := range list {
		if bytes.Equal(rec.Credential.ID, credentialID) {
			s.credentials[subjectID] = append(list[:i], list[i+1:]...)
			return nil
		}
	}
	return passkey.ErrNotFound
}

// SweepExpired removes ceremonies past cutoff (test helper).
func (s *Store) SweepExpired(cutoff time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, c := range s.ceremonies {
		if !c.ExpiresAt.After(cutoff) {
			delete(s.ceremonies, k)
		}
	}
}

var _ passkey.Store = (*Store)(nil)
