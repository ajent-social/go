package oidc_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/ajent-social/go/oidc"
	"github.com/ajent-social/go/oidc/memory"
)

func TestRejectsBadRedirect(t *testing.T) {
	ctx := context.Background()
	_, err := oidc.New(ctx, oidc.Config{
		Providers: []oidc.ProviderConfig{{
			ID: "google", Issuer: "https://accounts.google.com",
			ClientID: "cid", ClientSecret: "sec",
			RedirectURI: "http://evil.example/cb",
		}},
	}, memory.New())
	if !errors.Is(err, oidc.ErrInvalid) {
		t.Fatalf("got %v", err)
	}
}

func TestPendingConsumeAndBinding(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	digest := sha256.Sum256([]byte("state"))
	if err := store.PutPending(ctx, oidc.Pending{
		StateDigest: digest, Provider: "google", Nonce: "n",
		ExpiresAt: time.Now().Add(time.Minute), CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	got, err := store.TakePending(ctx, digest)
	if err != nil || got.Provider != "google" {
		t.Fatalf("%#v %v", got, err)
	}
	if _, err := store.TakePending(ctx, digest); !errors.Is(err, oidc.ErrNotFound) {
		t.Fatalf("replay: %v", err)
	}
	if err := store.PutBinding(ctx, oidc.Binding{
		Provider: "google", Subject: "sub1", AccountID: "acct1", CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.PutBinding(ctx, oidc.Binding{
		Provider: "google", Subject: "sub1", AccountID: "acct2", CreatedAt: time.Now(),
	}); !errors.Is(err, oidc.ErrExists) {
		t.Fatalf("got %v", err)
	}
}
