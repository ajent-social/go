package passkey_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/ajent-social/go/passkey"
	"github.com/ajent-social/go/passkey/memory"
)

func TestNewRequiresOrigin(t *testing.T) {
	if _, err := passkey.New(passkey.Config{RPDisplayName: "T"}, memory.New()); !errors.Is(err, passkey.ErrInvalid) {
		t.Fatalf("got %v", err)
	}
	svc, err := passkey.New(passkey.Config{
		RPDisplayName: "Test",
		Origin:        "http://localhost:8080",
	}, memory.New())
	if err != nil || svc == nil {
		t.Fatalf("%v %#v", err, svc)
	}
}

func TestCeremonyConsumedBeforeVerify(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	svc, err := passkey.New(passkey.Config{
		RPDisplayName: "Test",
		Origin:        "http://localhost:8080",
	}, store)
	if err != nil {
		t.Fatal(err)
	}
	res, err := svc.BeginRegistration(ctx, passkey.Subject{ID: "user-1", Name: "Ada"}, false)
	if err != nil || res.Handle == "" || res.Options == nil {
		t.Fatalf("%#v %v", res, err)
	}
	req, err := http.NewRequest(http.MethodPost, "http://localhost:8080/finish", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.Finish(ctx, res.Handle, req)
	if !errors.Is(err, passkey.ErrDenied) {
		t.Fatalf("want denied after consume+bad assertion, got %v", err)
	}
	_, err = svc.Finish(ctx, res.Handle, req)
	if !errors.Is(err, passkey.ErrNotFound) {
		t.Fatalf("replay: %v", err)
	}
}

func TestAddRequiresExistingCredential(t *testing.T) {
	ctx := context.Background()
	svc, err := passkey.New(passkey.Config{
		RPDisplayName: "Test",
		Origin:        "http://localhost:8080",
	}, memory.New())
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.BeginRegistration(ctx, passkey.Subject{ID: "user-1", Name: "Ada"}, true)
	if !errors.Is(err, passkey.ErrDenied) {
		t.Fatalf("got %v", err)
	}
}
