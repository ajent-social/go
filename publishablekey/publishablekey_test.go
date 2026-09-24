package publishablekey_test

import (
	"context"
	"errors"
	"testing"

	"github.com/ajent-social/go/publishablekey"
	"github.com/ajent-social/go/publishablekey/memory"
)

func TestIssueVerifyOrigin(t *testing.T) {
	ctx := context.Background()
	svc, err := publishablekey.New(publishablekey.Config{}, memory.New())
	if err != nil {
		t.Fatal(err)
	}
	issued, err := svc.Issue(ctx, publishablekey.IssueInput{
		OwnerID: "o1",
		AllowedOrigins: []string{"https://app.example.com", "https://*.example.com"},
		Scopes: []string{"chat:read"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Verify(ctx, publishablekey.VerifyInput{
		Plaintext: issued.Plaintext, Origin: "https://evil.com",
	}); !errors.Is(err, publishablekey.ErrDenied) {
		t.Fatalf("got %v", err)
	}
	k, err := svc.Verify(ctx, publishablekey.VerifyInput{
		Plaintext: issued.Plaintext, Origin: "https://app.example.com",
	})
	if err != nil || k.OwnerID != "o1" {
		t.Fatalf("%#v %v", k, err)
	}
	k2, err := svc.Verify(ctx, publishablekey.VerifyInput{
		Plaintext: issued.Plaintext, Origin: "https://docs.example.com",
	})
	if err != nil || k2.ID != k.ID {
		t.Fatalf("%#v %v", k2, err)
	}
	if err := svc.Revoke(ctx, issued.Key.ID, "o1"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Verify(ctx, publishablekey.VerifyInput{
		Plaintext: issued.Plaintext, Origin: "https://app.example.com",
	}); !errors.Is(err, publishablekey.ErrDenied) {
		t.Fatalf("got %v", err)
	}
}

func TestOriginAllowed(t *testing.T) {
	if !publishablekey.OriginAllowed("https://a.example.com", []string{"https://*.example.com"}) {
		t.Fatal("expected allow subdomain")
	}
	if publishablekey.OriginAllowed("https://evil.com", []string{"https://*.example.com"}) {
		t.Fatal("expected deny")
	}
}
