package accounts_test

import (
	"context"
	"errors"
	"testing"

	"github.com/ajent-social/go/accounts"
	"github.com/ajent-social/go/accounts/memory"
)

func TestCreateEnsureDisable(t *testing.T) {
	ctx := context.Background()
	svc, err := accounts.New(memory.New())
	if err != nil {
		t.Fatal(err)
	}
	a, err := svc.Create(ctx, accounts.CreateInput{Email: "Ada@Example.com", DisplayName: "Ada"})
	if err != nil || a.Email != "ada@example.com" || a.Status != accounts.StatusActive {
		t.Fatalf("%#v %v", a, err)
	}
	same, err := svc.EnsureByEmail(ctx, "ada@example.com", "Other")
	if err != nil || same.ID != a.ID {
		t.Fatalf("%#v %v", same, err)
	}
	if err := svc.Disable(ctx, a.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.RequireActive(ctx, a.ID); !errors.Is(err, accounts.ErrDenied) {
		t.Fatalf("got %v", err)
	}
}
