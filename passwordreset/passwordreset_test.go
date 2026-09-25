package passwordreset_test

import (
	"context"
	"errors"
	"testing"

	"github.com/ajent-social/go/passwordreset"
	"github.com/ajent-social/go/passwordreset/memory"
)

func TestIssueConsume(t *testing.T) {
	ctx := context.Background()
	svc, err := passwordreset.New(passwordreset.Config{
		BaseURL: "https://app.example/auth/reset",
	}, memory.New(), nil)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := svc.Issue(ctx, passwordreset.IssueInput{AccountID: "acct1"})
	if err != nil || issued.Token == "" {
		t.Fatalf("%#v %v", issued, err)
	}
	ch, err := svc.Consume(ctx, issued.Token)
	if err != nil || ch.AccountID != "acct1" {
		t.Fatalf("%#v %v", ch, err)
	}
	if _, err := svc.Consume(ctx, issued.Token); !errors.Is(err, passwordreset.ErrNotFound) {
		t.Fatalf("replay: %v", err)
	}
}
