package magiclink_test

import (
	"context"
	"errors"
	"testing"

	"github.com/ajent-social/go/magiclink"
	"github.com/ajent-social/go/magiclink/memory"
)

type memMailer struct{ lastURL string }

func (m *memMailer) SendMagicLink(_ context.Context, _, url string) error {
	m.lastURL = url
	return nil
}

func TestIssueConsumeOnce(t *testing.T) {
	ctx := context.Background()
	mailer := &memMailer{}
	svc, err := magiclink.New(magiclink.Config{
		BaseURL: "https://app.example/auth/magic",
	}, memory.New(), mailer)
	if err != nil {
		t.Fatal(err)
	}
	iss, err := svc.Issue(ctx, magiclink.IssueInput{
		Email: "ada@example.com", Purpose: magiclink.PurposeLogin, SubjectID: "acct_1",
	})
	if err != nil || iss.Token == "" || mailer.lastURL == "" {
		t.Fatalf("%#v %v", iss, err)
	}
	ch, err := svc.Consume(ctx, iss.Token)
	if err != nil || ch.SubjectID != "acct_1" || ch.Email != "ada@example.com" {
		t.Fatalf("%#v %v", ch, err)
	}
	if _, err := svc.Consume(ctx, iss.Token); !errors.Is(err, magiclink.ErrNotFound) {
		t.Fatalf("replay: %v", err)
	}
}

func TestRejectsBadEmail(t *testing.T) {
	svc, err := magiclink.New(magiclink.Config{BaseURL: "https://app.example/m"}, memory.New(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Issue(context.Background(), magiclink.IssueInput{
		Email: "not-an-email", Purpose: magiclink.PurposeLogin,
	}); !errors.Is(err, magiclink.ErrInvalid) {
		t.Fatalf("got %v", err)
	}
}
