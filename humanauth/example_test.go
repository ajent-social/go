package humanauth_test

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"

	"github.com/ajent-social/go/humanauth"
	"github.com/ajent-social/go/humanauth/memory"
	mlmemory "github.com/ajent-social/go/magiclink/memory"
	pkmemory "github.com/ajent-social/go/passkey/memory"
)

// printMailer prints the link instead of sending mail.
type printMailer struct{}

func (printMailer) SendMagicLink(_ context.Context, email, url string) error {
	fmt.Println("mail to", email, ":", url)
	return nil
}

// oneEmail admits exactly one address. A real Policy consults the
// application's account directory and refuses disabled accounts.
type oneEmail struct{ subject humanauth.Subject }

func (p oneEmail) SubjectForEmail(_ context.Context, email string) (humanauth.Subject, error) {
	if email != p.subject.Name {
		return humanauth.Subject{}, errors.New("not allowed")
	}
	return p.subject, nil
}

func (p oneEmail) Admit(_ context.Context, subjectID string) (humanauth.Subject, error) {
	if subjectID != p.subject.ID {
		return humanauth.Subject{}, errors.New("not allowed")
	}
	return p.subject, nil
}

func ExampleNew() {
	svc, err := humanauth.New(humanauth.Config{
		PublicURL:     "https://app.example.com",
		RPDisplayName: "Example App",
	}, humanauth.Deps{
		Sessions:   memory.New(),
		MagicLinks: mlmemory.New(),
		Mailer:     printMailer{},
		Passkeys:   pkmemory.New(),
		Policy: oneEmail{subject: humanauth.Subject{
			ID:          "user-7f3a", // opaque and stable: it becomes the WebAuthn user handle
			Name:        "person@example.com",
			DisplayName: "Example Person",
		}},
	})
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	for _, p := range svc.Paths() {
		mux.Handle(p, svc.Handler())
	}
	// The application's own login page posts email and next to
	// /auth/magic/request and loads /auth/passkey.js.
	mux.HandleFunc("POST /settings/name", func(w http.ResponseWriter, r *http.Request) {
		sess, err := svc.Session(r)
		if err != nil {
			http.Error(w, "sign in", http.StatusUnauthorized)
			return
		}
		if err := svc.CheckCSRF(r); err != nil {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		fmt.Fprintln(w, "hello", sess.Subject.DisplayName)
	})
	_ = &http.Server{Addr: ":8443", Handler: mux}
}
