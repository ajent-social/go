package humanauth

import (
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html/template"
	"io/fs"
	"net/http"
	"sort"
	"strings"

	"github.com/ajent-social/go/magiclink"
	"github.com/ajent-social/go/passkey"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static/*.js
var staticFS embed.FS

const (
	maxFinishBody         = 64 << 10
	contentSecurityPolicy = "default-src 'self'; script-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
)

// route is one row of the handler table.
type route struct {
	method, path string
	h            http.HandlerFunc
}

func (s *Service) routes() []route {
	p := s.cfg.Prefix
	return []route{
		{http.MethodPost, p + "/magic/request", s.magicRequest},
		{http.MethodGet, p + "/magic/sent", s.magicSent},
		{http.MethodGet, p + "/magic", s.magicPage},
		{http.MethodGet, p + "/magic.js", s.script("static/magic.js")},
		{http.MethodPost, p + "/magic", s.magicRedeem},
		{http.MethodGet, p + "/passkey.js", s.script("static/passkey.js")},
		{http.MethodPost, p + "/passkey/login/begin", s.passkeyLoginBegin},
		{http.MethodPost, p + "/passkey/login/finish", s.passkeyLoginFinish},
		{http.MethodPost, p + "/passkey/register/begin", s.passkeyRegisterBegin},
		{http.MethodPost, p + "/passkey/register/finish", s.passkeyRegisterFinish},
		{http.MethodPost, p + "/logout", s.logout},
	}
}

// Paths returns the exact request paths Handler serves, sorted.
func (s *Service) Paths() []string {
	seen := map[string]bool{}
	var out []string
	for _, rt := range s.routes() {
		if !seen[rt.path] {
			seen[rt.path] = true
			out = append(out, rt.path)
		}
	}
	sort.Strings(out)
	return out
}

func (s *Service) buildHandler() http.Handler {
	mux := http.NewServeMux()
	for _, rt := range s.routes() {
		mux.HandleFunc(rt.method+" "+rt.path, rt.h)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		if !strings.HasSuffix(r.URL.Path, ".js") {
			h.Set("Cache-Control", "no-store")
		}
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", contentSecurityPolicy)
		h.Set("X-Content-Type-Options", "nosniff")
		mux.ServeHTTP(w, r)
	})
}

// --- magic link -------------------------------------------------------------

func (s *Service) magicRequest(w http.ResponseWriter, r *http.Request) {
	if s.cop.Check(r) != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	email := r.PostFormValue("email")
	next := r.PostFormValue("next")
	s.log.WarnContext(r.Context(), "humanauth: magic link request", "outcome", s.issueMagicLink(r, email))
	if localPath(next) {
		http.SetCookie(w, &http.Cookie{
			Name:     s.nextCookie(),
			Value:    base64.RawURLEncoding.EncodeToString([]byte(next)),
			Path:     s.cfg.Prefix,
			MaxAge:   int(s.cfg.MagicLinkTTL.Seconds()),
			HttpOnly: true,
			Secure:   s.secure,
			SameSite: http.SameSiteLaxMode,
		})
	}
	redirect(w, s.cfg.Prefix+"/magic/sent")
}

// issueMagicLink returns a log-safe outcome. It never returns the email or token.
func (s *Service) issueMagicLink(r *http.Request, email string) string {
	ctx := r.Context()
	if strings.TrimSpace(email) == "" {
		return "refused: empty email"
	}
	sub, err := s.policy.SubjectForEmail(ctx, email)
	if err != nil || sub.ID == "" {
		return "refused: policy"
	}
	adm, err := s.policy.Admit(ctx, sub.ID)
	if err != nil || adm.ID != sub.ID {
		return "refused: admit"
	}
	if _, err := s.magic.Issue(ctx, magiclink.IssueInput{
		Email:     email,
		Purpose:   magiclink.PurposeLogin,
		SubjectID: sub.ID,
	}); err != nil {
		if errors.Is(err, magiclink.ErrInvalid) {
			return "refused: invalid email"
		}
		return "error: issue or mail failed"
	}
	return "sent"
}

func (s *Service) magicSent(w http.ResponseWriter, r *http.Request) {
	s.render(w, http.StatusOK, "sent.html")
}

func (s *Service) magicPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, http.StatusOK, "redeem.html")
}

func (s *Service) magicRedeem(w http.ResponseWriter, r *http.Request) {
	if s.cop.Check(r) != nil {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	sub, err := s.redeem(r)
	if err == nil {
		err = s.mint(w, r, sub, MethodMagicLink)
	}
	if err != nil {
		s.log.WarnContext(r.Context(), "humanauth: magic link redeem refused", "error", errorClass(err))
		s.render(w, http.StatusBadRequest, "invalid.html")
		return
	}
	target := s.cfg.AfterLogin
	if c, err := r.Cookie(s.nextCookie()); err == nil {
		if raw, err := base64.RawURLEncoding.DecodeString(c.Value); err == nil && localPath(string(raw)) {
			target = string(raw)
		}
		http.SetCookie(w, &http.Cookie{
			Name: s.nextCookie(), Value: "", Path: s.cfg.Prefix, MaxAge: -1,
			HttpOnly: true, Secure: s.secure, SameSite: http.SameSiteLaxMode,
		})
	}
	redirect(w, target)
}

// redeem consumes the token and applies Policy. The challenge is burned
// before any policy decision, so a refused link cannot be retried.
func (s *Service) redeem(r *http.Request) (Subject, error) {
	ctx := r.Context()
	ch, err := s.magic.Consume(ctx, r.PostFormValue("token"))
	if err != nil {
		return Subject{}, err
	}
	if ch.Purpose != magiclink.PurposeLogin {
		return Subject{}, ErrDenied
	}
	// magiclink checks expiry against the wall clock; re-check against the
	// configured clock so both agree on the lifetime.
	if !ch.ExpiresAt.After(s.now()) {
		return Subject{}, magiclink.ErrExpired
	}
	sub, err := s.policy.SubjectForEmail(ctx, ch.Email)
	if err != nil {
		return Subject{}, errors.Join(ErrDenied, err)
	}
	if sub.ID == "" || (ch.SubjectID != "" && ch.SubjectID != sub.ID) {
		return Subject{}, ErrDenied
	}
	return s.admit(r, sub.ID)
}

// admit asks Policy for the current subject and requires the same ID back.
func (s *Service) admit(r *http.Request, subjectID string) (Subject, error) {
	adm, err := s.policy.Admit(r.Context(), subjectID)
	if err != nil {
		return Subject{}, errors.Join(ErrDenied, err)
	}
	if adm.ID != subjectID {
		return Subject{}, ErrDenied
	}
	return adm, nil
}

// --- passkey ----------------------------------------------------------------

func (s *Service) passkeyLoginBegin(w http.ResponseWriter, r *http.Request) {
	if s.cop.Check(r) != nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
		return
	}
	res, err := s.pk.BeginLogin(r.Context())
	if err != nil {
		s.log.WarnContext(r.Context(), "humanauth: passkey login begin failed", "error", errorClass(err))
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "passkey sign-in unavailable"})
		return
	}
	s.setCeremony(w, res.Handle)
	writeJSON(w, http.StatusOK, res.Options)
}

func (s *Service) passkeyLoginFinish(w http.ResponseWriter, r *http.Request) {
	if s.cop.Check(r) != nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
		return
	}
	handle := s.takeCeremony(w, r)
	err := func() error {
		if handle == "" {
			return ErrInvalid
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxFinishBody)
		res, err := s.pk.Finish(r.Context(), handle, r)
		if err != nil {
			return err
		}
		if res.Kind != passkey.KindLogin {
			return ErrDenied
		}
		sub, err := s.admit(r, res.Subject.ID)
		if err != nil {
			return err
		}
		return s.mint(w, r, sub, MethodPasskey)
	}()
	if err != nil {
		s.log.WarnContext(r.Context(), "humanauth: passkey sign-in refused", "error", errorClass(err))
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "passkey sign-in failed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"redirect": s.cfg.AfterLogin})
}

func (s *Service) passkeyRegisterBegin(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.guardSession(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	n, err := s.passkeys.CountCredentials(ctx, sess.Subject.ID)
	if err != nil {
		s.log.WarnContext(ctx, "humanauth: passkey register begin failed", "error", errorClass(err))
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "passkey registration unavailable"})
		return
	}
	res, err := s.pk.BeginRegistration(ctx, passkey.Subject{
		ID:          sess.Subject.ID,
		Name:        sess.Subject.Name,
		DisplayName: sess.Subject.DisplayName,
	}, n > 0)
	if err != nil {
		s.log.WarnContext(ctx, "humanauth: passkey register begin refused", "error", errorClass(err))
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "passkey registration failed"})
		return
	}
	s.setCeremony(w, res.Handle)
	writeJSON(w, http.StatusOK, res.Options)
}

func (s *Service) passkeyRegisterFinish(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.guardSession(w, r)
	if !ok {
		return
	}
	handle := s.takeCeremony(w, r)
	err := func() error {
		if handle == "" {
			return ErrInvalid
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxFinishBody)
		res, err := s.pk.Finish(r.Context(), handle, r)
		if err != nil {
			return err
		}
		if res.Kind != passkey.KindRegister && res.Kind != passkey.KindAdd {
			return ErrDenied
		}
		if res.Subject.ID != sess.Subject.ID {
			return ErrDenied
		}
		return nil
	}()
	if err != nil {
		s.log.WarnContext(r.Context(), "humanauth: passkey registration refused", "error", errorClass(err))
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "passkey registration failed"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// guardSession requires a session (401) and a passing CheckCSRF (403).
func (s *Service) guardSession(w http.ResponseWriter, r *http.Request) (Session, bool) {
	sess, err := s.Session(r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "sign-in required"})
		return Session{}, false
	}
	if s.CheckCSRF(r) != nil {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
		return Session{}, false
	}
	return sess, true
}

func (s *Service) setCeremony(w http.ResponseWriter, handle string) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.ceremonyCookie(),
		Value:    handle,
		Path:     s.cfg.Prefix + "/passkey",
		MaxAge:   int(s.cfg.CeremonyTTL.Seconds()),
		HttpOnly: true,
		Secure:   s.secure,
		SameSite: http.SameSiteStrictMode,
	})
}

// takeCeremony reads the ceremony cookie and expires it in the response
// before the caller verifies anything.
func (s *Service) takeCeremony(w http.ResponseWriter, r *http.Request) string {
	var handle string
	if c, err := r.Cookie(s.ceremonyCookie()); err == nil {
		handle = c.Value
	}
	http.SetCookie(w, &http.Cookie{
		Name:     s.ceremonyCookie(),
		Value:    "",
		Path:     s.cfg.Prefix + "/passkey",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   s.secure,
		SameSite: http.SameSiteStrictMode,
	})
	return handle
}

// --- logout -----------------------------------------------------------------

func (s *Service) logout(w http.ResponseWriter, r *http.Request) {
	if sess, err := s.Session(r); err == nil {
		if s.CheckCSRF(r) != nil {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if digest, err := hexDigest(sess.ID); err == nil {
			if err := s.sessions.Delete(r.Context(), digest); err != nil {
				s.log.WarnContext(r.Context(), "humanauth: logout delete failed", "error", errorClass(err))
			}
		}
	}
	s.clearSessionCookie(w)
	redirect(w, s.cfg.AfterLogout)
}

// --- helpers ----------------------------------------------------------------

func (s *Service) nextCookie() string     { return s.cookieBase + "_next" }
func (s *Service) ceremonyCookie() string { return s.cookieBase + "_ceremony" }

type pageData struct {
	Prefix     string
	Stylesheet string
}

func parsePages() (map[string]*template.Template, error) {
	names, err := fs.Glob(templateFS, "templates/*.html")
	if err != nil {
		return nil, err
	}
	pages := map[string]*template.Template{}
	for _, name := range names {
		base := strings.TrimPrefix(name, "templates/")
		if base == "layout.html" {
			continue
		}
		t, err := template.ParseFS(templateFS, "templates/layout.html", name)
		if err != nil {
			return nil, err
		}
		pages[base] = t
	}
	return pages, nil
}

func (s *Service) render(w http.ResponseWriter, status int, page string) {
	t := s.pages[page]
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_ = t.ExecuteTemplate(w, "layout", pageData{Prefix: s.cfg.Prefix, Stylesheet: s.cfg.Stylesheet})
}

func (s *Service) script(name string) http.HandlerFunc {
	body, err := staticFS.ReadFile(name)
	if err != nil {
		panic("humanauth: missing embedded " + name)
	}
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=3600")
		_, _ = w.Write(body)
	}
}

func redirect(w http.ResponseWriter, location string) {
	w.Header().Set("Location", location)
	w.WriteHeader(http.StatusSeeOther)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// errorClass keeps logs free of emails and tokens: it reports only which
// sentinel an error matches.
func errorClass(err error) string {
	for _, e := range []error{
		ErrInvalid, ErrNotFound, ErrDenied,
		magiclink.ErrInvalid, magiclink.ErrNotFound, magiclink.ErrExpired, magiclink.ErrDenied,
		passkey.ErrInvalid, passkey.ErrNotFound, passkey.ErrExpired, passkey.ErrDenied,
	} {
		if errors.Is(err, e) {
			return e.Error()
		}
	}
	var mbe *http.MaxBytesError
	if errors.As(err, &mbe) {
		return "body too large"
	}
	return "internal"
}
