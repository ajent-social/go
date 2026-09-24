package mcpoauth

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"unicode/utf8"
)

const (
	maxBodyBytes  = 16 << 10
	maxQueryBytes = 8 << 10
	maxFieldBytes = 2 << 10
)

type metadata struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	RegistrationEndpoint              string   `json:"registration_endpoint"`
	RevocationEndpoint                string   `json:"revocation_endpoint"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	RevocationAuthMethodsSupported    []string `json:"revocation_endpoint_auth_methods_supported"`
	ScopesSupported                   []string `json:"scopes_supported"`
}

type resourceMetadata struct {
	Resource             string   `json:"resource"`
	AuthorizationServers []string `json:"authorization_servers"`
	ScopesSupported      []string `json:"scopes_supported"`
	BearerMethods        []string `json:"bearer_methods_supported"`
}

// grantTypes lists the grants the token endpoint actually serves.
func grantTypes(cfg Config) []string {
	if cfg.DisableRefresh {
		return []string{"authorization_code"}
	}
	return []string{"authorization_code", "refresh_token"}
}

// buildMetadata pre-marshals both discovery documents so the request path
// never marshals. refresh_token is advertised only when it is served.
func buildMetadata(cfg Config) ([]byte, []byte, error) {
	m, err := json.Marshal(metadata{
		Issuer:                            cfg.Issuer,
		AuthorizationEndpoint:             cfg.Issuer + cfg.AuthorizePath,
		TokenEndpoint:                     cfg.Issuer + cfg.TokenPath,
		RegistrationEndpoint:              cfg.Issuer + cfg.RegisterPath,
		RevocationEndpoint:                cfg.Issuer + cfg.RevokePath,
		ResponseTypesSupported:            []string{"code"},
		GrantTypesSupported:               grantTypes(cfg),
		CodeChallengeMethodsSupported:     []string{"S256"},
		TokenEndpointAuthMethodsSupported: []string{"none"},
		RevocationAuthMethodsSupported:    []string{"none"},
		ScopesSupported:                   cfg.Scopes,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("marshal authorization server metadata: %w", err)
	}
	r, err := json.Marshal(resourceMetadata{
		Resource: cfg.Resource, AuthorizationServers: []string{cfg.Issuer},
		ScopesSupported: cfg.Scopes, BearerMethods: []string{"header"},
	})
	if err != nil {
		return nil, nil, fmt.Errorf("marshal protected resource metadata: %w", err)
	}
	return m, r, nil
}

func staticJSON(body []byte) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if r.Method == http.MethodGet {
			_, _ = w.Write(body)
		}
	})
}

// MetadataHandler serves RFC 8414 metadata for GET/HEAD.
func (s *Server) MetadataHandler() http.Handler { return staticJSON(s.metadata) }

// ProtectedResourceHandler serves RFC 9728 metadata for GET/HEAD.
func (s *Server) ProtectedResourceHandler() http.Handler { return staticJSON(s.resource) }

// BearerToken extracts an RFC 6750 header credential.
func BearerToken(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	if len(h) < 8 || !strings.EqualFold(h[:7], "bearer ") {
		return "", false
	}
	tok := strings.TrimSpace(h[7:])
	return tok, tok != "" && len(tok) <= 256 && cleanString(tok)
}

// Challenge writes a 401 naming the protected resource metadata document.
func (s *Server) Challenge(w http.ResponseWriter, invalidToken bool) {
	v := fmt.Sprintf("Bearer resource_metadata=%q", s.endpoint(protectedResourcePath))
	if invalidToken {
		v += `, error="invalid_token"`
	}
	w.Header().Set("WWW-Authenticate", v)
	w.Header().Set("Cache-Control", "no-store")
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeOAuthError(w http.ResponseWriter, status int, code, desc string) {
	writeJSON(w, status, map[string]string{"error": code, "error_description": desc})
}

// singleValues rejects duplicated or oversized parameters.
func singleValues(v url.Values) (map[string]string, error) {
	out := make(map[string]string, len(v))
	for k, vs := range v {
		if len(vs) != 1 {
			return nil, fmt.Errorf("%w: duplicate parameter %q", ErrInvalid, k)
		}
		if len(k) > 64 || len(vs[0]) > maxFieldBytes || !cleanString(vs[0]) || !utf8.ValidString(vs[0]) {
			return nil, fmt.Errorf("%w: malformed parameter %q", ErrInvalid, k)
		}
		out[k] = vs[0]
	}
	return out, nil
}

// postForm parses a bounded application/x-www-form-urlencoded body with no
// query string and no duplicate parameters.
func postForm(w http.ResponseWriter, r *http.Request) (map[string]string, error) {
	if r.URL.RawQuery != "" {
		return nil, fmt.Errorf("%w: query parameters are not accepted", ErrInvalid)
	}
	ct := r.Header.Get("Content-Type")
	if mt, _, _ := strings.Cut(ct, ";"); strings.TrimSpace(mt) != "application/x-www-form-urlencoded" {
		return nil, fmt.Errorf("%w: content type must be application/x-www-form-urlencoded", ErrInvalid)
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err != nil {
		return nil, fmt.Errorf("%w: body too large or unreadable", ErrInvalid)
	}
	vals, err := url.ParseQuery(string(body))
	if err != nil {
		return nil, fmt.Errorf("%w: malformed form body", ErrInvalid)
	}
	return singleValues(vals)
}

// AuthorizeHandler validates GET authorization requests, records the
// consent request and delegates rendering to the application callback.
func (s *Server) AuthorizeHandler(consent func(w http.ResponseWriter, r *http.Request, handle string, req ConsentRequest)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if len(r.URL.RawQuery) > maxQueryBytes {
			http.Error(w, "request too large", http.StatusRequestURITooLong)
			return
		}
		values, parseErr := url.ParseQuery(r.URL.RawQuery)
		if parseErr != nil {
			http.Error(w, "malformed request parameters", http.StatusBadRequest)
			return
		}
		p, err := singleValues(values)
		if err != nil {
			http.Error(w, "malformed request parameters", http.StatusBadRequest)
			return
		}
		// Validation order is security-critical: client_id and redirect_uri
		// are checked first and answered directly, never by redirect.
		if p["client_id"] == "" || p["redirect_uri"] == "" {
			http.Error(w, "missing client_id or redirect_uri", http.StatusBadRequest)
			return
		}
		client, err := s.store.Client(r.Context(), p["client_id"])
		if err != nil {
			if !errors.Is(err, ErrNotFound) {
				s.log.Error("oauth: lookup client", "error", err)
				http.Error(w, "server error", http.StatusInternalServerError)
				return
			}
			http.Error(w, "unknown client_id", http.StatusBadRequest)
			return
		}
		if !s.redirectOK(client, p["redirect_uri"]) {
			http.Error(w, "redirect_uri does not match a registered value", http.StatusBadRequest)
			return
		}
		redirectURI, state := p["redirect_uri"], p["state"]
		fail := func(code, desc string) {
			http.Redirect(w, r, errorRedirect(redirectURI, code, desc, state), http.StatusFound)
		}
		if len(state) > maxState {
			fail("invalid_request", "state is too long")
			return
		}
		if p["response_type"] != "code" {
			fail("unsupported_response_type", "response_type must be code")
			return
		}
		if p["code_challenge_method"] != "S256" {
			fail("invalid_request", "code_challenge_method must be S256")
			return
		}
		if !validCodeChallenge(p["code_challenge"]) {
			fail("invalid_request", "code_challenge must be a 43-character base64url S256 digest")
			return
		}
		if res, ok := p["resource"]; ok && res != s.cfg.Resource {
			fail("invalid_target", "resource is not served by this authorization server")
			return
		}
		scopes, err := parseScopes(p["scope"], s.cfg.Scopes)
		if err != nil {
			fail("invalid_scope", "requested scope is not permitted")
			return
		}
		handle, err := randomSecret()
		if err != nil {
			s.log.Error("oauth: generate consent handle", "error", err)
			fail("server_error", "could not start authorization")
			return
		}
		now := s.now()
		rec := ConsentRecord{
			ID: digest(handle), ClientID: client.ID, RedirectURI: redirectURI,
			CodeChallenge: p["code_challenge"], State: state, Resource: s.cfg.Resource,
			Scopes: scopes, CreatedAt: now, ExpiresAt: now.Add(s.cfg.ConsentTTL),
		}
		if err := s.store.CreateConsent(r.Context(), rec); err != nil {
			s.log.Error("oauth: persist consent request", "error", err)
			fail("server_error", "could not start authorization")
			return
		}
		consent(w, r, handle, ConsentRequest{ClientID: client.ID, ClientName: client.Name, Scopes: scopes, Resource: rec.Resource, ExpiresAt: rec.ExpiresAt})
	})
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	Scope        string `json:"scope"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

func writeIssued(w http.ResponseWriter, out issued) {
	writeJSON(w, http.StatusOK, tokenResponse{
		AccessToken: out.access, TokenType: "bearer",
		ExpiresIn: int64(out.expiresAt.Sub(out.now).Seconds()), Scope: strings.Join(out.scopes, " "),
		RefreshToken: out.refresh,
	})
}

// TokenHandler serves the authorization_code grant with mandatory PKCE and,
// unless disabled, the refresh_token grant with strict rotation.
func (s *Server) TokenHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			writeOAuthError(w, http.StatusMethodNotAllowed, "invalid_request", "POST required")
			return
		}
		p, err := postForm(w, r)
		if err != nil {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "malformed request")
			return
		}
		if res, ok := p["resource"]; ok && res != s.cfg.Resource {
			writeOAuthError(w, http.StatusBadRequest, "invalid_target", "resource is not served by this authorization server")
			return
		}
		if p["client_id"] == "" {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "missing required parameter")
			return
		}
		switch p["grant_type"] {
		case "authorization_code":
			s.tokenAuthorizationCode(w, r, p)
		case "refresh_token":
			if s.cfg.DisableRefresh {
				writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type", "only authorization_code is supported")
				return
			}
			s.tokenRefresh(w, r, p)
		default:
			writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type", "grant_type must be authorization_code or refresh_token")
		}
	})
}

func (s *Server) tokenAuthorizationCode(w http.ResponseWriter, r *http.Request, p map[string]string) {
	code, clientID, redirectURI, verifier := p["code"], p["client_id"], p["redirect_uri"], p["code_verifier"]
	if code == "" || redirectURI == "" || verifier == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "missing required parameter")
		return
	}
	if !validCodeVerifier(verifier) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "code_verifier must be 43-128 unreserved characters")
		return
	}
	// Consume first: exactly one exchange may proceed, and any failed
	// attempt with a stolen code burns it (RFC 6749 §4.1.2).
	rec, err := s.store.ConsumeCode(r.Context(), digest(code))
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "invalid, expired or already redeemed authorization code")
			return
		}
		s.log.Error("oauth: consume authorization code", "error", err)
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not redeem code")
		return
	}
	now := s.now()
	switch {
	case rec.ClientID != clientID || rec.RedirectURI != redirectURI:
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "client_id or redirect_uri does not match the authorization")
		return
	case !now.Before(rec.ExpiresAt):
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "authorization code expired")
		return
	case rec.Resource != s.cfg.Resource || rec.Subject == "":
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "authorization code is not valid for this resource")
		return
	case !verifyPKCES256(verifier, rec.CodeChallenge):
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "PKCE verification failed")
		return
	}
	// Never trust a stored scope just because it came from the store.
	scopes, err := narrowScopes(rec.Scopes, s.cfg.Scopes)
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "authorization code does not carry a permitted scope")
		return
	}
	out, err := s.issueGrant(r.Context(), rec, scopes, now)
	if err != nil {
		if errors.Is(err, ErrDenied) {
			// Application issuance policy refused inside CreateGrant.
			writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "authorization is no longer permitted")
			return
		}
		s.log.Error("oauth: create grant", "error", err)
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not issue token")
		return
	}
	writeIssued(w, out)
}

func (s *Server) tokenRefresh(w http.ResponseWriter, r *http.Request, p map[string]string) {
	if p["refresh_token"] == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "missing required parameter")
		return
	}
	out, err := s.refresh(r.Context(), p["refresh_token"], p["client_id"], p["scope"])
	if err != nil {
		switch {
		case errors.Is(err, ErrReused):
			s.log.Warn("oauth: refresh token reuse detected; grant revoked", "client_id", p["client_id"])
			writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "refresh token is invalid, expired or revoked")
		case errors.Is(err, ErrDenied), errors.Is(err, ErrNotFound), errors.Is(err, ErrExpired):
			writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "refresh token is invalid, expired or revoked")
		default:
			s.log.Error("oauth: rotate refresh token", "error", err)
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not issue token")
		}
		return
	}
	writeIssued(w, out)
}

// RevokeHandler serves RFC 7009 for access and refresh tokens; either revokes
// the whole grant. token_type_hint is accepted and ignored. Unknown and
// revoked tokens look identical.
func (s *Server) RevokeHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			writeOAuthError(w, http.StatusMethodNotAllowed, "invalid_request", "POST required")
			return
		}
		p, err := postForm(w, r)
		if err != nil || p["token"] == "" {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "token parameter required")
			return
		}
		if err := s.Revoke(r.Context(), p["token"]); err != nil {
			s.log.Error("oauth: revoke token", "error", err)
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not revoke token")
			return
		}
		w.WriteHeader(http.StatusOK)
	})
}

type registrationRequest struct {
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	Scope                   string   `json:"scope"`
}

type registrationResponse struct {
	ClientID                string   `json:"client_id"`
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
}

// RegisterHandler serves RFC 7591 registration for public PKCE clients. Client
// metadata URLs are never fetched and no secret is issued. Rate limiting
// belongs to the application at the mount point.
func (s *Server) RegisterHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			writeOAuthError(w, http.StatusMethodNotAllowed, "invalid_request", "POST required")
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
		if err != nil {
			writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata", "request body too large or unreadable")
			return
		}
		var req registrationRequest
		if err := uniqueJSONObject(body); err != nil {
			writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata", "duplicate or malformed client metadata")
			return
		}
		if err := json.Unmarshal(body, &req); err != nil {
			writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata", "request body is not valid JSON")
			return
		}
		reject := func(desc string) { writeOAuthError(w, http.StatusBadRequest, "invalid_client_metadata", desc) }
		if len(req.ClientName) > maxClientName || !cleanString(req.ClientName) || !utf8.ValidString(req.ClientName) {
			reject("client_name is too long or contains control characters")
			return
		}
		if len(req.RedirectURIs) == 0 || len(req.RedirectURIs) > maxRedirects {
			reject(fmt.Sprintf("redirect_uris must contain between 1 and %d entries", maxRedirects))
			return
		}
		for i, raw := range req.RedirectURIs {
			if err := validateRedirectURI(raw, s.cfg.AllowLoopbackRedirects, s.cfg.AllowLocalhostRedirects); err != nil || slices.Contains(req.RedirectURIs[:i], raw) {
				reject("redirect_uris must be unique absolute URLs allowed by the configured callback policy")
				return
			}
		}
		for _, g := range req.GrantTypes {
			if !slices.Contains(grantTypes(s.cfg), g) {
				reject("requested grant_types are not supported")
				return
			}
		}
		for _, t := range req.ResponseTypes {
			if t != "code" {
				reject("only the code response type is supported")
				return
			}
		}
		if req.TokenEndpointAuthMethod != "" && req.TokenEndpointAuthMethod != "none" {
			reject("only public clients (token_endpoint_auth_method none) are supported")
			return
		}
		if _, err := parseScopes(req.Scope, s.cfg.Scopes); err != nil {
			reject("requested scope is not permitted")
			return
		}
		if strings.TrimSpace(req.ClientName) == "" {
			req.ClientName = "Unnamed OAuth client"
		}
		id, err := randomSecret()
		if err != nil {
			s.log.Error("oauth: generate client id", "error", err)
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not register client")
			return
		}
		c := Client{ID: id, Name: strings.TrimSpace(req.ClientName), RedirectURIs: slices.Clone(req.RedirectURIs), CreatedAt: s.now()}
		if err := s.store.CreateClient(r.Context(), c); err != nil {
			s.log.Error("oauth: persist client", "error", err)
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not register client")
			return
		}
		writeJSON(w, http.StatusCreated, registrationResponse{
			ClientID: c.ID, ClientName: c.Name, RedirectURIs: c.RedirectURIs,
			GrantTypes: grantTypes(s.cfg), ResponseTypes: []string{"code"},
			TokenEndpointAuthMethod: "none",
		})
	})
}

// RFC metadata extensions are allowed, but duplicate top-level members are
// ambiguous and must not be interpreted differently by an intermediary.
func uniqueJSONObject(body []byte) error {
	d := json.NewDecoder(bytes.NewReader(body))
	first, err := d.Token()
	if err != nil || first != json.Delim('{') {
		return ErrInvalid
	}
	seen := map[string]bool{}
	for d.More() {
		token, err := d.Token()
		if err != nil {
			return ErrInvalid
		}
		key, ok := token.(string)
		if !ok || seen[key] {
			return ErrInvalid
		}
		seen[key] = true
		var value json.RawMessage
		if err = d.Decode(&value); err != nil {
			return ErrInvalid
		}
	}
	if _, err = d.Token(); err != nil {
		return ErrInvalid
	}
	if _, err = d.Token(); err != io.EOF {
		return ErrInvalid
	}
	return nil
}
