package mcpoauth

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

const maxCIMDBytes = 64 << 10

// Private seams are for deterministic tests. Address policy is always applied
// before dialing; no exported configuration can replace this transport.
type cimdFetcher struct {
	lookup func(context.Context, string, string) ([]netip.Addr, error)
	dial   func(context.Context, string, string) (net.Conn, error)
	roots  *x509.CertPool
}

func cimdURL(id string) (*url.URL, error) {
	if len(id) > maxFieldBytes || !cleanString(id) {
		return nil, ErrInvalid
	}
	u, err := url.Parse(id)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Opaque != "" || u.Path == "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(id, "#") || u.RawPath != "" || (u.Port() != "" && u.Port() != "443") || u.String() != id {
		return nil, ErrInvalid
	}
	if strings.Contains(u.Path, "\\") {
		return nil, ErrInvalid
	}
	for _, segment := range strings.Split(u.Path, "/") {
		if segment == "." || segment == ".." {
			return nil, ErrInvalid
		}
	}
	host := u.Hostname()
	if host != strings.ToLower(host) || strings.HasSuffix(host, ".") || strings.Contains(host, "%") {
		return nil, ErrInvalid
	}
	for _, c := range host {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == ':') {
			return nil, ErrInvalid
		}
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.String() != host || !publicCIMDIP(ip) {
			return nil, ErrInvalid
		}
	} else {
		if len(host) > 253 || !strings.Contains(host, ".") {
			return nil, ErrInvalid
		}
		for _, label := range strings.Split(host, ".") {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return nil, ErrInvalid
			}
		}
	}
	return u, nil
}

// Conservatively exclude special-purpose allocations, including documentation,
// transition, benchmarking, protocol-assignment and non-global IPv6 space.
var cimdDenied = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"), netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("192.31.196.0/24"), netip.MustParsePrefix("192.52.193.0/24"), netip.MustParsePrefix("192.175.48.0/24"), netip.MustParsePrefix("198.18.0.0/15"), netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"), netip.MustParsePrefix("224.0.0.0/3"),
	netip.MustParsePrefix("2620:4f:8000::/48"), netip.MustParsePrefix("2001::/23"), netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("2002::/16"), netip.MustParsePrefix("3fff::/20"),
}

func publicCIMDIP(ip netip.Addr) bool {
	if !ip.IsValid() || ip.Is4In6() || ip.Zone() != "" || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	if ip.Is6() && !netip.MustParsePrefix("2000::/3").Contains(ip) {
		return false
	}
	for _, p := range cimdDenied {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}

func (s *Server) resolveClient(ctx context.Context, id string) (Client, error) {
	// URL-like identifiers never fall back to an opaque store entry, even when
	// CIMD is disabled or the URL/document is invalid.
	if strings.ContainsAny(id, ":/\\") {
		if !s.cfg.EnableClientIDMetadataDocuments {
			return Client{}, ErrDenied
		}
		c, err := s.fetchCIMD(ctx, id)
		if err != nil {
			return Client{}, ErrDenied
		}
		return c, nil
	}
	return s.store.Client(ctx, id)
}

func (s *Server) fetchCIMD(ctx context.Context, id string) (Client, error) {
	u, err := cimdURL(id)
	if err != nil {
		return Client{}, ErrDenied
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	f := s.cimd
	if f == nil {
		f = &cimdFetcher{}
	}
	lookup := f.lookup
	if lookup == nil {
		// Refuse partial address results when one address-family lookup fails.
		lookup = (&net.Resolver{PreferGo: true, StrictErrors: true}).LookupNetIP
	}
	addresses, err := lookup(ctx, "ip", u.Hostname())
	if err != nil || len(addresses) == 0 || len(addresses) > 64 {
		return Client{}, ErrDenied
	}
	for _, ip := range addresses {
		if !publicCIMDIP(ip) {
			return Client{}, ErrDenied
		}
	}
	// Use only a checked numeric destination. Never resolve the name again at
	// dial time (including retries); TLS still authenticates the original host.
	destination := net.JoinHostPort(addresses[0].String(), "443")
	dial := f.dial
	if dial == nil {
		dial = (&net.Dialer{Timeout: 3 * time.Second}).DialContext
	}
	tr := &http.Transport{
		Proxy: nil, DisableCompression: true, DisableKeepAlives: true,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12, ServerName: u.Hostname(), RootCAs: f.roots},
		TLSHandshakeTimeout: 3 * time.Second, ResponseHeaderTimeout: 3 * time.Second, MaxResponseHeaderBytes: 16 << 10,
		TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" || address != net.JoinHostPort(u.Hostname(), "443") {
				return nil, ErrDenied
			}
			return dial(ctx, "tcp", destination)
		},
	}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, id, nil)
	if err != nil {
		return Client{}, ErrDenied
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Encoding", "identity")
	resp, err := client.Do(req)
	if err != nil {
		return Client{}, ErrDenied
	}
	defer resp.Body.Close()
	media, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || media != "application/json" || resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Encoding") != "" || resp.ContentLength > maxCIMDBytes {
		return Client{}, ErrDenied
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxCIMDBytes+1))
	if err != nil || len(body) > maxCIMDBytes {
		return Client{}, ErrDenied
	}
	return s.parseCIMD(id, body)
}

// boundedJSON rejects duplicate keys at every depth, trailing values and deep
// extension data before unmarshalling. Unknown extensions are otherwise ignored.
func boundedJSON(body []byte) error {
	d := json.NewDecoder(bytes.NewReader(body))
	d.UseNumber()
	var value func(int) error
	value = func(depth int) error {
		if depth > 16 {
			return ErrInvalid
		}
		t, err := d.Token()
		if err != nil {
			return ErrInvalid
		}
		delim, ok := t.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				k, err := d.Token()
				if err != nil {
					return ErrInvalid
				}
				key, ok := k.(string)
				if !ok || seen[key] {
					return ErrInvalid
				}
				seen[key] = true
				if err := value(depth + 1); err != nil {
					return err
				}
			}
			t, err = d.Token()
			if err != nil || t != json.Delim('}') {
				return ErrInvalid
			}
		case '[':
			for d.More() {
				if err := value(depth + 1); err != nil {
					return err
				}
			}
			t, err = d.Token()
			if err != nil || t != json.Delim(']') {
				return ErrInvalid
			}
		default:
			return ErrInvalid
		}
		return nil
	}
	if err := value(0); err != nil {
		return err
	}
	if _, err := d.Token(); !errors.Is(err, io.EOF) {
		return ErrInvalid
	}
	return nil
}

func (s *Server) parseCIMD(id string, body []byte) (Client, error) {
	if len(body) > maxCIMDBytes || !utf8.Valid(body) || boundedJSON(body) != nil {
		return Client{}, ErrDenied
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(body, &fields) != nil || fields == nil {
		return Client{}, ErrDenied
	}
	for key := range fields {
		for _, known := range []string{"client_id", "client_name", "redirect_uris", "token_endpoint_auth_method", "grant_types", "response_types", "error"} {
			if strings.EqualFold(key, known) && key != known {
				return Client{}, ErrDenied
			}
		}
	}
	if _, ok := fields["error"]; ok {
		return Client{}, ErrDenied
	}
	var doc struct {
		ClientID      string   `json:"client_id"`
		ClientName    string   `json:"client_name"`
		RedirectURIs  []string `json:"redirect_uris"`
		AuthMethod    string   `json:"token_endpoint_auth_method"`
		GrantTypes    []string `json:"grant_types"`
		ResponseTypes []string `json:"response_types"`
	}
	if json.Unmarshal(body, &doc) != nil || doc.ClientID != id || doc.AuthMethod != "none" || len(doc.ClientName) > maxClientName || strings.TrimSpace(doc.ClientName) == "" || !cleanString(doc.ClientName) || len(doc.RedirectURIs) == 0 || len(doc.RedirectURIs) > maxRedirects {
		return Client{}, ErrDenied
	}
	for i, uri := range doc.RedirectURIs {
		if len(uri) > maxRedirectURI || validateRedirectURI(uri, s.cfg.AllowLoopbackRedirects, s.cfg.AllowLocalhostRedirects) != nil || slices.Contains(doc.RedirectURIs[:i], uri) {
			return Client{}, ErrDenied
		}
	}
	// OAuth defaults are authorization_code and code; explicit empty lists,
	// nulls and unsupported values fail closed.
	if v, ok := fields["grant_types"]; ok {
		if string(v) == "null" || len(doc.GrantTypes) == 0 || len(doc.GrantTypes) > 2 {
			return Client{}, ErrDenied
		}
	}
	for i, g := range doc.GrantTypes {
		if !slices.Contains(grantTypes(s.cfg), g) || slices.Contains(doc.GrantTypes[:i], g) {
			return Client{}, ErrDenied
		}
	}
	if len(doc.GrantTypes) > 0 && !slices.Contains(doc.GrantTypes, "authorization_code") {
		return Client{}, ErrDenied
	}
	if _, ok := fields["response_types"]; ok {
		if len(doc.ResponseTypes) != 1 || doc.ResponseTypes[0] != "code" {
			return Client{}, ErrDenied
		}
	}
	return Client{ID: id, Name: doc.ClientName, RedirectURIs: doc.RedirectURIs}, nil
}
