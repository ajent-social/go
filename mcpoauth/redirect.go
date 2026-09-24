package mcpoauth

import (
	"fmt"
	"net"
	"strconv"
)

// validateRedirectURI accepts an absolute https URL with a non-empty host, or,
// when loopback is allowed, an http URL whose host is a numeric IPv4/IPv6
// loopback literal (RFC 8252 §7.3). An independent compatibility option admits
// exact localhost with an explicit valid port. Other hostnames, userinfo,
// fragments, whitespace, control characters and custom schemes are rejected.
func validateRedirectURI(raw string, allowLoopback, allowLocalhost bool) error {
	u, err := parseURL(raw, allowLocalhost)
	if err != nil {
		return fmt.Errorf("redirect_uri: %w", err)
	}
	if u.Scheme == "http" && u.Hostname() == "localhost" {
		port, err := strconv.Atoi(u.Port())
		if !allowLocalhost || err != nil || port < 1 || port > 65535 {
			return ErrInvalid
		}
		return nil
	}
	if u.Scheme == "http" && !allowLoopback {
		return fmt.Errorf("%w: redirect_uri must use https", ErrInvalid)
	}
	return nil
}

// isLoopbackHost reports whether host is a numeric loopback IP literal.
// url.Hostname strips IPv6 brackets.
func isLoopbackHost(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// exactRedirectMatch performs the exact string comparison against registered
// URIs. No prefix, suffix, path, port or subdomain tolerance.
func exactRedirectMatch(c Client, uri string) bool {
	for _, r := range c.RedirectURIs {
		if r == uri {
			return true
		}
	}
	return false
}

// redirectOK re-checks a registered URI's shape at authorization time so a
// store containing a URI registered under different rules still fails closed.
func (s *Server) redirectOK(c Client, uri string) bool {
	if !exactRedirectMatch(c, uri) {
		return false
	}
	return validateRedirectURI(uri, s.cfg.AllowLoopbackRedirects, s.cfg.AllowLocalhostRedirects) == nil
}
