package mcpoauth

import (
	"context"
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"
)

// HTTP public clients identify themselves but do not authenticate with a
// secret. URL IDs are syntax checked, never fetched during token revocation.
func validPublicClientID(id string) bool {
	if id == "" || len(id) > maxFieldBytes || !utf8.ValidString(id) || strings.IndexFunc(id, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
		return false
	}
	if strings.ContainsAny(id, ":/\\") {
		_, err := cimdURL(id)
		return err == nil
	}
	return true
}

func (s *Server) revokeClientToken(ctx context.Context, raw, clientID string) error {
	if len(raw) > maxFieldBytes {
		return nil
	}
	tokenID := digest(raw)
	rec, err := s.store.Token(ctx, tokenID)
	var grantID string
	if err == nil {
		if rec.ClientID != clientID {
			return nil
		}
		grantID = rec.GrantID
	} else if errors.Is(err, ErrNotFound) {
		refresh, e := s.store.Refresh(ctx, tokenID)
		if errors.Is(e, ErrNotFound) {
			return nil
		}
		if e != nil {
			return e
		}
		if refresh.ClientID != clientID {
			return nil
		}
		grantID = refresh.GrantID
	} else {
		return err
	}
	if grantID == "" {
		return nil
	}
	grant, err := s.store.Grant(ctx, grantID)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if grant.ClientID != clientID {
		return nil
	}
	err = s.store.RevokeGrant(ctx, grantID, s.now())
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	return err
}
