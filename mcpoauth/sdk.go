package mcpoauth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"slices"

	"github.com/modelcontextprotocol/go-sdk/auth"
)

const sdkIdentityKey = "amsl.mcpoauth.identity"

// TokenVerifier adapts Verify to the official MCP SDK bearer middleware. It
// authenticates only; applications must check current permissions at each
// business effect. No request header, token or store error is exposed in Extra.
func (s *Server) TokenVerifier(ctx context.Context, token string, _ *http.Request) (*auth.TokenInfo, error) {
	id, err := s.Verify(ctx, token)
	if err != nil {
		return nil, auth.ErrInvalidToken
	}
	// An unambiguous, domain-separated digest binds sessions to the full grant
	// identity, including application workspace binding, without exposing tokens.
	binding, _ := json.Marshal([]string{"amsl.mcpoauth.session.v1", id.Subject, id.Binding, id.ClientID, id.GrantID, s.cfg.Resource})
	sum := sha256.Sum256(binding)
	return &auth.TokenInfo{Scopes: slices.Clone(id.Scopes), Expiration: id.ExpiresAt, UserID: hex.EncodeToString(sum[:]), Extra: map[string]any{sdkIdentityKey: id}}, nil
}

// IdentityFromContext returns a copy of the complete AMSL identity installed by
// the official SDK RequireBearerToken middleware using Server.TokenVerifier.
// It conveys authentication, not current application authorization.
func IdentityFromContext(ctx context.Context) (Identity, bool) {
	return IdentityFromTokenInfo(auth.TokenInfoFromContext(ctx))
}

// IdentityFromTokenInfo reads SDK request Extra.TokenInfo in tool handlers.
// The returned identity and scopes are copies; neither grants app permissions.
func IdentityFromTokenInfo(info *auth.TokenInfo) (Identity, bool) {
	if info == nil {
		return Identity{}, false
	}
	id, ok := info.Extra[sdkIdentityKey].(Identity)
	if !ok {
		return Identity{}, false
	}
	id.Scopes = slices.Clone(id.Scopes)
	return id, true
}
