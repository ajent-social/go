// Package microsoft provides Microsoft identity platform presets for oidc.New.
//
// Status: CANDIDATE. Capability: identity.oidc-social (Microsoft preset).
package microsoft

import "fmt"

// ProviderID for oidc.ProviderConfig.ID.
const ProviderID = "microsoft"

// Issuer returns the OIDC issuer for a tenant ("common", "organizations",
// "consumers", or a tenant GUID/domain).
func Issuer(tenant string) string {
	if tenant == "" {
		tenant = "common"
	}
	return fmt.Sprintf("https://login.microsoftonline.com/%s/v2.0", tenant)
}

// DefaultScopes for OIDC login.
func DefaultScopes() []string {
	return []string{"openid", "email", "profile"}
}
