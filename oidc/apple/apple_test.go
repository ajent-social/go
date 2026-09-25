package apple_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/ajent-social/go/oidc/apple"
)

func TestClientSecret(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	fixed := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	tok, err := apple.ClientSecret(apple.ClientSecretInput{
		TeamID: "TEAM", ClientID: "com.example.app", KeyID: "KEY1",
		PrivateKey: pemBytes, Now: func() time.Time { return fixed },
	})
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("parts=%d", len(parts))
	}
}

func TestPreset(t *testing.T) {
	iss, id, scopes, err := apple.Preset("com.example", "https://app.example/cb")
	if err != nil || iss != apple.Issuer || id != apple.ProviderID || len(scopes) == 0 {
		t.Fatalf("%v %v %v %v", iss, id, scopes, err)
	}
}
