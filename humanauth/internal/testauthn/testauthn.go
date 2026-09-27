// Package testauthn is a test-only software WebAuthn authenticator: ES256 keys,
// "none" attestation, discoverable credentials, user presence and user
// verification always asserted. It answers the options JSON that
// go-webauthn produces so passkey ceremonies can be tested end to end.
// No production code imports it.
package testauthn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sync"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
)

const (
	flagUP   = 0x01
	flagUV   = 0x04
	flagAT   = 0x40
	algES256 = -7
)

var b64 = base64.RawURLEncoding

// Authenticator holds discoverable credentials for one origin.
type Authenticator struct {
	origin string
	rpID   string

	mu    sync.Mutex
	creds []*credential
}

type credential struct {
	id         []byte
	key        *ecdsa.PrivateKey
	userHandle []byte
	rpID       string
	signCount  uint32
}

// New returns an authenticator that acts for the given origin.
func New(origin string) (*Authenticator, error) {
	u, err := url.Parse(origin)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("testauthn: bad origin %q", origin)
	}
	return &Authenticator{origin: origin, rpID: u.Hostname()}, nil
}

type creationOptions struct {
	PublicKey struct {
		Challenge string `json:"challenge"`
		RP        struct {
			ID string `json:"id"`
		} `json:"rp"`
		User struct {
			ID string `json:"id"`
		} `json:"user"`
		PubKeyCredParams []struct {
			Alg int `json:"alg"`
		} `json:"pubKeyCredParams"`
		ExcludeCredentials []struct {
			ID string `json:"id"`
		} `json:"excludeCredentials"`
	} `json:"publicKey"`
}

type requestOptions struct {
	PublicKey struct {
		Challenge        string `json:"challenge"`
		RPID             string `json:"rpId"`
		AllowCredentials []struct {
			ID string `json:"id"`
		} `json:"allowCredentials"`
	} `json:"publicKey"`
}

// Create answers credential-creation options JSON with a registration
// response JSON body.
func (a *Authenticator) Create(optionsJSON []byte) ([]byte, error) {
	var opts creationOptions
	if err := json.Unmarshal(optionsJSON, &opts); err != nil {
		return nil, fmt.Errorf("testauthn: creation options: %w", err)
	}
	pk := opts.PublicKey
	if pk.Challenge == "" || pk.User.ID == "" {
		return nil, errors.New("testauthn: creation options missing challenge or user")
	}
	if pk.RP.ID != a.rpID {
		return nil, fmt.Errorf("testauthn: rp id %q does not match %q", pk.RP.ID, a.rpID)
	}
	es256 := false
	for _, p := range pk.PubKeyCredParams {
		es256 = es256 || p.Alg == algES256
	}
	if !es256 {
		return nil, errors.New("testauthn: ES256 not offered")
	}
	userHandle, err := b64.DecodeString(pk.User.ID)
	if err != nil {
		return nil, fmt.Errorf("testauthn: user id: %w", err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	id := make([]byte, 16)
	_, _ = rand.Read(id)
	cred := &credential{id: id, key: key, userHandle: userHandle, rpID: a.rpID}

	cose, err := coseKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	authData := authenticatorData(a.rpID, flagUP|flagUV|flagAT, 0)
	authData = append(authData, make([]byte, 16)...) // AAGUID
	authData = binary.BigEndian.AppendUint16(authData, uint16(len(id)))
	authData = append(authData, id...)
	authData = append(authData, cose...)

	attObj, err := webauthncbor.Marshal(map[string]any{
		"fmt":      "none",
		"attStmt":  map[string]any{},
		"authData": authData,
	})
	if err != nil {
		return nil, err
	}
	clientData, err := a.clientData("webauthn.create", pk.Challenge)
	if err != nil {
		return nil, err
	}

	a.mu.Lock()
	a.creds = append(a.creds, cred)
	a.mu.Unlock()

	return json.Marshal(map[string]any{
		"id":                      b64.EncodeToString(id),
		"rawId":                   b64.EncodeToString(id),
		"type":                    "public-key",
		"authenticatorAttachment": "platform",
		"clientExtensionResults":  map[string]any{},
		"response": map[string]any{
			"clientDataJSON":    b64.EncodeToString(clientData),
			"attestationObject": b64.EncodeToString(attObj),
			"transports":        []string{"internal"},
		},
	})
}

// Get answers credential-request options JSON with an assertion response
// JSON body, using the newest matching discoverable credential.
func (a *Authenticator) Get(optionsJSON []byte) ([]byte, error) {
	var opts requestOptions
	if err := json.Unmarshal(optionsJSON, &opts); err != nil {
		return nil, fmt.Errorf("testauthn: request options: %w", err)
	}
	pk := opts.PublicKey
	if pk.Challenge == "" {
		return nil, errors.New("testauthn: request options missing challenge")
	}
	rpID := pk.RPID
	if rpID == "" {
		rpID = a.rpID
	}
	allowed := map[string]bool{}
	for _, c := range pk.AllowCredentials {
		allowed[c.ID] = true
	}

	a.mu.Lock()
	var cred *credential
	for i := len(a.creds) - 1; i >= 0; i-- {
		c := a.creds[i]
		if c.rpID == rpID && (len(allowed) == 0 || allowed[b64.EncodeToString(c.id)]) {
			cred = c
			break
		}
	}
	var count uint32
	if cred != nil {
		cred.signCount++
		count = cred.signCount
	}
	a.mu.Unlock()
	if cred == nil {
		return nil, errors.New("testauthn: no credential for rp")
	}

	authData := authenticatorData(rpID, flagUP|flagUV, count)
	clientData, err := a.clientData("webauthn.get", pk.Challenge)
	if err != nil {
		return nil, err
	}
	clientHash := sha256.Sum256(clientData)
	digest := sha256.Sum256(append(append([]byte{}, authData...), clientHash[:]...))
	sig, err := ecdsa.SignASN1(rand.Reader, cred.key, digest[:])
	if err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{
		"id":                      b64.EncodeToString(cred.id),
		"rawId":                   b64.EncodeToString(cred.id),
		"type":                    "public-key",
		"authenticatorAttachment": "platform",
		"clientExtensionResults":  map[string]any{},
		"response": map[string]any{
			"clientDataJSON":    b64.EncodeToString(clientData),
			"authenticatorData": b64.EncodeToString(authData),
			"signature":         b64.EncodeToString(sig),
			"userHandle":        b64.EncodeToString(cred.userHandle),
		},
	})
}

func (a *Authenticator) clientData(typ, challenge string) ([]byte, error) {
	return json.Marshal(map[string]any{
		"type":        typ,
		"challenge":   challenge,
		"origin":      a.origin,
		"crossOrigin": false,
	})
}

func authenticatorData(rpID string, flags byte, count uint32) []byte {
	h := sha256.Sum256([]byte(rpID))
	out := append([]byte{}, h[:]...)
	out = append(out, flags)
	return binary.BigEndian.AppendUint32(out, count)
}

// coseKey encodes an EC2 P-256 public key as a COSE_Key map.
func coseKey(pub *ecdsa.PublicKey) ([]byte, error) {
	raw, err := pub.Bytes() // uncompressed: 0x04 || X || Y
	if err != nil {
		return nil, err
	}
	if len(raw) != 65 {
		return nil, errors.New("testauthn: unexpected P-256 point length")
	}
	return webauthncbor.Marshal(map[int]any{
		1:  2,        // kty: EC2
		3:  algES256, // alg: ES256
		-1: 1,        // crv: P-256
		-2: raw[1:33],
		-3: raw[33:],
	})
}
