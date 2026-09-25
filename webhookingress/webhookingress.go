// Package webhookingress verifies inbound AMSL HMAC webhook signatures.
//
// Signature format matches webhookegress: header
// `X-AMSL-Signature: t=<unix>,v1=<hex>` over `t + "." + body`.
// Provider webhooks (Stripe, Svix/Resend, etc.) stay with their SDKs or
// dedicated packages (e.g. billing/stripeverify).
package webhookingress

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const Header = "X-AMSL-Signature"

var (
	ErrMissing = errors.New("webhookingress: missing signature header")
	ErrInvalid = errors.New("webhookingress: invalid signature")
	ErrStale   = errors.New("webhookingress: timestamp outside skew")
)

// Sign returns hex HMAC-SHA256 of ts + "." + body (same as webhookegress.Sign).
func Sign(secret, ts string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(ts))
	_, _ = mac.Write([]byte("."))
	_, _ = mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// Verify checks a signature header within skew.
func Verify(secret, header string, body []byte, skew time.Duration, now time.Time) error {
	if secret == "" || header == "" {
		return ErrMissing
	}
	tStr, v1, ok := parseSigHeader(header)
	if !ok {
		return ErrInvalid
	}
	ts, err := strconv.ParseInt(tStr, 10, 64)
	if err != nil {
		return ErrInvalid
	}
	if skew <= 0 {
		skew = 5 * time.Minute
	}
	diff := now.UTC().Unix() - ts
	if diff < 0 {
		diff = -diff
	}
	if diff > int64(skew.Seconds()) {
		return ErrStale
	}
	expected := Sign(secret, tStr, body)
	if !hmac.Equal([]byte(expected), []byte(v1)) {
		return ErrInvalid
	}
	return nil
}

// VerifyRequest reads the raw body (bounded), verifies Header, and returns the body bytes.
func VerifyRequest(r *http.Request, secret string, skew time.Duration, maxBody int64) ([]byte, error) {
	if r == nil {
		return nil, ErrInvalid
	}
	if maxBody <= 0 {
		maxBody = 1 << 20 // 1 MiB
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > maxBody {
		return nil, ErrInvalid
	}
	if err := Verify(secret, r.Header.Get(Header), body, skew, time.Now()); err != nil {
		return nil, err
	}
	return body, nil
}

func parseSigHeader(h string) (t, v1 string, ok bool) {
	parts := strings.Split(h, ",")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if strings.HasPrefix(p, "t=") {
			t = strings.TrimPrefix(p, "t=")
		}
		if strings.HasPrefix(p, "v1=") {
			v1 = strings.TrimPrefix(p, "v1=")
		}
	}
	return t, v1, t != "" && v1 != ""
}
