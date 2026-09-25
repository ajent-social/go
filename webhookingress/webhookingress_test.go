package webhookingress_test

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/ajent-social/go/webhookingress"
)

func TestVerifyRoundTrip(t *testing.T) {
	secret := "whsec_test"
	body := []byte(`{"type":"ping"}`)
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	sig := webhookingress.Sign(secret, ts, body)
	header := "t=" + ts + ",v1=" + sig
	if err := webhookingress.Verify(secret, header, body, time.Minute, time.Now()); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyRejectsStaleAndBad(t *testing.T) {
	secret := "whsec_test"
	body := []byte(`{}`)
	old := strconv.FormatInt(time.Now().Add(-time.Hour).Unix(), 10)
	header := "t=" + old + ",v1=" + webhookingress.Sign(secret, old, body)
	if err := webhookingress.Verify(secret, header, body, 5*time.Minute, time.Now()); !errors.Is(err, webhookingress.ErrStale) {
		t.Fatalf("got %v want ErrStale", err)
	}
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	bad := "t=" + ts + ",v1=" + webhookingress.Sign("other", ts, body)
	if err := webhookingress.Verify(secret, bad, body, time.Minute, time.Now()); !errors.Is(err, webhookingress.ErrInvalid) {
		t.Fatalf("got %v want ErrInvalid", err)
	}
}

func TestVerifyRequest(t *testing.T) {
	secret := "whsec_test"
	body := []byte(`{"ok":true}`)
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	req := httptest.NewRequest(http.MethodPost, "https://example/hooks", bytes.NewReader(body))
	req.Header.Set(webhookingress.Header, "t="+ts+",v1="+webhookingress.Sign(secret, ts, body))
	got, err := webhookingress.VerifyRequest(req, secret, time.Minute, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("body mismatch")
	}
}
