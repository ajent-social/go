package stripeverify_test

import (
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/ajent-social/go/billing/stripeverify"
	"github.com/stripe/stripe-go/v82/webhook"
)

func TestParseAcceptsValidSignature(t *testing.T) {
	secret := "whsec_test_secret"
	v, err := stripeverify.New(stripeverify.Config{Secret: secret, IgnoreAPIVersionMismatch: true})
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"id":"evt_1","object":"event","api_version":"2020-01-01","type":"customer.subscription.updated","livemode":false,"data":{"object":{"id":"sub_1","object":"subscription","customer":"cus_1","status":"active","current_period_end":1700000000}}}`)
	ts := time.Now()
	sig := webhook.ComputeSignature(ts, payload, secret)
	header := fmt.Sprintf("t=%d,v1=%s", ts.Unix(), hex.EncodeToString(sig))
	ev, err := v.Parse(payload, header)
	if err != nil {
		t.Fatal(err)
	}
	if ev.ID != "evt_1" || ev.CustomerRef != "cus_1" || ev.Status != "active" || ev.SubscriptionRef != "sub_1" {
		t.Fatalf("%+v", ev)
	}
}

func TestParseRejectsBadSignature(t *testing.T) {
	v, err := stripeverify.New(stripeverify.Config{Secret: "whsec_test_secret"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = v.Parse([]byte(`{"id":"evt_1"}`), "t=1,v1=deadbeef")
	if err == nil {
		t.Fatal("expected deny")
	}
}
