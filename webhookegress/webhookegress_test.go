package webhookegress_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/ajent-social/go/webhookegress"
	"github.com/ajent-social/go/webhookegress/memory"
)

func TestSignVerifyAndDeliver(t *testing.T) {
	ctx := context.Background()
	var gotBody []byte
	var gotSig string
	var wg sync.WaitGroup
	wg.Add(1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer wg.Done()
		gotSig = r.Header.Get(webhookegress.SignatureHeader)
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(200)
	}))
	defer srv.Close()

	store := memory.New()
	d, err := webhookegress.New(webhookegress.Config{HTTPClient: srv.Client()}, store)
	if err != nil {
		t.Fatal(err)
	}
	created, err := d.CreateEndpoint(ctx, webhookegress.CreateEndpointInput{
		OwnerID: "o1", URL: srv.URL, Events: []string{"order.created"},
	})
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"ok":true}`)
	if err := d.Emit(ctx, "o1", "order.created", payload, map[string]string{
		created.Endpoint.ID: created.Secret,
	}); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("delivery timeout")
	}
	if string(gotBody) != string(payload) {
		t.Fatalf("body=%s", gotBody)
	}
	if !webhookegress.Verify(created.Secret, gotSig, payload, time.Minute, time.Now()) {
		t.Fatalf("sig verify failed: %s", gotSig)
	}
}

func TestRejectsHTTPURL(t *testing.T) {
	d, err := webhookegress.New(webhookegress.Config{}, memory.New())
	if err != nil {
		t.Fatal(err)
	}
	_, err = d.CreateEndpoint(context.Background(), webhookegress.CreateEndpointInput{
		OwnerID: "o", URL: "http://evil.example/hook", Events: []string{"a"},
	})
	if err == nil {
		t.Fatal("expected reject")
	}
}
