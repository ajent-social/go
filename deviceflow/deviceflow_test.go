package deviceflow_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ajent-social/go/deviceflow"
)

func TestDeviceFlowPoll(t *testing.T) {
	var polls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		switch r.URL.Path {
		case "/device":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"device_code": "dc", "user_code": "ABCD-1234",
				"verification_uri": "https://example.com/device",
				"expires_in": 600, "interval": 1,
			})
		case "/token":
			n := polls.Add(1)
			if n < 2 {
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "authorization_pending"})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "tok", "token_type": "bearer", "expires_in": 3600,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	c, err := deviceflow.New(deviceflow.Config{
		ClientID: "cid", DeviceAuthURL: srv.URL + "/device", TokenURL: srv.URL + "/token",
		HTTPClient: srv.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	dc, err := c.Request(ctx)
	if err != nil || dc.UserCode != "ABCD-1234" {
		t.Fatalf("%#v %v", dc, err)
	}
	tok, err := c.Poll(ctx, dc)
	if err != nil || tok.AccessToken != "tok" {
		t.Fatalf("%#v %v", tok, err)
	}
}
