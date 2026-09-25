package usage_test

import (
	"context"
	"errors"
	"testing"

	"github.com/ajent-social/go/usage"
	"github.com/ajent-social/go/usage/memory"
)

func TestConsume(t *testing.T) {
	svc, err := usage.New(memory.New())
	if err != nil {
		t.Fatal(err)
	}
	key := usage.Key{Owner: "a1", Meter: "steps", Period: "2026-09"}
	c, err := svc.Consume(context.Background(), key, 3, 10)
	if err != nil || c.Used != 3 {
		t.Fatalf("%+v %v", c, err)
	}
	_, err = svc.Consume(context.Background(), key, 8, 10)
	if !errors.Is(err, usage.ErrDenied) {
		t.Fatalf("got %v", err)
	}
	used, err := svc.Check(context.Background(), key)
	if err != nil || used != 3 {
		t.Fatalf("%d %v", used, err)
	}
}
