package tenant_test

import (
	"context"
	"errors"
	"testing"

	"github.com/ajent-social/go/tenant"
	"github.com/ajent-social/go/tenant/memory"
)

type fakeRT struct {
	failProvision bool
}

func (f fakeRT) Provision(_ context.Context, in tenant.Instance) (string, error) {
	if f.failProvision {
		return "", errors.New("boom")
	}
	return in.Hostname, nil
}
func (f fakeRT) Upgrade(context.Context, tenant.Instance, string) error { return nil }
func (f fakeRT) Destroy(context.Context, tenant.Instance) error         { return nil }

func TestLifecycle(t *testing.T) {
	ctx := context.Background()
	svc, err := tenant.New(tenant.Config{BaseDomain: "zatiti.cloud"}, memory.New(), fakeRT{})
	if err != nil {
		t.Fatal(err)
	}
	inst, err := svc.Request(ctx, tenant.RequestInput{AccountID: "a1", Slug: "example"})
	if err != nil || inst.Hostname != "example.zatiti.cloud" || inst.Status != tenant.StatusRequested {
		t.Fatalf("%#v %v", inst, err)
	}
	ready, err := svc.Provision(ctx, inst.ID)
	if err != nil || ready.Status != tenant.StatusReady {
		t.Fatalf("%#v %v", ready, err)
	}
	digest := "sha256:" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	up, err := svc.Upgrade(ctx, inst.ID, digest)
	if err != nil || up.ImageDigest != digest {
		t.Fatalf("%#v %v", up, err)
	}
	gone, err := svc.Destroy(ctx, inst.ID)
	if err != nil || gone.Status != tenant.StatusDestroyed {
		t.Fatalf("%#v %v", gone, err)
	}
}

func TestProvisionFailureMarksFailed(t *testing.T) {
	ctx := context.Background()
	store := memory.New()
	svc, err := tenant.New(tenant.Config{BaseDomain: "zatiti.cloud"}, store, fakeRT{failProvision: true})
	if err != nil {
		t.Fatal(err)
	}
	inst, err := svc.Request(ctx, tenant.RequestInput{AccountID: "a1", Slug: "demo"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Provision(ctx, inst.ID); err == nil {
		t.Fatal("expected error")
	}
	got, err := store.Lookup(ctx, inst.ID)
	if err != nil || got.Status != tenant.StatusFailed || got.LastError == "" {
		t.Fatalf("%#v %v", got, err)
	}
}

func TestRejectsReservedSlug(t *testing.T) {
	ctx := context.Background()
	svc, err := tenant.New(tenant.Config{BaseDomain: "zatiti.cloud"}, memory.New(), fakeRT{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Request(ctx, tenant.RequestInput{AccountID: "a1", Slug: "www"}); !errors.Is(err, tenant.ErrInvalid) {
		t.Fatalf("got %v", err)
	}
}
