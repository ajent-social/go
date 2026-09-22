package servicecred_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/ajent-social/go/servicecred"
	"github.com/ajent-social/go/servicecred/boltstore"
)

func ExampleService() {
	ctx := context.Background()
	dir, err := os.MkdirTemp("", "servicecred-example-")
	if err != nil {
		fmt.Println(err)
		return
	}
	defer os.RemoveAll(dir)
	store, err := boltstore.Open(ctx, filepath.Join(dir, "credentials.db"))
	if err != nil {
		fmt.Println(err)
		return
	}
	svc, err := servicecred.New(store)
	if err != nil {
		fmt.Println(err)
		return
	}
	// These bindings must come from authenticated, authorized application policy.
	grant := servicecred.Grant{Access: servicecred.Access{Owner: "account-1", Resource: "resource-1", Scopes: []string{"read"}}, ExpiresAt: time.Now().Add(time.Hour)}
	secret, meta, err := svc.Issue(ctx, grant, grant)
	if err != nil {
		fmt.Println(err)
		return
	}
	required := servicecred.Access{Owner: "account-1", Resource: "resource-1", Scopes: []string{"read"}}
	_, err = svc.Verify(ctx, secret.Reveal(), required)
	fmt.Println("authorized:", err == nil)
	if err := svc.Revoke(ctx, grant.Owner, grant.Resource, meta.ID); err != nil {
		fmt.Println(err)
		return
	}
	_, err = svc.Verify(ctx, secret.Reveal(), required)
	fmt.Println("revoked:", err != nil)
	// Output:
	// authorized: true
	// revoked: true
}
