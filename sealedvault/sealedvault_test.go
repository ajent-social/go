package sealedvault_test

import (
	"context"
	"errors"
	"testing"

	"github.com/ajent-social/go/sealedvault"
	"github.com/ajent-social/go/sealedvault/memory"
)

func TestPutGetDelete(t *testing.T) {
	svc, err := sealedvault.New(memory.New())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := svc.Put(ctx, sealedvault.PutInput{Owner: "a1", Name: "conn", Ciphertext: []byte("sealed")}); err != nil {
		t.Fatal(err)
	}
	got, err := svc.Get(ctx, "a1", "conn")
	if err != nil || string(got.Ciphertext) != "sealed" {
		t.Fatalf("%+v %v", got, err)
	}
	if _, err := svc.Put(ctx, sealedvault.PutInput{Owner: "a1", Name: "x", Ciphertext: nil}); !errors.Is(err, sealedvault.ErrInvalid) {
		t.Fatalf("got %v", err)
	}
	if err := svc.Delete(ctx, "a1", "conn"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Get(ctx, "a1", "conn"); !errors.Is(err, sealedvault.ErrNotFound) {
		t.Fatalf("got %v", err)
	}
}
