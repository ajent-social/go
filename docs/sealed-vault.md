# infrastructure.sealed-vault

Status: CANDIDATE. Package: `github.com/ajent-social/go/sealedvault`.

## Intent

Store caller-sealed ciphertext blobs by owner+name. No encryption inside AMSL.

## Non-goals

KMS key management, automatic rotation, or accepting plaintext.
