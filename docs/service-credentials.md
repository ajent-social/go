# Proposed first slice: identity.service-credentials

Status: candidate contract, no implementation. This document contains original behavioral requirements, not extracted private source.

A secret credential is issued once to an owner and resource scope. Persist a digest, not the bearer secret. Verification must combine secret validity with explicit expiry/revocation and caller-owned authorization. Listing returns sanitized metadata only. A browser-publishable identifier is a different credential kind.

## Contract questions before implementation

- Who owns credential IDs, scope vocabulary and resource identity?
- What storage transaction makes creation and revocation durable?
- Must disabled-owner checks happen on every request, and who supplies them?
- What revocation consistency is promised across instances and caches?
- Which storage adapter is demonstrated by a real consumer?

## Required verification

Wrong secret, wrong owner, wrong resource, missing scope, expired/revoked key, concurrent lifecycle changes, malformed input and secret disclosure tests. Examples must include caller authorization rather than imply possession permits every operation. Use standard cryptography. Record actual execution and real application adoption separately.

Do not publish a provisional security API merely to populate this repository.
