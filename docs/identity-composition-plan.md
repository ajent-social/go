# Identity composition qualification plan

Date: 2026-09-27. Status: proposed work; no implementation or maturity promotion.

## Purpose

Qualify existing identity mechanisms for applications composing human accounts,
tenant-scoped machine credentials and HTTP MCP authorization. This is a reuse and
gap-assessment plan, not a universal account framework or a new hosted service.
Existing package contracts remain authoritative until reviewed amendments land.

## Work packages

| ID | Work | Completion evidence |
|---|---|---|
| IC01 | Compare `mcpoauth` and its SQL adapter against isolated issuer/resource deployments sharing a database. Examine all client, consent, code, grant and token lookups, not only token resource checks. | Two synthetic issuers cannot redeem, manage, refresh or collide with each other's records. Record supported isolation strategy; propose a scoped adapter only if existing boundaries are insufficient. |
| IC02 | Qualify live caller-policy checks inside durable grant issuance and refresh, including account disablement and binding revocation races. | Transactional tests prove revocation ordering, denied issuance and refresh reuse semantics. Any hook has a minimal public contract; application policy and schemas stay outside the library. |
| IC03 | Qualify `servicecred` for caller-authorized user-created keys: issue-once reveal, exact owner/resource/scope ceilings, mandatory expiry, metadata listing, replacement and revocation. | Existing contract tests plus composition cases for current authority checks, lost issuance response, storage errors and rotation. Add only demonstrated generic gaps; UI, user/tenant authorization, paid-access decisions and product last-used reporting remain application concerns. |
| IC04 | Assess the selected `accounts`, `magiclink` and `oidc` primitives for lifecycle composition and transactional invalidation. | Written reuse/gap verdicts; no claim that the subject registry implements organizations, account linking, recovery policy or deletion orchestration. Compare established libraries before adding a package. |
| IC05 | Document bounded registration/cleanup and backup restore responsibilities for multi-host MCP adapters. | Restart/restore and concurrency evidence; restored credentials cannot silently regain authority. Separate library guarantees from caller operating requirements. |

IC01–IC05 investigation can proceed independently. A single maintainer integrates
shared contract/schema changes. Implementation requires a concrete failing case,
a reviewed contract and exclusive file ownership; no speculative placeholder
packages. Keep any reusable addition narrowly scoped and usable without a runtime
AMSL service. Preserve existing consumer compatibility or publish an explicit
migration contract.

## Protocol qualification

Pin a supported MCP authorization specification and client matrix before claiming
interoperability. Review the [2025-11-25 authorization specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
against the package's documented public-client subset. Track client metadata and
confidential-client gaps explicitly; do not claim full conformance from one
successful client. Remote metadata retrieval, if separately introduced, requires
its own bounded fetch, SSRF and cache contract.

## Publication and evidence

Use synthetic fixtures and independently reproducible public evidence. Restricted
maintainer observations are not public adoption verification. No product names,
private sources, identifiers or source code are required in this plan. Any later
extraction needs provenance/publication qualification before copying. Update
capability catalog/contracts when actual guarantees change, run focused and
required repository checks, and retain CANDIDATE status until the existing review
gates are satisfied. This plan itself changes no Go API or storage schema.
