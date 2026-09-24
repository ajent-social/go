# infrastructure.tenant-instance

Status: CANDIDATE. Package: `github.com/ajent-social/go/tenant`.

Durable lifecycle for dedicated product instances: Request → Provision →
Ready → Upgrade / Destroy. Cloud work is a `Runtime` seam (compose Pulumi
`containerdeploy` + `tenantdnstls`). Entitlement checks stay with the app
before Request. Hostname = `slug.baseDomain`.
