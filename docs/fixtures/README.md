# Public client metadata fixture

`mcp-public-client.json` is a public OAuth client metadata document for explicit interoperability tests. Its client ID is the exact HTTPS JSON-document URL served by the public GitHub-source CDN. It contains no client secret, credentials or application authority.

The source stays in this repository; the CDN URL is selected because it serves the JSON body as `application/json`, as the released safe fetcher requires. Tests must reject redirects, wrong content types and content encodings rather than relaxing those checks.

The callback uses the reserved `.invalid` domain and fixed nonprivileged port `7443`. A controlled test harness may resolve that hostname to its own verified-HTTPS callback listener with an explicitly trusted fixture CA. It is not a production client or a deployed callback service. Do not disable TLS verification or weaken server-side public-address protections to use this fixture.

Tests should record the fetched document digest and source revision, use the released OAuth APIs and official MCP SDKs, and independently verify login/consent, current application authorization, resource binding and revocation. Publishing this document does not qualify any consumer or grant access. Never fetch logos or unrelated metadata URLs.
