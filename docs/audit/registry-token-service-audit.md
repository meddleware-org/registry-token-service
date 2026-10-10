# Security Audit — `registry-token-service`

**Classification:** Internal security review
**Project:** `repos/registry-token-service` — CNCF Distribution token service for `registry.meddleware.co.uk` (Go)
**Project type:** Go service + container image + token issuer (authorization decision point)
**Template:** AUDIT_TEMPLATE.md (2026-10-08) + AUDIT_TEMPLATE_GO.md (2026-10-08) + AUDIT_TEMPLATE_IMG.md (2026-10-08) + AUDIT_TEMPLATE_AUTH.md (2026-10-08)
**Go:** `go 1.26.6`, `toolchain go1.26.9` in `go.mod`; CI uses `go-version-file: go.mod`; builder `golang:1.26.9-bookworm` (digest-pinned, checked against the `go.mod` toolchain in the Dockerfile)
**Modules:** `golang-jwt/jwt/v5` v5.3.1 (RS256 signing), `google/uuid` v1.6.0 (`jti`); everything else is stdlib
**Entry points:** `cmd/server` (listens on `:8080`: `GET /token`, `GET /healthz`; `-healthcheck` flag for the container `HEALTHCHECK`)
**Upstreams:** Hydra public token endpoint `http://hydra.auth.svc.cluster.local:4444/oauth2/token` (the client's own Basic credentials, 10 s); Keto read API `http://keto.auth.svc.cluster.local:4466` (no credential, 5 s). Both in-cluster.
**Images:** `quay.io/meddleware-org/registry-token-service:0.1.6@sha256:1f3d27f402867275b427119ceffbd595eba98df6dee5ccf24847a717e321f033` (also `docker.io/meddleware/registry-token-service`; best-effort mirror on the self-hosted registry)
**Base images:** build `golang:1.26.9-bookworm@sha256:d9c68c2c…641453c`; runtime `scratch` (binary + CA bundle)
**Runtime user:** `65534:65534`   **Runtime FS:** read-only root; the only mount is the signing-key Secret (read-only, mode 0440)
**Deployed by:** `k8s/base/registry/token-service` through `k8s/clusters/meddleware-org/registry` (digest stamped from `config/images.yaml`)
**Build args:** `VERSION`, `TARGETOS`, `TARGETARCH`, and OCI label strings (`VENDOR`, `DESCRIPTION`, `SOURCE_URL`, `DOCUMENTATION_URL`, `IMAGE_URL`) — none secret
**Auth role(s):** token issuer (Distribution registry bearer tokens) and authorization decision point (asks Keto, never decides itself)
**Identity provider:** Ory Hydra (client-credentials grant at the public token endpoint, used only to validate the client's credentials) and Ory Keto (read API `GET /relation-tuples/check`, namespace `Registry`)
**Token formats:** JWT, RS256, `typ` JWT, `kid` = RFC 7638 thumbprint of the signing key, `aud` a plain JSON string
**Signing / client credentials:** `signing.key` (RSA ≥ 4096-bit, Secret `token-service-keys`, mounted file, no rotation cadence fixed — F14); the service holds no client secret of its own, it forwards the caller's Basic credentials to Hydra
**Authorization model:** Keto namespace `Registry`; relations `pullers`, `pushers`, `admins` (repository, then organisation fallback) and `listers` (object `catalog`)
**Deployment status:** image `quay.io/meddleware-org/registry-token-service` 0.1.6 (cosign-verified 2026-10-09, `bootstrap/images/verify-digests.sh` 16/16) running in namespace `registry` (`k8s/base/registry/token-service`); public through `token.meddleware.co.uk` (Cloudflare rate-limit rule plus nginx 2 r/s per IP)
**Review date:** 2026-09-18 (first pass) · re-verified 2026-10-03 · re-verified 2026-10-09
**Reviewer:** Internal review
**Severity ceiling:** High — it gates registry push and pull, so a scope escalation or fail-open defect would allow unauthorised image pushes. No Critical or High defect found; realised ceiling Medium (F1, resolved).
**Status:** re-verified 2026-10-09

---

## Executive summary

The service authenticates a client with Hydra (client credentials), asks Keto for each requested
action (repository object first, then its organisation), and signs an RS256 token whose `access`
claim is the intersection of what was requested and what was granted. Every anchor failure answers
503; nothing fails open. It never parses tokens, so algorithm confusion is impossible on this side.

All first-pass findings are resolved, adjudicated or accepted. The 2026-10-03 pass found, and fixed in
0.1.3:

- **F7 (Low)** — `TOKEN_TTL` had no bounds: zero or a negative value minted already-expired tokens and
  a long one issued push credentials that outlived a revoked grant. It must now be 60–3600 seconds
  or the service refuses to start.
- **F8 (Low)** — the trust-boundary packages had no tests (Hydra and Keto clients at 0%, issuer and
  configuration partial), so the fail-closed mapping and the token format were asserted only in
  prose. They are now tested (each above 90%), including the RFC 7638 `kid` against the RFC's own
  example.

The 2026-10-09 re-verification added the AUTH lens (this audit predates it) and the IMG/GO rows, and
recorded the 0.1.5 and 0.1.6 hardening as findings, all RESOLVED: scope bounds and the Distribution
name grammar before Keto (F10), `Cache-Control: no-store` on every token answer (F11), an audit line
of requested versus granted scope (F12), end-to-end handler tests against fake Hydra and Keto (F13),
the key-rotation runbook (F14) and a release that runs full CI and scans the image before signing
(F15). The lens review also found items still open, none above Low and none a fail-open path:

- **F16 (Low, DEFERRED)** — only the first `scope` query parameter is read, although the
  Distribution spec lets a client repeat it; extra scopes are dropped (the service under-grants).
- **F17 (Low, DEFERRED)** — `SECURITY.md` and a runbook still describe SPIFFE mutual authentication
  on the Hydra/Keto hop, which the platform does not run (F4 already corrected the audit).
- **F18 (Low, DEFERRED)** — the MIT and BSD licence notices of the two bundled modules are not shipped
  in the image.
- **F22 (Low, DEFERRED)** — the published `cosign verify` command accepts any workflow in the
  repository rather than the release workflow.
- **F19, F20, F21 (Info, ACCEPTED-RISK)** — bounded Hydra/Keto error bodies reach the error log; each
  validation mints and discards a Hydra token; `.git` is not in `.dockerignore`.

The signing-key rotation has a written procedure but has not been rehearsed; that stays a
pre-mainnet maintainer item (Section D).

## Threat model / trust boundaries

| Actor | Holds / proves | Can do | Bounded by |
| --- | --- | --- | --- |
| Anonymous | nothing | reach `/token` | Basic auth required before any anchor call |
| Credential holder | Hydra client credentials | request any scope | Keto grants per action; `FilterActions`; `service` must match |
| On-path attacker (Hydra/Keto) | cluster network | delay, error | 503 on any failure; scoped NetworkPolicy; single node (WireGuard between nodes) |
| Registry | the token | enforce `iss`/`aud`/`exp`/`kid`/RS256 | short TTL (F7) |
| Key thief | the RSA key | forge tokens | operator custody: Secret 0440, UID 65534, ≥4096-bit check; rotation runbook (F14) |
| Identity provider (Hydra) | the client's secret check | accept or refuse a credential | 503 when unreachable or unexpected; the service never stores or compares a secret |
| Authorization service (Keto) | the grants | allow or deny each action | deny by default; 503 on anything but an explicit answer; tuples are written only by the setup Job inside the `auth` namespace |
| Relying verifier (the registry) | the public key in `rootcertbundle` | accept any token the key signs | pinned RS256, `iss`, `aud`, `kid`, `exp` on its side; token TTL 300 s |
| Registry client with a valid credential | a Hydra client secret | request tokens for any scope | granted ∩ requested (F10 bounds the request), audit line (F12) |

### Identity & credential matrix

| Authority / credential | Holder | What it confers | Misuse / compromise impact | Rotation / revocation plan |
| --- | --- | --- | --- | --- |
| Token-signing private key | Secret `token-service-keys` (mounted file, 0440, UID 65534) | mints tokens the registry accepts | forged push/pull tokens for any repository until the registry stops trusting the key | rotation with overlap, and the compromise procedure, in `docs/runbooks/key-rotation.md` (F14); not yet rehearsed |
| Hydra client secrets (`registry-ci-push`, `registry-node-pull`, `registry-browser`) | CI secrets, node, `registry-auth-proxy`'s mounted file; never this service | obtain tokens as that client within its Keto grants | impersonating the client | rotated in Hydra and the holder together (`hydra-client-setup` Job re-run); maintainer item (OPERATOR_TASKS.md) |
| Issued access token (bearer) | the Docker client, in transit | the granted scopes for 300 s | replay within the TTL | short TTL (60–3600 s enforced); single audience; `no-store` (F11); never logged |
| Keto tuples | the `auth` setup Job and an operator with Keto write access (port 4467, reachable only inside `auth`) | who may push, pull, list | privilege escalation by a written tuple | inventory in B.AUTH-2; the write port is not reachable from `registry` or `apps` |
| Hydra and Keto admin APIs | platform | create clients, write tuples | full takeover | not exposed beyond the platform (PLATFORM lens) |

## Severity scale

Critical / High / Medium / Low / Info / Positive.

## Scope

- **In scope (0.1.6):** `cmd/server/**`, `internal/{config,hydra,keto,token}/**`, tests, `Dockerfile`,
  workflows (`go-ci.yml`, `docker-publish.yml`, `dependabot.yml`), `SECURITY.md`, `docs/runbooks/*`,
  `k8s/base/registry/token-service/*`, `k8s/base/registry/networkpolicy.yaml`, and read-only
  `k8s/base/auth/{networkpolicy,jobs/*}` for the Hydra client and Keto tuple inventory.
- **Out of scope:** Hydra, Keto and the registry themselves; key custody; the registry credential
  inventory (maintainer item, `OPERATOR_TASKS.md` "Image registry credentials", before mainnet).
- **Environment (2026-10-09):** `go vet ./...` clean; `go test -race -cover ./...` green, 30 test
  functions (48 runs with subtests): config 93.8%, hydra 94.4%, keto 93.5%, token 91.4%,
  `cmd/server` 48.3% (the handler is covered; `main`, `healthCheck` and `logRequest` are not).
  golangci-lint v2.13.0 and govulncheck v1.8.0 run in CI: Go CI and Publish (Docker) for `v0.1.6`
  both succeeded 2026-10-09 (the local lint and govulncheck binaries are built with Go 1.25 and
  cannot load a 1.26 module, so they were not re-run here). Live check: `GET
  https://token.meddleware.co.uk/token` without credentials answers 401 with `Cache-Control:
  no-store`.

## Findings

### F1 — `service` not validated

**Severity:** Medium   **Disposition:** RESOLVED — a `service` other than `TOKEN_SERVICE` is refused
with 400 before any anchor call.
**Remediation / evidence:** `handleToken` (`cmd/server/main.go`); pinned by `TestToken_ServiceMustNameThisService`
and `TestHandleToken_ServiceMismatch` (neither reaches Hydra or Keto).

### F2 — Empty `access` issued with 200

**Severity:** Low   **Disposition:** ADJUDICATED — required by the Distribution token flow.
**Remediation / evidence:** `TestToken_DenyByDefaultAndEmptyAccessIsStillA200` pins the behaviour.

### F3 — No tests for the security-load-bearing code

**Severity:** Low   **Disposition:** RESOLVED (first pass: scope filter and handler 503 paths;
completed by F8 and F13).

### F4 — Plaintext to Hydra and Keto

**Severity:** Low   **Disposition:** RESOLVED (documented and layered) — in-cluster `http`,
fail-fast URL validation, NetworkPolicy admitting only these pods to Hydra and Keto, single-node
traffic; WireGuard encrypts between nodes (D18 corrected the earlier mutual-auth claim).
**Remediation / evidence (2026-10-09):** the policy is `k8s/base/auth/networkpolicy.yaml`: the `auth`
namespace is default-deny and admits the `registry` namespace only for the pod `app: token-service`
on ports 4444 (Hydra public) and 4466 (Keto read). Cilium WireGuard has been live since 2026-10-01
but the cluster has one node, so same-node pod traffic is not encrypted by it; there is no mutual
authentication (decision D18: Cilium deprecated SPIRE mutual auth). The residual risk is a hostile
pod on the node, bounded by the NetworkPolicy. `SECURITY.md` still claims SPIFFE mutual
authentication — F17.

### F5 — No `nbf`, no skew leeway

**Severity:** Info   **Disposition:** ACCEPTED-RISK — the registry applies its own leeway.
**Remediation / evidence:** unchanged; tokens carry `iat` and `exp` (`TestSignClaims` asserts the span).

### F6 — Verified-clean properties

**Severity:** Positive — stdlib Basic auth; `sub` from the authenticated client; JSON-encoded output;
errors never echo the secret. Re-checked 2026-10-09 against 0.1.6: the secret reaches only the Hydra
request; the client id is the only credential-derived value logged.

### F7 — `TOKEN_TTL` unbounded

**Severity:** Low   **Disposition:** RESOLVED (0.1.3)
**Where:** `internal/config/config.go`
**Issue / impact:** any integer was accepted. Zero or negative minted expired tokens (registry
outage); a large value (a typo such as `86400`) issued push tokens valid long after a Keto grant was
removed.
**Remediation / evidence:** 60–3600 seconds or startup fails; the deployment uses 300. Test
`TestLoadRefusesBadSettings`. Fixed in 0.1.3 (commit 68cbb6b).

### F8 — Trust boundaries untested

**Severity:** Low   **Disposition:** RESOLVED (0.1.3)
**Where:** `internal/hydra`, `internal/keto`, `internal/token/issuer.go`, `internal/config`
**Issue / impact:** the rules that keep the service fail-closed (only an explicit "allowed" or an
issued token counts; anything else is an error → 503) and the token format the registry depends on
had no tests; a refactor could have inverted a branch unnoticed.
**Remediation / evidence:** `client_test.go` (Hydra and Keto status and body mapping, credentials
and query values intact, unreachable anchor), `issuer_test.go` (verifies with `jwt.Parse` pinned to
RS256 with `aud` and `iss`; `kid` equals the thumbprint; RFC 7638 §3.1 example vector; string `aud`;
TTL span; access claim), `config_test.go` (PKCS1 and PKCS8, 2048-bit refused, unsupported PEM,
missing file, URL and TTL validation). Commit 68cbb6b (0.1.3). The handler, which this finding left
at 27.2%, is covered by F13.

### F9 — Repository and organisation objects share one Keto namespace

**Severity:** Info   **Disposition:** ADJUDICATED
**Where:** `checkRepoOrOrgPermission`
**Issue / impact:** an organisation's object is its bare name, which is also the object of a
single-segment repository of the same name, so a grant on repository `foo` also grants `foo/*`.
Grants are written only by the maintainer, and every repository here is `org/name`.
**Remediation / evidence:** documented; a distinct object prefix for organisations would need a
migration of the live tuples (Implementation suggestions). Behaviour pinned by
`TestToken_OrgGrantAppliesToItsRepositoriesAndCatalogNeedsListers`. Unchanged 2026-10-09.

### F10 — Token request unbounded and repository names unvalidated

**Severity:** Low   **Disposition:** RESOLVED (0.1.5)
**Where:** `cmd/server/main.go` `handleToken`, `internal/token/scope.go`
**Issue:** the `scope` value had no size or entry limit and a repository name was passed to Keto as the
object verbatim. Each requested action costs up to two sequential Keto checks, so any credential
holder could multiply its work at the authorization service, and a crafted name could address an
object that is not a repository (for example `catalog` with another relation or an organisation
object).
**Impact:** authorization-service load amplification by an authenticated client; Keto objects that
are not repository names. No scope escalation (Keto still decides).
**Remediation / evidence:** at most 16 scope entries and 4096 scope bytes, else 400
(`token.MaxScopeItems`, `token.MaxScopeBytes`); a repository name must match the Distribution name
grammar and 255 bytes (`token.ValidRepositoryName`) or it is never offered to Keto and grants
nothing. Tests `TestToken_RequestsAreBounded` (exactly 16 entries passes, 17 fails, an oversize
scope fails), `TestToken_MalformedRepositoryNamesNeverReachKeto`, `TestValidRepositoryName`. Commit
4a20b33 (0.1.5).

### F11 — Token answers were cacheable

**Severity:** Low   **Disposition:** RESOLVED (0.1.5)
**Where:** `handleToken`
**Issue:** RFC 6749 §5.1 requires `Cache-Control: no-store` and `Pragma: no-cache` on a token
response; the handler set neither.
**Impact:** a shared cache or proxy on the path could store a bearer token.
**Remediation / evidence:** both headers are set at the top of the handler, so every answer to a token
request carries them, errors included. Verified live 2026-10-09: the 401 from
`https://token.meddleware.co.uk/token` returns `cache-control: no-store` and `pragma: no-cache`.
Asserted in `cmd/server/token_flow_test.go`. Commit 4a20b33.

### F12 — No audit trail of what was granted

**Severity:** Low   **Disposition:** RESOLVED (0.1.5)
**Where:** `handleToken`
**Issue:** the success path logged nothing, so a misused credential could not be reconstructed.
**Impact:** no way to answer "which scopes did client X receive, and when" (needed by the compromise
procedure in F14).
**Remediation / evidence:** one `token issued` line per success with `client_id`, `requested` and
`granted` lists (`type:name:actions`), never a credential or token. Bounded by F10.
`TestToken_AuditLineNamesWhatWasGrantedAndNeverTheSecret`. Commit 4a20b33. Refusals are logged at
warn (`invalid client credentials`, `service mismatch`) or error (anchor failure) with the client id.

### F13 — Handler flow untested end to end

**Severity:** Low   **Disposition:** RESOLVED (0.1.5)
**Where:** `cmd/server/main.go`
**Issue:** after F8 the handler was the one trust-boundary component with 27.2% coverage; the
composition of Hydra, Keto, intersection and signing was asserted only in prose.
**Impact:** a refactor could invert a branch of the full flow without a failing test.
**Remediation / evidence:** `cmd/server/token_flow_test.go` (13 tests) runs the real handler against
fake Hydra and Keto servers: no credentials or invalid ones never reach an anchor, granted =
requested ∩ Keto, deny by default with an empty 200, organisation fallback and catalog needing
`listers`, unknown types and actions grant nothing, every anchor failure and an unreachable anchor
are 503, the audit line, the `service` check. Handler package coverage is now 48.3%; the untested
remainder is `main`, `healthCheck` and `logRequest`. Commit 4a20b33.

### F14 — No signing-key rotation or compromise procedure

**Severity:** Low   **Disposition:** RESOLVED (documented, commit 7bb4c8c, released with 0.1.6) —
rehearsal is a maintainer item before mainnet (Section D)
**Where:** `docs/runbooks/key-rotation.md`, `SECURITY.md`
**Issue:** the audit recorded "rotate on suspicion" with no steps; a one-step replacement of the key
and restart leaves a window in which every token is refused, and there was no compromise procedure.
**Impact:** an operator under pressure could lock out all pushes and pulls, or leave a stolen key
trusted.
**Remediation / evidence:** commit 7bb4c8c adds the runbook: a planned rotation with overlap (new
public key added to the registry's `rootcertbundle` first, key Secret replaced, wait one
`TOKEN_TTL`, then the old key removed) and a compromise procedure (trust only the new key at once,
review the `token issued` lines from F12). `SECURITY.md` links it. Not yet rehearsed against the live
registry, and the registry reads one `rootcertbundle` file, so the overlap relies on that file
holding both keys; a rehearsal confirms it. No automated rotation test exists because the
verifier is the registry, outside this repository.

### F15 — Release did not run CI and did not scan the image before signing

**Severity:** Low   **Disposition:** RESOLVED (0.1.6)
**Where:** `.github/workflows/docker-publish.yml`
**Issue:** the release's `verify` job ran only `go vet` and `go test -race`, so a `v*` tag skipped
the branch lint, govulncheck and filesystem scan, and the pushed image was not scanned before it
was signed.
**Impact:** a tag could ship what CI would have refused (IMG-M8, base §B.2 *Release gate equals CI*).
**Remediation / evidence:** the release calls `go-ci.yml` (lint, vet, race tests, govulncheck,
filesystem scan) as a reusable workflow (`verify`, a `needs` of both publish jobs, via
`workflow_call`), and the
`publish-public` job runs a Trivy scan of the pushed digest (fixable CRITICAL/HIGH fail) before
`cosign sign`. Commit a61d989 (0.1.6); the `v0.1.6` Publish run succeeded 2026-10-09. The Go builder
digest is pinned to the `go.mod` toolchain and checked in the Dockerfile (0.1.4, commit ee26f59:
govulncheck found eleven standard-library advisories in 1.26.7).

### F16 — Only the first `scope` parameter is read

**Severity:** Low   **Disposition:** DEFERRED — a one-line change plus a test (read `Query()["scope"]`,
join the values and apply the F10 bounds to the joined string); not mainnet-blocked, to ship in the
next patch release
**Where:** `cmd/server/main.go` `handleToken` (`r.URL.Query().Get("scope")`)
**Issue:** the Distribution token specification says `scope` is repeated once per entry of the
registry's challenge. `Get` returns the first value only, so later scopes are dropped silently. No
test sends repeated parameters (the helper builds one `scope` value).
**Impact:** a client that requests several scopes in separate parameters (for example a push with a
cross-repository mount: `repository:a:push,pull` and `repository:b:pull`) is granted only the first
entry and fails on the second. It fails closed — the service under-grants, never over-grants — and
the current clients (CI push, node pull, the browser proxy) work because they request one scope at a
time.
**Remediation / evidence:** not yet changed in code.

### F17 — `SECURITY.md` and a runbook still claim mutual authentication to Hydra and Keto

**Severity:** Low   **Disposition:** DEFERRED — documentation fix in `SECURITY.md` ("Transport to Hydra
and Keto") and `docs/runbooks/keto-outage.md` (the line on "the mutual-auth policy"), to ship with the
next patch release
**Where:** `SECURITY.md`, `docs/runbooks/keto-outage.md`
**Issue:** `SECURITY.md` says in-cluster traffic has "SPIFFE-based mutual authentication on the
token-service → Hydra/Keto path". The platform runs no mutual authentication
(`k8s/base/kube-system/cilium/values.yaml`, `k8s/base/auth/kustomization.yaml`, decision D18); F4
already records the correction.
**Impact:** a reader of the security policy would overstate the control on the hop that carries client
secrets in clear text inside the cluster. The real controls are the NetworkPolicy (F4) and, between
nodes, WireGuard.
**Remediation / evidence:** not yet changed in the repository's documents; the audit text is correct.

### F18 — Licence notices of bundled modules not shipped

**Severity:** Low   **Disposition:** DEFERRED — add the `golang-jwt/jwt` (MIT) and `google/uuid`
(BSD-3-Clause) licence texts to the runtime stage (for example `/THIRD_PARTY_LICENSES`, as the web
images do) and check it in CI; to ship in the next patch release
**Where:** `Dockerfile` runtime stage (`scratch`, binary and CA bundle only)
**Issue:** the compiled binary contains both modules; the image carries neither licence text. The
`.dockerignore` also excludes the project's own `LICENSE`, which the OCI label (`0BSD`) covers. The
SBOM attestation (`anchore/sbom-action` on the pushed image) lists the modules from the Go build
information, so the dependency list itself is present.
**Impact:** redistribution without the MIT and BSD notices; no security effect.
**Remediation / evidence:** not yet changed.

### F19 — Hydra and Keto error bodies reach the error log

**Severity:** Info   **Disposition:** ACCEPTED-RISK — bounded (4096 bytes from Hydra, 1024 from
Keto), only on the unexpected-status path, never returned to the client, never containing the
caller's secret (Hydra's error JSON names the error, not the credential); the text is the main
diagnostic for an anchor outage
**Where:** `internal/hydra/client.go`, `internal/keto/client.go` (`returned HTTP %d: %s`)
**Issue:** the AUTH lens asks that logs never contain identity-provider response bodies. These errors
embed the bounded body and `handleToken` logs them at error level.
**Impact:** an operator-readable log line may contain Hydra or Keto error text. The client sees only a
fixed 503 body.
**Remediation / evidence:** unchanged by decision; `TestToken_AuditLineNamesWhatWasGrantedAndNeverTheSecret`
asserts that the caller's secret never appears in the log.

### F20 — Credential validation mints and discards a Hydra token

**Severity:** Info   **Disposition:** ACCEPTED-RISK — inherent to delegating the check to Hydra's
token endpoint (Hydra has no verify-only endpoint for client secrets); load is bounded by the Cloudflare rule (5 requests
per 10 s per IP) and the nginx limit (2 r/s, burst 20) in front of `/token`
**Where:** `hydra.ValidateClientCredentials`
**Issue:** each `/token` request with a plausible credential performs a client-credentials grant, so
Hydra issues and stores an access token that is thrown away.
**Impact:** token-table growth in Hydra proportional to the request rate; bounded by the limits above
and Hydra's token expiry. The service itself stays stateless.
**Remediation / evidence:** noted; no cache is added because CLAUDE.md forbids an in-memory client
credential cache.

### F21 — `.git` is not excluded from the build context

**Severity:** Info   **Disposition:** ACCEPTED-RISK — the data only enters the discarded build stage
(`COPY . .`); the `scratch` runtime stage copies the binary and the CA bundle, so no layer of the
published image holds it, and CI builds from a clean checkout. The one-line fix (`.git` in
`.dockerignore`) can ride with the next release.
**Where:** `.dockerignore` (excludes `.env*`, `.github/`, docs and licence files, not `.git`)
**Issue:** the IMG lens asks that VCS data be kept out of the build context.
**Impact:** none on the image; a local build would send `.git` to the daemon.
**Remediation / evidence:** noted 2026-10-09.

### F22 — Published `cosign verify` command is repository-wide, not workflow-pinned

**Severity:** Low   **Disposition:** DEFERRED — documentation fix: the `README.md` command (and the
workspace's `bootstrap/images/verify-digests.sh` default, which uses the same shape) should use the
anchored form `^https://github.com/meddleware-org/registry-token-service/\.github/workflows/docker-publish\.yml@refs/tags/v`,
as static-server's `SECURITY.md` already does; to ship with the next patch release
**Where:** `README.md` "Verifying" section
**Issue:** `--certificate-identity-regexp 'https://github.com/meddleware-org/registry-token-service/.*'`
is unanchored and accepts a signature from any workflow in the repository, on any ref (IMG-M8).
**Impact:** a verifier trusts more than the release workflow; the cluster-side check
(`verify-digests.sh`, 16/16 valid on 2026-10-09) inherits the same breadth.
**Remediation / evidence:** not yet changed.

## Section A — Invariant verification matrix

| # | Invariant | Enforced at | Proven by | Status |
| --- | --- | --- | --- | --- |
| I1 | Keto decides; any failure is 503 | `keto.CheckPermission`; handler | `keto/client_test.go`; `TestToken_EveryAnchorFailureIsA503`; `TestToken_AnUnreachableAnchorIsA503` | HOLDS |
| I2 | Hydra decides; any failure is 503 | `hydra.ValidateClientCredentials`; handler | `hydra/client_test.go`; the same handler tests | HOLDS |
| I3 | RS256 only; key ≥ 4096 bits | issuer; `config.Load` | `issuer_test.go`; `config_test.go` | HOLDS |
| I4 | `access` = requested ∩ granted | `FilterActions`; handler | `scope_test.go`; `TestToken_GrantIsTheIntersectionOfRequestedAndGranted` | HOLDS |
| I5 | Short-lived, stateless tokens | issuer; TTL bounds | `config_test.go` | HOLDS (F7) |
| I6 | `service` must match | handler | `TestToken_ServiceMustNameThisService`; `TestHandleToken_ServiceMismatch` | HOLDS (F1) |
| I7 | Unauthenticated requests never reach an anchor | handler | `TestToken_NoCredentialsNeverReachesAnAnchor` | HOLDS |
| I8 | A request is bounded (16 entries, 4096 bytes) | `handleToken` | `TestToken_RequestsAreBounded` | HOLDS (F10) |
| I9 | Only a well-formed repository name becomes a Keto object | `token.ValidRepositoryName` | `TestToken_MalformedRepositoryNamesNeverReachKeto`; `TestValidRepositoryName` | HOLDS (F10) |
| I10 | Every token answer is `no-store` | top of `handleToken` | handler tests; live 401 on 2026-10-09 | HOLDS (F11) |
| I11 | Each grant is logged with requested and granted scope, never a credential | `handleToken` | `TestToken_AuditLineNamesWhatWasGrantedAndNeverTheSecret` | HOLDS (F12) |
| I12 | Every requested scope entry is evaluated, including repeated `scope` parameters | `handleToken` (`Query().Get`) | none | GAP — F16 (under-grants, fails closed) |
| I13 | Signing key rotates with overlap and has a compromise procedure | `docs/runbooks/key-rotation.md` | not rehearsed | HOLDS (code-only) — F14 |

### Lens categories

| Lens | Category | Status |
| --- | --- | --- |
| GO | HTTP server hygiene | HOLDS (code-only) — `ReadTimeout` 10 s (covers headers; no separate `ReadHeaderTimeout`), `WriteTimeout` 15 s, `IdleTimeout` 60 s, `MaxHeaderBytes` at the net/http default (1 MiB, behind nginx and Cloudflare); `GET`-only routes (the mux answers 405 otherwise); no request body is read; a handler panic is recovered per connection by net/http |
| GO | Outbound calls | HOLDS — Hydra `http.Client` 10 s, body ≤ 4096 B; Keto 5 s, body ≤ 1024 B; in-cluster `http`, no TLS settings to weaken (F4); the default redirect policy is left, the hosts are fixed in-cluster services |
| GO | Input & path handling | HOLDS — no file access; scope size, entry count and name grammar are bounded (F10) |
| GO | AuthN / AuthZ | HOLDS — see the AUTH rows; no local secret comparison exists (Hydra checks) |
| GO | Secrets | HOLDS — key from a read-only Secret mount; client secrets only in the Hydra request, never logged (`TestToken_AuditLineNamesWhatWasGrantedAndNeverTheSecret`) |
| GO | Client identity / rate limits | at the ingress: Cloudflare rule (5 per 10 s per IP on `/token`) and nginx 2 r/s burst 20 on the last `X-Forwarded-For` hop (`docs/networking/RATE_LIMITS.md`); the service keys nothing on a client address |
| GO | Concurrency | HOLDS — `go test -race` green; no shared mutable state in the handler |
| GO | Graceful shutdown | HOLDS (code-only) — SIGTERM and SIGINT call `Server.Shutdown` with 10 s |
| GO | Health endpoint | HOLDS — `/healthz` returns `{"status":"ok"}`; there is no `/version` |
| GO | Error handling | HOLDS — fixed JSON error bodies; Hydra/Keto bodies reach only the log (F19) |
| GO | CI (B.GO-1) | HOLDS — `go.sum` committed; `go vet`, golangci-lint v2.13.0, `go test -race`, govulncheck v1.8.0 (pinned) and a Trivy filesystem scan in `go-ci.yml`; build uses `-trimpath`, `CGO_ENABLED=0`, version injected with `-X main.version` |
| IMG | Base images | HOLDS — builder digest-pinned and checked against the `go.mod` toolchain; runtime `scratch` |
| IMG | Build context | HOLDS with a nit — `.env*` excluded; `.git` is not (F21) |
| IMG | Reproducible build stage | HOLDS — `go mod download` from `go.mod`/`go.sum`; no installers; only the binary and CA bundle reach the runtime stage |
| IMG | No secrets in layers | HOLDS — build args are OCI label strings |
| IMG | Runtime user & filesystem | HOLDS — `USER 65534:65534`; pod: `runAsNonRoot`, `readOnlyRootFilesystem`, `allowPrivilegeEscalation: false`, capabilities dropped, `RuntimeDefault` seccomp, `automountServiceAccountToken: false` |
| IMG | Runtime configuration | HOLDS — the image sets only `PORT`; the manifest sets `TOKEN_*`, `HYDRA_TOKEN_URL`, `KETO_READ_URL`, `RSA_PRIVATE_KEY_PATH`, `LOG_LEVEL` |
| IMG | Health & resources | HOLDS — readiness and liveness on `/healthz`; requests 20m/32Mi, limits 200m/128Mi |
| IMG | SBOM & notices | SBOM HOLDS (SPDX attestation from the pushed image); licence notices GAP — F18 |
| IMG | Scan before sign | HOLDS — Trivy on the pushed digest before `cosign sign` (F15) |
| IMG | Verification command | GAP — F22 |
| IMG | Deployment pinning | HOLDS — digest from `config/images.yaml` stamped into the `registry` overlay; cosign-verified 2026-10-09 |
| AUTH | Issuer keys & signing | HOLDS — RS256 fixed in code (`jwt.SigningMethodRS256`); key ≥ 4096-bit from a mounted file; `kid` = RFC 7638 thumbprint (tested against the RFC example); rotation with overlap documented (F14), not rehearsed |
| AUTH | Token claims & lifetime | HOLDS — `iss`, `aud` (string), `sub` (the authenticated client), `exp`, `iat`, `jti` (UUID); no `nbf` (F5); TTL 60–3600 s enforced, 300 s deployed; claims minimal |
| AUTH | Token verification | N/A — the service issues and never parses tokens; the registry verifies |
| AUTH | Credential validation is delegated | HOLDS — Hydra only; no local store or allowlist |
| AUTH | Fail closed | HOLDS — Hydra or Keto down, slow, or unexpected status gives 503 (`TestToken_EveryAnchorFailureIsA503`, `TestToken_AnUnreachableAnchorIsA503`); timeouts on both clients |
| AUTH | Authorization model | HOLDS — deny by default; granted = requested ∩ Keto; repository then organisation fallback is a deliberate broad grant (F9) |
| AUTH | OAuth client configuration | N/A in this repository; the three client-credentials clients are registered by `k8s/base/auth/jobs/hydra-client-setup.yaml` (B.AUTH-2); no redirect URIs apply |
| AUTH | Client-side token caching | N/A — nothing cached; CLAUDE.md forbids a credential cache |
| AUTH | Inbound credential handling | HOLDS — the Basic credential is forwarded only to the configured Hydra URL; the service injects nothing else |
| AUTH | Identity-provider configuration | out of this repository (PLATFORM lens); Hydra client-credentials only, no registration flow involved |
| AUTH | Error & enumeration hygiene | HOLDS — 401 with `WWW-Authenticate: Basic` for missing or invalid credentials, uniform `invalid credentials` body; 400 for bad input; 503 for anchors; the log carries bounded anchor text (F19) |
| AUTH | Abuse limits | HOLDS at the edge — Cloudflare rule plus nginx per-IP limit; the service has none of its own (F20 notes the Hydra cost) |
| AUTH | Transport to identity services | MITIGATED — in-cluster `http`; NetworkPolicy to the single pod, WireGuard between nodes, one node; no mutual authentication (F4, F17) |
| AUTH | Audit trail | HOLDS — `token issued` line (F12); Hydra and Keto keep their own admin logs |

## Section B — Supply-chain, publish-authority & capability matrix

### B.1 Dependency & CVE risk

| Dependency | Pinned version | Liveness dependency? | CVE / audit status | Notes |
| --- | --- | --- | --- | --- |
| `golang-jwt/jwt/v5` | v5.3.1 (`go.sum`) | signing | govulncheck clean in CI | signing only; no parsing in the service |
| `google/uuid` | v1.6.0 | `jti` | clean | |
| Go toolchain | go1.26.9 (`go.mod` `toolchain`; builder digest `sha256:d9c68c2c…`) | build | 0.1.4 moved off 1.26.7 (eleven stdlib advisories, GO-2026-6607…6617) | the Dockerfile fails if the builder differs from `go.mod` |
| Ory Hydra | v2.3.0 (digest-pinned in `k8s/base/auth`); client-credentials grant at `POST /oauth2/token` | yes — 503 when down (fails closed) | upstream | `docs/runbooks/keto-outage.md` covers Keto; a Hydra outage logs `auth service unavailable` |
| Ory Keto | v0.14.0 (digest-pinned); `GET /relation-tuples/check` on the read port 4466 | yes — 503 when down (fails closed) | upstream | an undefined relation makes Keto reject the check, which becomes 503 |
| Trivy / govulncheck / golangci-lint | v0.74.0 / v1.8.0 / v2.13.0 (pinned in workflows) | CI | | |

### B.2 Publish authority, capabilities & secret custody

| Authority / secret | Where held | Custody | Gates | Rotation |
| --- | --- | --- | --- | --- |
| RSA signing key | k8s Secret `token-service-keys` (0440, SOPS at rest) | maintainer | every registry token | `docs/runbooks/key-rotation.md` (overlap and compromise); not rehearsed — Section D |
| `QUAY_TOKEN`, `DOCKERHUB_TOKEN`, `PRIVATE_REGISTRY_*` | GitHub secrets | robot accounts | image push | inventory (scope, holder, rotation date) is a maintainer item before mainnet — `OPERATOR_TASKS.md` "Image registry credentials"; the self-hosted mirror job is best-effort and fails without its credentials |
| Image signature, SBOM and provenance attestations | `publish-public` job (Sigstore keyless, `id-token: write` on that job only) | GitHub OIDC | what the cluster trusts | n/a |

CI and release integrity (base §B.2): actions pinned by full SHA (`go-ci.yml`, `docker-publish.yml`); an
explicit `permissions:` block (`contents: read`; `id-token` and `attestations` only on `publish-public`);
tag-gated release (`v*`); release gate equals CI (F15); Dependabot weekly and grouped for Docker, Go
modules and GitHub Actions (`.github/dependabot.yml`); no `set -x` or secret echo; no real-funds job;
no test-only build mode. Idempotent publish: a re-run of a tag pushes the same tags again (no
overwrite protection beyond the registry's own); the digest, not the tag, is what the cluster trusts.

### B.IMG-1 Publish & attestation

Each pushed image (quay.io and Docker Hub, multi-arch, signed at the index digest) carries a keyless
cosign signature, an SPDX SBOM attached as a signed attestation (`cosign attest --type spdxjson`) and a
GitHub build-provenance attestation, plus BuildKit `provenance: mode=max`; none of these steps uses
`continue-on-error`. The self-hosted registry push (`publish-private`) is a best-effort mirror: it
carries `continue-on-error`, is not signed, and fails without credentials (maintainer item).

### B.AUTH-1 Key & credential inventory

| Key / credential (name only) | Type / algorithm | Where held | Who can read it | Rotation cadence · last rotated | Compromise procedure |
| --- | --- | --- | --- | --- | --- |
| `signing.key` | RSA ≥ 4096-bit, RS256 | Secret `token-service-keys`, mounted 0440 | the token-service pod (UID 65534); the maintainer with cluster access | no fixed cadence; rotated on suspicion; last rotation not recorded in this audit | `docs/runbooks/key-rotation.md`, compromise section (F14) |
| Public half of the signing key | RSA public key | registry `rootcertbundle` (`/etc/registry/certs/token-service.pub.pem`) | the registry | rotates with the key (overlap) | as above |
| `registry-ci-push`, `registry-node-pull`, `registry-browser` client secrets | Hydra client secrets | Secret `hydra-client-secrets` (applied by the setup Job); CI secrets; node; `registry-auth-proxy`'s mounted file | the holders; never this service | on suspicion; re-run `hydra-client-setup` after updating the Secret | rotate the Secret and re-run the Job; review `token issued` lines (F12) |
| `QUAY_TOKEN`, `DOCKERHUB_TOKEN`, `PRIVATE_REGISTRY_*` | registry robot tokens | GitHub secrets | GitHub Actions (publish jobs) | maintainer item — `OPERATOR_TASKS.md` | revoke in the registry console |

### B.AUTH-2 Client & authorization inventory

| OAuth client / relation | Type, grant types, auth method | Redirect URIs | Scopes / relations granted | Owner | Last reviewed |
| --- | --- | --- | --- | --- | --- |
| `registry-ci-push` | confidential; `client_credentials`; Basic (`client_secret_basic`) | none | Hydra scope `registry:push registry:pull`; Keto `pushers` and `pullers` on org `meddleware-org` | maintainer | 2026-10-09 |
| `registry-node-pull` | confidential; `client_credentials`; Basic | none | Hydra scope `registry:pull`; Keto `pullers` on `meddleware-org` | maintainer | 2026-10-09 |
| `registry-browser` | confidential; `client_credentials`; Basic | none | Hydra scope `registry:push registry:pull registry:catalog`; Keto `pullers` on `meddleware-org`, `listers` on `catalog` (no `pushers` tuple, so the browser cannot push) | maintainer | 2026-10-09 |
| Keto `Registry#pullers` / `#pushers` / `#admins` | tuples on a repository or organisation object; `delete` maps to `admins` | n/a | checked repository first, then organisation | maintainer | 2026-10-09 |
| Keto `Registry:catalog#listers` | tuple | n/a | `registry:catalog:*` | maintainer | 2026-10-09 |

The service requests Hydra's grant without a scope (OQ6), so the Hydra scopes above are not what
limits access; Keto is. Tuples are written by `keto-relations-setup` inside the `auth` namespace,
and the Keto write port (4467) is not reachable from `registry` or `apps` (`networkpolicy.yaml`).

### B.AUTH-3 Protocol conformance

Distribution token authentication specification (Docker Registry v2 token auth), followed as:
`GET /token?service=&scope=` with HTTP Basic credentials; response `{"token","expires_in","issued_at"}`;
JWT header `typ`/`alg` RS256 and `kid` = JWK SHA-256 thumbprint (RFC 7638) matching the registry's
trusted key; claims `iss`, `sub`, `aud` (a plain string, as the Distribution v3 parser expects), `exp`,
`iat`, `jti`, `access` (`type`, `name`, `actions`). Deviations: no `nbf` (F5); the `access` list can
be empty with 200 (F2, as the flow requires); repeated `scope` parameters are not honoured (F16);
`offline_token`, `client_id` and `account` are ignored. The wire shape is pinned by `TestSignClaims`
(`aud` string, `kid`, TTL span, access list) and `TestThumbprintMatchesRFC7638`. No RFC 9728 or OIDC
discovery applies.

## Section C — Test-coverage & hermetic/live split

### C.1 Coverage grade — A− (trust-boundary packages above 90%; the handler flow covered end to end by fakes)

| Dimension | Assessment |
| --- | --- |
| Happy-path coverage | covered — intersection, organisation fallback, catalog (`token_flow_test.go`) |
| Error-path coverage | covered — no credentials, invalid credentials, every Hydra and Keto failure mode, unreachable anchors, bad `service`, oversize and over-long scope |
| Boundary / edge cases | covered — exactly 16 entries passes, 17 fails; malformed and 256-byte names; empty scope; unknown types and actions; TTL bounds; 2048-bit key refused |
| Security-relevant coverage | covered — `kid` against the RFC 7638 example; string `aud`; no secret in the log; deny by default. Not covered: repeated `scope` parameters (F16); `main`, shutdown and `logRequest`; rotation (verifier is the registry) |

`go test -race -cover ./...` on 2026-10-09: 30 test functions (48 runs with subtests), all passing;
`cmd/server` 48.3%, `internal/config` 93.8%, `internal/hydra` 94.4%, `internal/keto` 93.5%,
`internal/token` 91.4%.

### C.2 Hermetic vs. live paths

| Path | Hermetic? | Deferred to | Tracking |
| --- | --- | --- | --- |
| Anchors, issuer, config, scope, handler | yes (fake Hydra and Keto servers) | — | `go test` |
| Live Hydra, Keto and registry; token accepted by the registry | no | cluster | platform-probe's `/v2/_catalog` chain check (status page "registry" check) |
| Key rotation with overlap against the live registry | no | rehearsal | maintainer, before mainnet (Section D) |

## Section D — Deployment-readiness gates

### pre-localnet

- [x] builds; tests, vet, lint, govulncheck green; config fails closed — Go CI green on `main` and on the `v0.1.6` tag, 2026-10-09
- [x] algorithm pinned; keys from a mounted file; nothing secret in source or logs — `jwt.SigningMethodRS256`, `config.Load`, F12 test
- [x] fail-closed tests for Hydra and Keto outages green — `TestToken_EveryAnchorFailureIsA503`, `TestToken_AnUnreachableAnchorIsA503`
- [x] server timeouts, body limits (no body read; request bounded by F10) and outbound client timeouts set
- [x] every `FROM` digest-pinned; `.dockerignore` excludes local env files (the `.git` nit is F21); lockfile install; no secrets in `ARG`/`ENV`/`COPY`/`RUN`

### pre-testnet

- [x] deployed with scoped NetworkPolicy; `SECURITY.md`; key custody documented
- [x] 0.1.6 deployed (digest in `config/images.yaml`, cosign-verified 2026-10-09); the status page's registry chain check reads operational
- [x] B.AUTH-1 key and credential inventory and B.AUTH-2 client and relation inventory complete (above)
- [x] OAuth clients registered with minimal grants (client-credentials only, no redirect URIs); the browser client has no `pushers` tuple
- [x] non-root runtime; pod security context complete; probes and limits set; deployment by digest from `config/images.yaml`
- [ ] documentation matches the platform — F17 (mutual-authentication claim), F22 (workflow-pinned verify command), F18 (licence notices): next patch release
- [ ] repeated `scope` parameters evaluated — F16: next patch release

### pre-mainnet

- [ ] key rotation with overlap rehearsed against the live registry — maintainer item (`docs/runbooks/key-rotation.md` exists, F14)
- [ ] registry credential inventory (`QUAY_TOKEN`, `DOCKERHUB_TOKEN`, `PRIVATE_REGISTRY_*`: scope, holder, rotation date) — maintainer item, `OPERATOR_TASKS.md` "Image registry credentials"
- [x] token endpoint rate-limited (Cloudflare rule and nginx per IP); SIGTERM drains in-flight requests; health endpoint reveals nothing sensitive
- [x] signature, SBOM attestation and provenance on every pushed public image, no `continue-on-error` (the self-hosted mirror is listed as best-effort)
- [ ] external review of the issuing path — mainnet/maintainer item
- [x] no chain dependency; no additional gate

## Cross-project themes

- **Fail closed** — every anchor failure is 503; tests pin it (F8, F13).
- **Supply chain** — two small modules; pinned scanners, actions and builder; signed images with
  SBOM and provenance; release gate equals CI and the image is scanned before signing (F15); Dependabot
  configured; the registry credential inventory is a maintainer item.
- **Wire-format coupling** — the registry's token parser (string `aud`, `kid` thumbprint) is pinned by
  issuer tests; the live chain check exercises the real registry.
- **On-chain-truth boundary** — N/A; no chain involvement.
- **Deployment readiness** — Section D, kept current.
- **Chain-access layering** — N/A.

## Normative requirements (MUST / MUST NOT)

- **GO-M1–GO-M8** — hold (GO-M6 at the ingress; GO-M1 as stated in Section A, the request body is never read).
- **IMG-M1–IMG-M7** — hold. **IMG-M8** — scan before sign and the SBOM hold; licence notices (F18) and
  the workflow-pinned verification command (F22) do not yet.
- **AUTH-M1** — N/A (the service does not verify tokens); its issuer side holds: RS256 fixed in code,
  `kid` from the key.
- **AUTH-M2** — holds for the signing key (mounted file); rotation with overlap is written down (F14)
  but not rehearsed.
- **AUTH-M3** — holds: audience-specific, 60–3600 s enforced, minimal claims.
- **AUTH-M4, AUTH-M5** — hold: Hydra validates, fail closed, deny by default, requested ∩ granted.
- **AUTH-M6, AUTH-M7, AUTH-M8, AUTH-M9, AUTH-M11** — N/A (no redirect clients, no browser session, no
  injection, no user tokens, no signed challenge).
- **AUTH-M10** — holds: uniform authentication errors, rate limits at the edge, decisions logged
  without credentials (F12).

## Implementation suggestions (SHOULD / MAY)

- SHOULD give organisation objects a distinct prefix in Keto (e.g. `org:<name>`), with a one-time
  tuple migration, so repository and organisation grants can never coincide (F9).
- SHOULD read every `scope` parameter and add a repeated-parameter test (F16).
- SHOULD correct `SECURITY.md` and the Keto runbook on mutual authentication (F17), ship licence
  texts in the image (F18), add `.git` to `.dockerignore` (F21) and anchor the `cosign verify`
  regexp (F22) in one patch release.
- MAY add a rotation rehearsal script that signs with two keys and checks a registry accepts both.
- MAY add the missing 0.1.1 and 0.1.2 changelog entries.

## Open questions (`OQ#`)

- **OQ1** — Ignore `service` deliberately? (Decided: no — validated; see F1.)
- **OQ2** — (Decided: 200 with empty access — see F2.)
- **OQ3** — Is `registry:catalog` the only `registry:*` scope needed? (Decided: yes — the browser UI
  lists the catalog; nothing else uses `registry:*`.)
- **OQ4** — Does `admins` imply `delete`? (Decided: yes — delete maps to `admins`; push and pull are
  checked independently.)
- **OQ5** — Keto's deny shape? (Decided: 403 and 200-with-false both read as deny; anything else is
  503 — now tested.)
- **OQ6** — Do client-credentials clients need a `scope`? (Decided: no — the grant is requested
  without one, and the live chain check succeeds.)

## Risks

- **Anchor liveness** — Keto or Hydra down halts all pushes and pulls (by design).
- **Key custody** — the signing key forges any token; rotation is documented but unrehearsed.
- **Plaintext hop** — Hydra/Keto traffic is in-cluster `http` with no mutual authentication; on one
  node, a hostile pod on the node is bounded only by the NetworkPolicy.
- **Supply-chain mutability** — Hydra, Keto and the registry are upstream images; registry robot
  credentials are long-lived until the maintainer inventory is done.

## Re-verification log

- 2026-09-18 — first-pass baseline (F1–F6).
- 2026-10-01 — D18 correction to F4 (NetworkPolicy applied; mutual-auth claim withdrawn).
- 2026-10-03 — re-verified under AUDIT_TEMPLATE.md + GO + IMG (Phase 7): F7, F8 RESOLVED in 0.1.3;
  F9 recorded; OQs decided; govulncheck pinned.
- 2026-10-08 — Lens dates reconciled with the registry (`check-template-dates.mjs`): base 2026-10-08, and SUI_CLIENT/GO 2026-10-08 and TS 2026-10-03 where cited. The changes (AUTH/PLATFORM/MCP/DB registered, the GO token row moved to AUTH, JSR in trusted publishing, layered injection guards) alter no disposition here. The GO AuthN row now points to the AUTH lens; adding AUTH to this audit is part of the alignment step.
- 2026-10-09 — re-verified against 0.1.6 (image `sha256:1f3d27f4…`, cosign-verified, Go CI and
  Publish green): added the AUTH lens (front-matter fields, identity and credential matrix, A rows,
  B.AUTH-1/2/3, Section D) and the IMG/GO rows; IMG date reconciled to 2026-10-08. New findings from
  the 0.1.4–0.1.6 work, all RESOLVED: F10 (scope bounds and name grammar), F11 (`no-store`), F12 (audit
  line), F13 (handler tests, 30 test functions), F14 (rotation runbook), F15 (release runs full CI,
  image scanned before signing). New open findings from the lens review: F16 (repeated `scope`
  parameters, DEFERRED), F17 (stale mutual-authentication claim in `SECURITY.md`, DEFERRED), F18
  (licence notices, DEFERRED), F22 (verify command not workflow-pinned, DEFERRED); F19, F20, F21
  ACCEPTED-RISK. F1–F9 re-checked and annotated with their tests; dispositions unchanged. Totals: 22
  findings — 11 RESOLVED (F1, F3, F4, F7, F8, F10–F15), 2 ADJUDICATED (F2, F9), 4 ACCEPTED-RISK (F5,
  F19, F20, F21), 4 DEFERRED (F16, F17, F18, F22), 1 Positive (F6). The DEFERRED items are
  documentation or one-line code changes for the next patch release, not mainnet-blocked.
