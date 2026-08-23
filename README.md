# registry-token-service

A minimal, security-critical token service that implements the
[CNCF Distribution registry token authentication specification](https://distribution.github.io/distribution/spec/auth/token/).
It sits in front of a Distribution (`registry:3`) instance and answers the token
requests Docker clients make during `docker push` / `docker pull`, delegating
**authentication** to [Ory Hydra](https://www.ory.sh/hydra/) and **authorization**
to [Ory Keto](https://www.ory.sh/keto/), then issuing short-lived RS256 JWTs the
registry validates directly.

- **Runtime base:** `scratch` (zero OS footprint, no shell, no package manager)
- **Language:** Go (stdlib + `golang-jwt` + `google/uuid`)
- **Non-root:** runs as UID/GID `65534`
- **License:** BSD Zero Clause ([0BSD](LICENSE))

> This is infrastructure glue with a small, sharp security surface. Read
> [SECURITY.md](SECURITY.md) before deploying — the invariants there are load-bearing.

## How it works

```
docker push registry.example.com/myorg/image
  → Registry: 401 WWW-Authenticate: Bearer realm=https://token.example.com/token, service=registry.example.com
  → Docker:   GET /token?service=registry.example.com&scope=repository:myorg/image:push
              Authorization: Basic base64(client_id:client_secret)
  → token-service:
      1. Validate client_id:client_secret via Hydra /oauth2/token (client_credentials)
      2. Check each requested action in Keto (Registry namespace, repo, relation)
      3. Sign an RS256 JWT whose access list = requested ∩ granted
  → Docker:   retry push with the Bearer JWT
  → Registry: verify JWT signature against the configured public key, allow/deny
```

The service is **stateless**: no sessions, no token cache, no refresh. Clients
transparently re-request tokens on expiry.

## Quick start

The service needs a ≥ 4096-bit RSA signing key and reachable Hydra + Keto endpoints.

```bash
# 1. Generate a signing key (the registry gets the matching public key).
openssl genrsa -out signing.key 4096
openssl rsa -in signing.key -pubout -out signing.pub.pem

# 2. Run the image (see .env.example for every variable).
docker run --rm -p 8080:8080 \
  -e TOKEN_ISSUER=https://token.example.com \
  -e TOKEN_SERVICE=registry.example.com \
  -e HYDRA_TOKEN_URL=http://hydra:4444/oauth2/token \
  -e KETO_READ_URL=http://keto:4466 \
  -v "$PWD/signing.key:/etc/token-service/signing.key:ro" \
  quay.io/meddleware-org/registry-token-service:latest
```

Point the Distribution registry's `auth.token` block at this service
(`realm: https://token.example.com/token`, `service`, `issuer`, and
`rootcertbundle` = the public key above).

## Configuration

| Variable | Required | Default | Description |
| --- | --- | --- | --- |
| `PORT` | no | `8080` | HTTP listen port |
| `TOKEN_ISSUER` | **yes** | — | `iss` claim (e.g. `https://token.example.com`) |
| `TOKEN_SERVICE` | **yes** | — | `aud` claim + registry service name |
| `TOKEN_TTL` | no | `300` | Token lifetime in seconds |
| `RSA_PRIVATE_KEY_PATH` | no | `/etc/token-service/signing.key` | PEM RSA private key (≥ 4096-bit; the service refuses to start otherwise) |
| `HYDRA_TOKEN_URL` | **yes** | — | Hydra public token endpoint (`POST /oauth2/token`) |
| `KETO_READ_URL` | **yes** | — | Keto read API base URL |
| `LOG_LEVEL` | no | `info` | `debug \| info \| warn \| error` |

## Endpoints

| Endpoint | Description |
| --- | --- |
| `GET /token` | Token endpoint — HTTP Basic auth + `service`/`scope` query params |
| `GET /healthz` | Liveness/readiness probe (`200 {"status":"ok"}`) |

The binary also supports `-healthcheck`, which dials `/healthz` and exits `0`/`1`
(used by the container `HEALTHCHECK` on Docker/Compose; Kubernetes uses its own probes).

## Authorization model (Keto)

Permissions are checked against the `Registry` namespace:

| Relation | Grants |
| --- | --- |
| `pullers` | pull |
| `pushers` | push |
| `admins`  | delete |

Subjects are Hydra `client_id`s. `pushers` and `pullers` are checked independently
(a push token requires a `pushers` grant; it does not imply pull).

**Two-tier object check.** For a `repository:<name>:<action>` scope, the service first
checks the specific repository object (e.g. `meddleware-org/static-server`) and, if that
is not granted, falls back to the **org object** — the path segment before the first `/`
(e.g. `meddleware-org`). This means:

- Grant an identity on the org object once and it can push/pull **every current and
  future repo** in that org — no per-image tuple churn (this is what lets the registry
  mirror new images dynamically).
- Grant an identity on a specific `org/repo` object to scope it to just that repo; the
  repo-level grant is evaluated before the org-level fallback.

Catalog listing (`registry:catalog:*`) is authorized separately via the `listers`
relation on the fixed `catalog` object.

A client requesting `push` that only has `pull` receives a token scoped to `pull` —
never an error, never an escalation.

## Verifying published images

Images are multi-arch, carry an SBOM + SLSA provenance, and are signed with keyless
[cosign](https://docs.sigstore.dev/):

```bash
cosign verify \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp 'https://github.com/meddleware-org/registry-token-service/.*' \
  quay.io/meddleware-org/registry-token-service:<tag>

# Inspect provenance / SBOM attestations:
cosign download attestation quay.io/meddleware-org/registry-token-service:<tag>
```

## Building

```bash
# Local binary
go build -o token-service ./cmd/server

# Container image (reproducible; base pinned by digest)
docker build --build-arg VERSION=v0.1.0 \
  -t quay.io/meddleware-org/registry-token-service:v0.1.0 .
```

## Contributing / development

See [AGENTS.md](AGENTS.md) for the package layout, auth-flow detail, and testing
recipes, and [CLAUDE.md](CLAUDE.md) for the architectural invariants. CI runs
`golangci-lint`, `go vet`, race tests, `govulncheck`, and a Trivy filesystem scan;
all must pass before a `v*` tag triggers a signed multi-registry release.
