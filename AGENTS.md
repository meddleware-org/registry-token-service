# AGENTS.md — registry-token-service

## Purpose

Implements the [Distribution registry token auth specification](https://distribution.github.io/distribution/spec/auth/token/).
When a Docker client pushes or pulls from `registry.meddleware.co.uk`, the registry redirects
authentication to this service via `WWW-Authenticate: Bearer realm="https://token.meddleware.co.uk/token"`.

## Auth flow

```
docker push registry.meddleware.co.uk/myorg/image
  → Registry: 401 WWW-Authenticate: Bearer realm=..., service=registry.meddleware.co.uk
  → Docker: GET /token?service=registry...&scope=repository:myorg/image:push
             Authorization: Basic base64(client_id:client_secret)
  → Token service:
      1. Validate client_id:client_secret via Hydra /oauth2/token (client_credentials)
      2. Check per-action Keto permission (Registry namespace, repo name, relation)
      3. Sign RS256 JWT with allowed access list
  → Docker: retry push with Bearer JWT
  → Registry: verify JWT signature with token-service.pub.pem, allow/deny
```

## Package layout

```
cmd/server/main.go          HTTP server, routing, token handler logic
internal/config/config.go   Environment-variable configuration + RSA key loading
internal/hydra/client.go    Hydra client_credentials validation
internal/keto/client.go     Keto relation-tuple permission check
internal/token/issuer.go    RS256 JWT signing (iss, sub, aud, access claims)
internal/token/scope.go     Parse/filter Distribution scope strings
```

## Key endpoints

| Endpoint | Description |
| --- | --- |
| `GET /token` | Main token endpoint — HTTP Basic auth, scope query param |
| `GET /healthz` | Liveness/readiness probe |

## Environment variables

| Variable | Required | Default | Description |
| --- | --- | --- | --- |
| `PORT` | no | `8080` | HTTP listen port |
| `TOKEN_ISSUER` | yes | — | `iss` claim (e.g. `https://token.meddleware.co.uk`) |
| `TOKEN_SERVICE` | yes | — | `aud` claim + registry service name |
| `TOKEN_TTL` | no | `300` | Token lifetime in seconds |
| `RSA_PRIVATE_KEY_PATH` | no | `/etc/token-service/signing.key` | PEM RSA private key |
| `HYDRA_TOKEN_URL` | yes | — | Hydra public token endpoint (`POST /oauth2/token`) |
| `KETO_READ_URL` | yes | — | Keto read API base URL |
| `LOG_LEVEL` | no | `info` | `debug\|info\|warn\|error` |

## Build and run

```bash
# build binary
go build -o token-service ./cmd/server

# run locally (requires Hydra + Keto accessible)
PORT=8080 \
TOKEN_ISSUER=https://token.meddleware.co.uk \
TOKEN_SERVICE=registry.meddleware.co.uk \
RSA_PRIVATE_KEY_PATH=./signing.key \
HYDRA_TOKEN_URL=http://hydra.auth.svc.cluster.local:4444/oauth2/token \
KETO_READ_URL=http://keto.auth.svc.cluster.local:4466 \
./token-service

# build Docker image
docker build --build-arg VERSION=v0.1.0 -t quay.io/meddleware-org/registry-token-service:v0.1.0 .
```

## Testing token issuance

```bash
# Generate a test key pair
openssl genrsa -out signing.key 4096
openssl rsa -in signing.key -pubout -out signing.pub.pem

# Request a token (expects Hydra + Keto to be up)
curl -su registry-ci-push:$SECRET \
  "http://localhost:8080/token?service=registry.meddleware.co.uk&scope=repository:meddleware-org/static-server:push"
```

## Keto namespace

Permissions are checked against the `Registry` namespace with relations:
- `pushers` — may push
- `pullers` — may pull
- `admins`  — may delete

`pushers` and `pullers` are checked independently (a push grant does not imply pull).
Subject IDs are Hydra `client_id` values.

**Two-tier object check** (`checkRepoOrOrgPermission` in `cmd/server/main.go`): for a
`repository:<name>:<action>` scope the service checks the specific repo object first
(e.g. `meddleware-org/static-server`), then falls back to the org object — the segment
before the first `/` (e.g. `meddleware-org`). An org-level grant covers every current and
future repo in the org (dynamic mirroring); a repo-level grant scopes an identity to one
repo and is evaluated first. Catalog listing uses the `listers` relation on the fixed
`catalog` object.

## Invariants

- The service MUST NOT issue tokens with actions not granted by Keto, even if the client requests them.
- A client with no Keto permissions for a repo receives a token with an empty `access` list for that repo (not an error).
- The RSA private key MUST be 4096-bit minimum. Do not downgrade to ECDSA without updating the Distribution registry's `rootcertbundle` format expectations.
