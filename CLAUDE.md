# CLAUDE.md — registry-token-service

## Identity

This is a security-critical service. It is the authentication and authorization gateway
for all container image pushes and pulls. Mistakes here either lock out CI or grant
unauthorized registry access.

## Architectural invariants (do not violate)

1. **Keto is the source of truth for permissions.** Never skip the Keto check, add
   shortcut allowlists, or hard-code client IDs that bypass the check. If Keto is
   unreachable, return 503 — do not fail open. Repository authorization is two-tier
   (`checkRepoOrOrgPermission`): the specific `org/repo` object is checked first, then
   the `org` object as a fallback. Both are real Keto checks — the org fallback is a
   broad grant, not a bypass; keep it that way.

2. **Hydra validates credentials — the token service does not.** Never implement
   client secret verification locally. Always delegate to Hydra's token endpoint.
   If Hydra is unreachable, return 503 — do not fail open.

3. **Token TTL is non-negotiable.** Respect `TOKEN_TTL`; do not issue tokens
   with longer lifetimes to "help" long-running clients. Docker clients re-fetch
   tokens when they expire.

4. **Only RS256.** The Distribution registry validates JWTs using the RSA public key
   in `rootcertbundle`. Do not switch to HMAC or ECDSA without updating the registry
   config and re-deploying.

5. **The `access` list is a filter, not a passthrough.** Parse the requested scope,
   then intersect with Keto-granted actions. A client requesting `push` that only has
   `pull` in Keto receives `["pull"]` in the token — it does not get an error and it
   does not get `push`.

## Auth flow

The service implements the [Distribution registry token auth specification](https://distribution.github.io/distribution/spec/auth/token/).
The registry answers an unauthenticated push or pull with `401 WWW-Authenticate: Bearer realm=".../token", service=...`.

```text
Docker: GET /token?service=...&scope=repository:myorg/image:push   (Authorization: Basic client_id:client_secret)
Token service:
  1. validate client_id:client_secret via Hydra /oauth2/token (client_credentials)
  2. check the per-action Keto permission (Registry namespace, repo name, relation)
  3. sign an RS256 JWT with the allowed access list (iss, sub, aud, access)
Docker: retry with the Bearer JWT; the registry verifies the signature with the public key and allows or denies.
```

Endpoints: `GET /token` (HTTP Basic, `scope` query parameter) and `GET /healthz` (liveness/readiness).

## Keto namespace

Permissions are checked against the `Registry` namespace. Relations: `pushers` (may push), `pullers` (may pull), `admins` (may
delete), `listers` (catalog listing, on the fixed `catalog` object). `pushers` and `pullers` are checked independently (a push grant
does not imply pull). Subject IDs are Hydra `client_id` values.

Two-tier object check (`checkRepoOrOrgPermission` in `cmd/server/main.go`): for a `repository:<name>:<action>` scope the service
checks the specific repo object first (e.g. `meddleware-org/static-server`), then the org object, the segment before the first `/`
(e.g. `meddleware-org`). An org-level grant covers every current and future repo in the org (dynamic mirroring); a repo-level grant
scopes an identity to one repo.

A client with no Keto permissions for a repo receives a token with an empty `access` list for that repo (not an error).

## Layout, configuration and commands

```text
cmd/server/main.go          HTTP server, routing, token handler logic
internal/config/config.go   environment configuration + RSA key loading (key must be at least 4096-bit)
internal/hydra/client.go    Hydra client_credentials validation
internal/keto/client.go     Keto relation-tuple permission check
internal/token/issuer.go    RS256 JWT signing
internal/token/scope.go     parse/filter Distribution scope strings (all repeated `scope` parameters, bounded as a whole)
scripts/                    third-party-licenses.sh (image notices), check-image-notices.sh (CI)
```

| Variable | Required | Default | Description |
| --- | --- | --- | --- |
| `PORT` | no | `8080` | HTTP listen port |
| `TOKEN_ISSUER` | yes | none | `iss` claim (e.g. `https://token.meddleware.co.uk`) |
| `TOKEN_SERVICE` | yes | none | `aud` claim + registry service name |
| `TOKEN_TTL` | no | `300` | Token lifetime in seconds (bounded; out-of-range values are refused at startup) |
| `RSA_PRIVATE_KEY_PATH` | no | `/etc/token-service/signing.key` | PEM RSA private key |
| `HYDRA_TOKEN_URL` | yes | none | Hydra public token endpoint (`POST /oauth2/token`) |
| `KETO_READ_URL` | yes | none | Keto read API base URL |
| `LOG_LEVEL` | no | `info` | `debug\|info\|warn\|error` |

```bash
go build -o token-service ./cmd/server
docker build --build-arg VERSION=v0.1.0 -t quay.io/meddleware-org/registry-token-service:v0.1.0 .
# test keys and a token request (needs Hydra + Keto up)
openssl genrsa -out signing.key 4096 && openssl rsa -in signing.key -pubout -out signing.pub.pem
curl -su registry-ci-push:$SECRET \
  "http://localhost:8080/token?service=registry.meddleware.co.uk&scope=repository:meddleware-org/static-server:push"
```

## Code style

- Match the sibling `registry-auth-proxy`: no global state, structured
  logging via `log/slog`, graceful shutdown, `envOr` for optional config.
- Error paths return immediately; do not swallow errors silently.
- Keep `cmd/server/main.go` thin — routing and handler wiring only. Business logic
  belongs in `internal/`.

## What not to do

- Do not add an in-memory client credential cache. Hydra already handles this efficiently.
- Do not add token refresh logic. Clients re-request tokens; the service is stateless.
- Do not add endpoints beyond `/token` and `/healthz`. JWKS, discovery, and consent
  flows belong in Hydra/Kratos, not here.
- Do not parse or validate the JWT after signing. Sign and return; the registry validates.
