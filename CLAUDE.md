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

## Code style

- Match the pattern in `images/static-server/main.go`: no global state, structured
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
