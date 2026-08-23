# Security Policy

## Scope

This policy covers security issues in:

- The Go binary (`cmd/server`, `internal/*`) — authentication/authorization bypass,
  token forgery, scope escalation, header/JWT injection, or similar
- The container image build (`Dockerfile`) — issues arising from the base image or
  build configuration
- The published images at `quay.io/meddleware-org/registry-token-service` and
  `docker.io/meddleware/registry-token-service`

It does not cover:

- The security of Ory Hydra or Ory Keto themselves (report those upstream to Ory)
- Vulnerabilities in the Go standard library (report to the [Go security team](https://go.dev/security))
- Misconfiguration of the operator's registry, Kubernetes, or Docker deployment
  (e.g. an under-sized signing key — the service refuses keys below 4096-bit, but
  the operator is responsible for key generation and storage)

## Security model (invariants)

These invariants are load-bearing. A report demonstrating that any is violated is
in scope and treated as high severity:

1. **Keto is the source of truth for permissions.** The service never bypasses the
   Keto check. If Keto is unreachable it returns `503` — it never fails open.
2. **Hydra validates credentials; the service never does.** Client secrets are
   validated by Hydra's token endpoint only. If Hydra is unreachable it returns `503`.
3. **RS256 only, ≥ 4096-bit key.** The service refuses to start with a weaker key.
4. **The `access` list is a filter, not a passthrough.** Requested scope is
   intersected with Keto-granted actions; a client never receives more than it is
   granted.
5. **Stateless, TTL-bound tokens.** No token caching or refresh; `TOKEN_TTL` is honored.

## Supported versions

Only the latest published image tag receives security fixes.

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Report vulnerabilities by emailing **<security@meddleware.co.uk>**. Include:

- A description of the vulnerability and its impact
- Steps to reproduce or a proof-of-concept (if available)
- The image tag or commit SHA you tested against

You will receive an acknowledgement within **3 business days** and a resolution plan
within **14 days** for confirmed issues. Critical issues (CVSS ≥ 9.0) are prioritised
for same-day acknowledgement.

## Disclosure

Once a fix is released, a security advisory will be published on the GitHub
repository. Reporters may be credited by name unless they prefer to remain anonymous.
