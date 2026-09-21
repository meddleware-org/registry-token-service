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
6. **`service` is validated.** The request's `service` parameter must equal `TOKEN_SERVICE`
   (the JWT `aud`); a mismatch is rejected with `400` rather than minting a token for the
   wrong audience.

## Transport to Hydra and Keto

The service calls Hydra (`HYDRA_TOKEN_URL`) and Keto (`KETO_READ_URL`) over **in-cluster HTTP**
(ClusterIP services in the `auth` namespace, e.g. `http://hydra.auth.svc.cluster.local:4444`).
`config.Load` validates both are well-formed `http(s)` URLs with a host and fails fast otherwise.
Two controls bound this plaintext hop:

- **NetworkPolicy.** The `auth` namespace runs default-deny ingress; only the `token-service` pod
  (in the `registry` namespace) may reach Hydra `:4444` and Keto `:4466`
  (`k8s/base/auth/networkpolicy.yaml`). No other pod can reach the auth services on those ports.
- **Transport encryption is a platform concern.** In-cluster pod-to-pod traffic is encrypted at the
  CNI layer (Cilium WireGuard transparent encryption), with SPIFFE-based mutual authentication on the
  token-service → Hydra/Keto path. Application-level mTLS is intentionally **not** implemented here;
  the client-credentials (Basic auth to Hydra) and Keto queries rely on the platform mesh for
  confidentiality and peer authentication.

## Signing-key custody

The RS256 JWT signing key is the single highest-value secret this service holds: whoever holds the
private key can mint tokens the registry will trust. Custody controls (the "proof" record for an
audit):

- **Never in the image or env.** The key is read from a file at `RSA_PRIVATE_KEY_PATH`
  (default `/etc/token-service/signing.key`); it is never baked into the image, passed as an env
  var, or logged.
- **Kubernetes Secret, tight mount.** The file is projected from a Kubernetes `Secret`
  (`token-service-keys`, key `signing.key`) mounted **read-only at mode `0440`**. The pod runs as
  `runAsUser: 65534` with `fsGroup: 65534`, so only the non-root service account can read it; the
  image itself sets `USER 65534:65534`.
- **Strength enforced at startup.** `config.Load` rejects any key `< 4096-bit` (`minRSABits`),
  failing closed rather than signing with a weak key.
- **Rotation.** Replace the `Secret` and restart the Deployment; the registry's `rootcertbundle`
  public key must be updated in lock-step (both trust the same key pair). Because tokens are
  short-lived (`TOKEN_TTL`), a rotation drains within one TTL window.
- **Optional hardening (infra-dependent, not in this repo):** encrypt the Secret at rest with SOPS
  or a KMS-backed sealed-secret. The mount/permission model above is unchanged either way.

## Runbooks

- [Keto outage](docs/runbooks/keto-outage.md) — what happens when the Keto authorization service is
  unreachable (registry-wide push/pull halt, fail-closed by design) and how to detect, mitigate, and
  recover.

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
