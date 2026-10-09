# Changelog

All notable changes to registry-token-service are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.6] - 2026-10-09

### Security

- The release runs the full Go CI workflow (lint, vet, race tests, govulncheck, filesystem scan) and the image is scanned before it is signed (fixable CRITICAL/HIGH fail).

## [0.1.5] - 2026-10-09

### Security

- Token requests are bounded and validated: at most 16 scope entries and 4096 scope bytes (400 otherwise), and a repository name must match the Distribution grammar before it becomes a Keto object. Token responses carry `Cache-Control: no-store` and `Pragma: no-cache` (RFC 6749 §5.1). The `token issued` audit line now names the requested and the granted scopes, never a credential. The whole flow is tested against fake Hydra and Keto (intersection, org fallback, deny by default, every anchor failure is 503, no secret in the log). New key-rotation runbook (overlap, and the compromise procedure)

## [0.1.4] - 2026-10-09

### Security

- Built with Go 1.26.9: govulncheck found eleven net/http and net/textproto advisories in 1.26.7 (GO-2026-6607 to GO-2026-6617). go.mod names the toolchain and the Dockerfile builder is pinned to the same patch and checks it.

## [0.1.3] - 2026-10-03

### Changed

- `TOKEN_TTL` must be between 60 and 3600 seconds; the service refuses to start otherwise (a zero
  or negative value minted already-expired tokens; a long one outlived revoked grants).

### Added

- Unit tests for the trust boundaries: Hydra and Keto status mapping (fail closed on anything but an
  explicit answer, query values passed intact), issuer claims (RS256, RFC 7638 `kid` checked against
  the RFC's example, string `aud`, TTL span, access list), and configuration (key size floor, PKCS1
  and PKCS8, URL and TTL validation).
- CI pins `govulncheck` (v1.8.0).

## [0.1.0] - 2026-08-23

### Added
- Two-tier repository authorization (`checkRepoOrOrgPermission`): a
  `repository:<name>:<action>` scope is checked against the specific `org/repo`
  object first, then the `org` object as a fallback. An org-level Keto grant now
  covers every current and future repo in the org, so new images can be mirrored
  without adding a per-repo tuple; per-repo grants still work and take precedence.
  Includes unit tests for `orgOf` and the two-tier check (httptest-faked Keto).
- Minimum RSA key-size enforcement: the service refuses to start with a signing
  key smaller than 4096 bits.
- `-healthcheck` CLI flag and container `HEALTHCHECK` for non-Kubernetes runtimes.
- Reproducible Dockerfile (base image pinned by digest) with full OCI image labels.
- CI (golangci-lint, `go vet`, race tests, govulncheck, Trivy) and a signed,
  multi-arch, multi-registry release pipeline (cosign + SBOM + SLSA provenance).
- Operator documentation: `README.md`, `SECURITY.md`, `.env.example`, `llms.txt`.

### Fixed
- `go.sum` was missing the module hash for `github.com/golang-jwt/jwt/v5`, which
  broke reproducible/offline builds; regenerated.

### Changed
- Extracted from the vault monorepo into a standalone project under `images/`.
