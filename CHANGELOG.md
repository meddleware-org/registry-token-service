# Changelog

All notable changes to registry-token-service are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
