# Changelog

All notable changes to registry-token-service are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.8] - 2026-10-20

### Changed

- **Image build: native cross-compile, no QEMU.** The builder stage is `FROM --platform=$BUILDPLATFORM` and
  compiles for the target with `GOOS=$TARGETOS GOARCH=$TARGETARCH` (`CGO_ENABLED=0`, `-trimpath` and the
  ldflags unchanged), so the release no longer emulates arm64 and `docker-publish.yml` no longer has the
  `docker/setup-qemu-action` step (a privileged binfmt step). `TARGETOS`/`TARGETARCH` have no default any more:
  a builder that does not set them fails the build instead of silently producing the wrong architecture.
  A build step also asserts, with `go version -m` (it reads the binary without running it), that the compiled
  binary's `GOARCH` equals the target architecture.
  Proof (rootless podman, builder pinned by digest): the new `linux/amd64` image built from the 0.1.7 sources with
  `VERSION=v0.1.7` is **byte-identical to the published 0.1.7** (`/token-service` `f41cbae0…`; the CA bundle and
  the `THIRD_PARTY_LICENSES` and `LICENSE` notices are byte-identical too). No behaviour change on amd64, the
  architecture the cluster runs.

### Fixed

- **The published `linux/arm64` image carried an x86-64 binary.** The Dockerfile declared `ARG TARGETARCH=amd64`,
  and that default overrode the platform value, so 0.1.7 and earlier compiled `GOARCH=amd64` in the arm64 build
  too: the arm64 image's `/token-service` is byte-identical to the amd64 one (`f41cbae0…`, ELF x86-64) and would
  not start on an arm64 node. With no default the arm64 image now contains an ELF aarch64 binary
  (`3272d30e…`; `go version -m`: `GOARCH=arm64`, `CGO_ENABLED=0`, `-trimpath=true`). The cluster is amd64, so
  nothing deployed was affected.

## [0.1.7] - 2026-10-18

### Fixed

- Every `scope` query parameter is evaluated, as the Docker token specification allows the parameter to be repeated (one per challenge entry, for example a push with a cross-repository mount); only the first was read before. The 16-entry and 4096-byte bounds apply to the request as a whole, over all parameters (400 beyond them), and the `access` list is still requested intersected with granted, never a passthrough.

### Security

- The image ships the licence notices of the code compiled into the binary (`/usr/share/doc/registry-token-service/THIRD_PARTY_LICENSES`: `golang-jwt/jwt` MIT, `google/uuid` BSD-3-Clause, the Go standard library) and this service's own `LICENSE`. The build fails if a module has no licence file, and CI builds the image and checks the files are present (`scripts/check-image-notices.sh`).
- `.git` is excluded from the build context.

### Changed

- `SECURITY.md` and the Keto outage runbook no longer claim SPIFFE mutual authentication on the Hydra and Keto hop (withdrawn, decision D18): the controls are the Cilium-enforced NetworkPolicy, Hydra client-secret authentication and single-node traffic. The README `cosign verify` command is pinned to the release workflow on `v*` tags.

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
