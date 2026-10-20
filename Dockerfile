# ── Build stage ───────────────────────────────────────────────────────────────
# Base pinned by digest for reproducible builds; the tag is kept for readability.
# To bump: docker buildx imagetools inspect golang:<go.mod toolchain>-bookworm --format '{{.Manifest.Digest}}'
# The builder runs on the BUILD host's architecture and cross-compiles (pure Go, CGO off), so no arm64 step runs
# under emulation. Nothing the builder executes is target-specific.
FROM --platform=$BUILDPLATFORM golang:1.26.9-bookworm@sha256:d9c68c2c51161e12fd77e4c6320687c9cd86e1af1e3ad6e6cd63ff970641453c AS builder

ARG VERSION=dev
# Set by BuildKit/podman from --platform; a plain builder that leaves them empty fails the guard below.
ARG TARGETOS
ARG TARGETARCH

WORKDIR /src

COPY go.mod go.sum* ./

# The binary is built with the toolchain go.mod names, which is the one CI's govulncheck checks: a builder
# image left on another patch fails here instead of shipping an unchecked stdlib.
RUN grep -q "^toolchain $(go env GOVERSION)$" go.mod || { echo "builder $(go env GOVERSION) != go.mod toolchain"; exit 1; }
RUN go mod download

COPY . .

# Fully static binary: no libc, no CGO — runs in scratch.
RUN : "${TARGETOS:?build with BuildKit or podman (sets TARGETOS)}" "${TARGETARCH:?build with BuildKit or podman (sets TARGETARCH)}" \
    && CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build \
    -trimpath \
    -ldflags="-s -w -X main.version=${VERSION}" \
    -o /out/token-service \
    ./cmd/server

# The compiled binary must be the target architecture (go version -m reads it without running it): an
# image of one architecture holding another's binary would pass every other check and fail only on a node.
RUN [ "$(go version -m /out/token-service | sed -n 's/^[[:space:]]*build[[:space:]]*GOARCH=//p')" = "${TARGETARCH}" ] \
    || { echo "/out/token-service is not built for ${TARGETARCH}"; exit 1; }

# Licence notices of what the binary contains (the Go modules and the standard library); the build fails if a
# module has no licence file. The project's own LICENSE is copied beside them.
RUN mkdir -p /out/doc && sh scripts/third-party-licenses.sh /out/doc/THIRD_PARTY_LICENSES && cp LICENSE /out/doc/LICENSE

# ── Runtime stage ─────────────────────────────────────────────────────────────
# scratch: zero OS footprint. The binary is fully self-contained.
FROM scratch

# Re-declare ARGs after FROM so they are visible for the labels below. Defaults are
# the upstream project coordinates; forks override via --build-arg.
ARG VERSION=dev
ARG VENDOR="Meddleware"
ARG DESCRIPTION="Distribution registry JWT token service backed by Ory Hydra + Keto."
ARG SOURCE_URL="https://github.com/meddleware-org/registry-token-service"
ARG DOCUMENTATION_URL="https://github.com/meddleware-org/registry-token-service#readme"
ARG IMAGE_URL="https://quay.io/meddleware-org/registry-token-service"

LABEL org.opencontainers.image.title="registry-token-service" \
      org.opencontainers.image.description="${DESCRIPTION}" \
      org.opencontainers.image.url="${IMAGE_URL}" \
      org.opencontainers.image.source="${SOURCE_URL}" \
      org.opencontainers.image.documentation="${DOCUMENTATION_URL}" \
      org.opencontainers.image.vendor="${VENDOR}" \
      org.opencontainers.image.licenses="0BSD" \
      org.opencontainers.image.version="${VERSION}"

COPY --from=builder /out/token-service /token-service
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
# MIT (golang-jwt/jwt), BSD-3-Clause (google/uuid, Go) notices and the 0BSD licence of this service.
COPY --from=builder /out/doc/ /usr/share/doc/registry-token-service/

USER 65534:65534

EXPOSE 8080

ENV PORT=8080

# Healthcheck for non-Kubernetes runtimes (Docker, Compose). The binary handles
# -healthcheck by dialling localhost/healthz and exiting 0/1. Kubernetes uses its
# own readiness/liveness probes and ignores this instruction.
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["/token-service", "-healthcheck"]

ENTRYPOINT ["/token-service"]
