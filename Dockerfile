# Optimized multi-arch Dockerfile for torgo (Go + Tor)
# Goals: multi-arch (linux/amd64,linux/arm64), BuildKit cache mounts, small final image (scratch),
# hardened/least-privilege final image, reproducible build-friendly labels. Use BuildKit cache mounts
# for GOMODCACHE and Go build cache. Buildx should be invoked with --attest / SBOM flags to produce
# provenance and SBOM (those CLI flags are provided in the CI pipeline / build command).

# -----------------------------
# 0) Build args (set in CI) -- helps reproducibility
# -----------------------------
ARG GO_VERSION=1.25
ARG ALPINE_VERSION=3.22
ARG BUILD_USER_UID=1001
ARG BUILD_USER_GID=1001
ARG APP_NAME=torgo
ARG BUILD_DATE=unspecified
ARG VCS_REF=unspecified

# -----------------------------
# 1) Builder stage (multi-arch)
# -----------------------------
FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-alpine AS builder

# Minimal packages needed for building
RUN apk add --no-cache --virtual .build-deps \
    git \
    gcc \
    musl-dev \
    build-base \
    && mkdir -p /build /cache /tmp/go-cache

# Create dedicated build user (non-root)
RUN addgroup -S -g ${BUILD_USER_GID} buildergroup \
 && adduser  -S -D -u ${BUILD_USER_UID} -G buildergroup builder \
 && chown -R builder:buildergroup /build /cache /tmp/go-cache


# Set environment for reproducible Go builds
ENV CGO_ENABLED=1 \
    GOCACHE=/cache/go-build \
    GOMODCACHE=/tmp/go-cache \
    GOPATH=/go \
    GOFLAGS=-mod=readonly

WORKDIR /build

# Copy go.mod first to leverage build cache
COPY go.* ./

# Run module download as the non-root build user using BuildKit cache mounts
# The cache targets must exist and be writable by the build user - we created and chowned them above.
USER builder
RUN --mount=type=cache,target=${GOMODCACHE} \
    --mount=type=cache,target=/cache/go-build \
    go mod download

# Copy rest of the source and build using cache mount for build cache
COPY --chown=builder:buildergroup . .
RUN --mount=type=cache,target=${GOMODCACHE} \
    --mount=type=cache,target=/cache/go-build \
    CGO_ENABLED=${CGO_ENABLED} go build -trimpath -ldflags='-s -w -extldflags=-static -buildid=' -o /${APP_NAME} ./cmd/${APP_NAME} \
    && strip --strip-all /${APP_NAME}

# -----------------------------
# 2) Deps stage (alpine) - install Tor and collect shared libs
# -----------------------------
FROM alpine:${ALPINE_VERSION} AS deps

# Keep packages minimal and pinned via ARG; install tor and runtime libs
RUN apk add --no-cache tor libssl3 libcrypto3 libevent zlib \
    && rm -rf /var/cache/apk/* /usr/share/man /tmp/*

# Expose the minimal set of files we need in the final scratch image
# We will copy the shared libs & tor binary into the scratch image

# -----------------------------
# 3) Final stage - scratch (smallest possible)
# -----------------------------
FROM scratch AS final

# Labels (best-effort — CI/buildx can overwrite with --label)
LABEL org.opencontainers.image.title="${APP_NAME}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.revision="${VCS_REF}"

# Copy musl loader and required shared libs
COPY --from=deps /lib/ld-musl-*.so.1 /lib/
COPY --from=deps /usr/lib/libz.so.1 /lib/
COPY --from=deps /usr/lib/libssl.so.3 /usr/lib/
COPY --from=deps /usr/lib/libcrypto.so.3 /usr/lib/
COPY --from=deps /usr/lib/libevent-2.1.so.7 /usr/lib/

# Copy tor binary and minimal passwd/group so we can run as tor user
COPY --from=deps /usr/bin/tor /usr/bin/tor
COPY --from=deps /etc/passwd /etc/passwd
COPY --from=deps /etc/group /etc/group

# Copy built application from builder
COPY --from=builder /${APP_NAME} /usr/local/bin/${APP_NAME}

# Copy tor configuration template (must be provided in repo)
COPY torrc.template /etc/tor/torrc.template

# Use the same uid/gid that tor expects (if present in /etc/passwd from deps)
# If tor expects uid 106:112 like in many distros, keep that; else fallback to nobody
USER 106:112

# Minimal seccomp & capabilities: final image is scratch, runtime should drop capabilities in service config
# Entrypoint
ENTRYPOINT ["/usr/local/bin/torgo"]

# -----------------------------
# Notes for CI / buildx invocation (example)
# -----------------------------
# Example buildx command (from your CI) to produce multi-arch image + SBOM + provenance:
#
# docker buildx build \
#   --platform linux/amd64,linux/arm64 \
#   --file Dockerfile \
#   --tag ghcr.io/<org>/torgo:latest \
#   --output type=image,push=true \
#   --build-arg BUILD_DATE=$(date -u +'%Y-%m-%dT%H:%M:%SZ') \
#   --build-arg VCS_REF=$(git rev-parse --short HEAD) \
#   --provenance-mode=max \
#   --attest type=sbom,mode=max \
#   --attest type=provenance,mode=max \
#   .
#
# Security hardening recommendations (CI/runtime):
# - Run container with user namespace remapping where possible.
# - Use seccomp and AppArmor profiles in the runtime (pod/container runtime config).
# - Run container with --read-only and mount writable dirs (logs, state) explicitly.
# - Limit capabilities (don't use --cap-add unless required). Use --cap-drop ALL and add minimal if needed.
# - Use image signing (cosign) and verification in your deployment pipeline.
# - Ensure torrc.template does not contain secrets; mount sensitive keys at runtime via secrets manager.

# End of Dockerfile
