# Optimized multi-arch Dockerfile for torgo (Go + Tor)
# Goals: multi-arch (linux/amd64,linux/arm64), BuildKit cache mounts, small final image (scratch),
# hardened/least-privilege final image. Git-based metadata (dates, commit, refs) is handled by CI
# via docker/metadata-action, not inside the Dockerfile.

# -----------------------------
# 0) Build args (global defaults)
# -----------------------------
ARG GO_VERSION=1.25
ARG ALPINE_VERSION=3.22
ARG BUILD_USER_UID=1001
ARG BUILD_USER_GID=1001
ARG APP_NAME=torgo

# -----------------------------
# 1) Builder stage (multi-arch)
# -----------------------------
FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-alpine AS builder

# Re-declare ARGs so they are visible in this stage
ARG BUILD_USER_UID
ARG BUILD_USER_GID
ARG APP_NAME

# Minimal packages needed for building
RUN apk add --no-cache --virtual .build-deps \
    git \
    gcc \
    musl-dev \
    build-base \
    && mkdir -p /build /cache /tmp/go-cache

# Create dedicated build user (non-root)
RUN addgroup -S -g "${BUILD_USER_GID}" buildergroup \
 && adduser  -S -D -u "${BUILD_USER_UID}" -G buildergroup builder \
 && chown -R builder:buildergroup /build /cache /tmp/go-cache

# Set environment for reproducible Go builds (cache paths, readonly modules)
ENV CGO_ENABLED=1 \
    GOCACHE=/cache/go-build \
    GOMODCACHE=/tmp/go-cache \
    GOPATH=/go \
    GOFLAGS=-mod=readonly

WORKDIR /build

# Copy go.mod first to leverage build cache
COPY go.* ./

# Run module download as the non-root build user using BuildKit cache mounts
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

# Re-declare version ARG so it’s visible here (optional but explicit)
ARG ALPINE_VERSION

# Keep packages minimal and pinned via ARG; install tor and runtime libs
RUN apk add --no-cache tor libssl3 libcrypto3 libevent zlib \
    && rm -rf /var/cache/apk/* /usr/share/man /tmp/*

# -----------------------------
# 3) Final stage - scratch (smallest possible)
# -----------------------------
FROM scratch AS final

# Re-declare APP_NAME so COPY uses the correct binary name
ARG APP_NAME

# Basic static label; git-derived labels come from CI (docker/metadata-action)
LABEL org.opencontainers.image.title="torgo"

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

# Use the same uid/gid that Tor expects (if present in /etc/passwd from deps)
USER 106:112

# Entrypoint
ENTRYPOINT ["/usr/local/bin/torgo"]

# End of Dockerfile
