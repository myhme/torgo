# syntax=docker/dockerfile:1.7

##############################################
# Builder stage (Standard Static)
##############################################
ARG GO_VERSION=1.25
ARG ALPINE_VERSION=3.23
ARG APP_NAME=torgo

# RESTORED: --platform=$BUILDPLATFORM
# This makes the build FAST (uses your native CPU) and RELIABLE.
FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-alpine AS builder

ARG APP_NAME
ARG TARGETOS
ARG TARGETARCH

# CRITICAL: Disable CGO.
# This ensures a 100% static binary that runs on any Linux (Alpine, Scratch, Debian).
ENV CGO_ENABLED=0 \
    GOOS=${TARGETOS} \
    GOARCH=${TARGETARCH}

# Removed 'gcc' and 'musl-dev' since we don't need external linking anymore.
RUN apk add --no-cache git

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# SECURITY HARDENING: Standard Static Build
# -trimpath: Removes file system paths (privacy).
# -ldflags "-s -w": Strips debug symbols (smaller, harder to reverse).
# REMOVED: -buildmode=pie (This was the cause of the "no such file" and build errors)
RUN go build \
      -trimpath \
      -ldflags="-s -w -buildid=" \
      -o "/${APP_NAME}" "./cmd/${APP_NAME}"

##############################################
# Runtime stage (Zero Trust)
##############################################
FROM alpine:${ALPINE_VERSION} AS final

ARG APP_NAME

# 1. Install Tor + Obfuscation Tools
RUN apk add --no-cache \
      tor \
      obfs4proxy \
      libcap \
    && rm -rf /var/cache/apk/* /usr/share/man /tmp/*

# 2. Copy the Static Binary
COPY --from=builder "/${APP_NAME}" "/usr/local/bin/${APP_NAME}"

# 3. Setup Zero-Trust Environment
RUN mkdir -p /var/lib/tor-temp /etc/torgo \
    && chown -R tor:tor /var/lib/tor-temp /etc/torgo /usr/local/bin/${APP_NAME} \
    && chmod 700 /var/lib/tor-temp

# 4. Install Config Template
COPY torrc.template /etc/tor/torrc.template
RUN chown tor:tor /etc/tor/torrc.template && chmod 644 /etc/tor/torrc.template

# 5. Security: Drop to non-root user
USER tor

# 6. Healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/torgo", "--selfcheck"]

ENTRYPOINT ["/usr/local/bin/torgo"]