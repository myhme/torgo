# syntax=docker/dockerfile:1.7

##############################################
# Builder stage (Hardened + Static PIE)
##############################################
ARG GO_VERSION=1.25
ARG ALPINE_VERSION=3.23
ARG APP_NAME=torgo

# REMOVE --platform=$BUILDPLATFORM to ensure we run native gcc on each arch (via QEMU)
FROM golang:${GO_VERSION}-alpine AS builder

ARG APP_NAME
ARG TARGETOS
ARG TARGETARCH

# We set CGO_ENABLED=1 explicitly for the build to allow external linking.
# We will use flags to force it to be static anyway.
ENV GOOS=${TARGETOS} \
    GOARCH=${TARGETARCH}

# Install build tools required for static linking with PIE
RUN apk add --no-cache git gcc musl-dev

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# SECURITY HARDENING: Static PIE Build
# 1. CGO_ENABLED=1: Required for -linkmode external
# 2. -linkmode external: Uses GCC to handle ASLR/PIE
# 3. -extldflags "-static": Forces GCC to bundle everything statically (no dynamic libs)
RUN CGO_ENABLED=1 go build \
      -trimpath \
      -buildmode=pie \
      -ldflags='-s -w -linkmode external -extldflags "-static" -buildid=' \
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

# 2. Copy the Hardened Static Binary
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