# syntax=docker/dockerfile:1.7

##############################################
# Builder stage (Hardened)
##############################################
ARG GO_VERSION=1.25
ARG ALPINE_VERSION=3.23
ARG APP_NAME=torgo

FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-alpine AS builder

ARG APP_NAME
ARG TARGETOS
ARG TARGETARCH

ENV CGO_ENABLED=0 \
    GOOS=${TARGETOS} \
    GOARCH=${TARGETARCH}

RUN apk add --no-cache git

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# SECURITY HARDENING: -buildmode=pie
# This enables Position Independent Executable (ASLR) for the Go binary.
RUN go build \
      -trimpath \
      -buildmode=pie \
      -ldflags="-s -w -buildid=" \
      -o "/${APP_NAME}" "./cmd/${APP_NAME}"

##############################################
# Runtime stage (Zero Trust)
##############################################
FROM alpine:${ALPINE_VERSION} AS final

ARG APP_NAME

# 1. Install Tor + Obfuscation Tools
# We add 'obfs4proxy' so you can use Bridges if you ever need to hide from deep inspection.
# 'libcap' is added in case we ever need to bind low ports (optional but good practice).
RUN apk add --no-cache \
      tor \
      obfs4proxy \
      libcap \
    && rm -rf /var/cache/apk/* /usr/share/man /tmp/*

# 2. Copy the Hardened Binary
COPY --from=builder "/${APP_NAME}" "/usr/local/bin/${APP_NAME}"

# 3. Setup Zero-Trust Environment
# We create a specific directory for our ephemeral Tor instances.
# We ensure the 'tor' user (uid 100) owns these paths.
RUN mkdir -p /var/lib/tor-temp /etc/torgo \
    && chown -R tor:tor /var/lib/tor-temp /etc/torgo /usr/local/bin/${APP_NAME} \
    && chmod 700 /var/lib/tor-temp

# 4. Install Config Template
COPY torrc.template /etc/tor/torrc.template
RUN chown tor:tor /etc/tor/torrc.template && chmod 644 /etc/tor/torrc.template

# 5. Security: Drop to non-root user
USER tor

# 6. Healthcheck (Uses your new --selfcheck flag)
# Checks every 30s, fails if Tor isn't ready within 10s of check start.
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/torgo", "--selfcheck"]

ENTRYPOINT ["/usr/local/bin/torgo"]