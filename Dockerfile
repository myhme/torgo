# syntax=docker/dockerfile:1.7

##############################################
# Builder stage
##############################################
ARG GO_VERSION=1.25
ARG ALPINE_VERSION=3.21
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

RUN go build \
      -trimpath \
      -ldflags="-s -w -buildid=" \
      -o "/${APP_NAME}" "./cmd/${APP_NAME}"

##############################################
# Runtime stage
##############################################
FROM alpine:${ALPINE_VERSION} AS final

ARG APP_NAME

# Install Tor and minimal dependencies
# Alpine 'tor' package creates user 'tor' (uid 100, gid 101 usually)
RUN apk add --no-cache \
      tor \
      libevent \
      libssl3 \
      libcrypto3 \
      zlib \
    && rm -rf /var/cache/apk/* /usr/share/man /tmp/*

# Copy binary
COPY --from=builder "/${APP_NAME}" "/usr/local/bin/${APP_NAME}"

# Setup permissions for the non-root user
# We create the directory structure needed for tmpfs mounts
RUN mkdir -p /var/lib/tor-temp /etc/torgo \
    && chown -R tor:tor /var/lib/tor-temp /etc/torgo /usr/local/bin/${APP_NAME}

# Default config template
COPY torrc.template /etc/tor/torrc.template
RUN chmod 644 /etc/tor/torrc.template

# Switch to non-root user for safety (though Compose should also enforce this)
USER tor

ENTRYPOINT ["/usr/local/bin/torgo"]