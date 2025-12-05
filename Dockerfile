# syntax=docker/dockerfile:1.7

##############################################
# Global build arguments
##############################################
ARG GO_VERSION=1.25
ARG ALPINE_VERSION=3.22
ARG APP_NAME=torgo

##############################################
# Builder stage (builds per-architecture)
##############################################
FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-alpine AS builder

ARG APP_NAME
ARG TARGETOS
ARG TARGETARCH

# Ensure Go builds correct architecture
ENV CGO_ENABLED=1 \
    GOOS=${TARGETOS} \
    GOARCH=${TARGETARCH} \
    GOMODCACHE=/tmp/go-cache

# Minimal build deps
RUN apk add --no-cache \
      git \
      gcc \
      musl-dev \
      build-base

WORKDIR /src

# Modules first (cache-friendly)
COPY go.mod go.sum ./
RUN go mod download

# Copy full source
COPY . .

# Build statically-linked per-arch binary
RUN go build \
      -trimpath \
      -mod=readonly \
      -ldflags="-s -w -extldflags=-static -buildid=" \
      -o "/${APP_NAME}" "./cmd/${APP_NAME}" \
    && strip --strip-all "/${APP_NAME}"

##############################################
# Final runtime stage (minimal Alpine)
##############################################
FROM alpine:${ALPINE_VERSION} AS final

ARG APP_NAME

# Tor + cryptsetup + required libs
RUN apk add --no-cache \
      tor \
      cryptsetup \
      libssl3 \
      libcrypto3 \
      libevent \
      zlib \
    && rm -rf /var/cache/apk/* /usr/share/man /tmp/*

# Install built binary
COPY --from=builder "/${APP_NAME}" "/usr/local/bin/${APP_NAME}"

# Tor template (must exist in repo root)
COPY torrc.template /etc/tor/torrc.template

# Optional hardened seccomp profile
# COPY seccomp.json /etc/torgo/seccomp.json

# Run as Alpine `tor` user (uid=106, gid=112)
USER 106:112

ENTRYPOINT ["/usr/local/bin/torgo"]
