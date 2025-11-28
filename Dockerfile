# syntax=docker/dockerfile:1.7

# Optimized multi-stage Dockerfile for torgo (Go + Tor + LUKS RAM)
# - Builder: golang:alpine
# - Final:   alpine (tor + cryptsetup present at runtime)
# - No libdevmapper / luksmeta (they don't exist on Alpine)

ARG GO_VERSION=1.25
ARG ALPINE_VERSION=3.22
ARG APP_NAME=torgo

# -----------------------------
# 1) Builder stage
# -----------------------------
FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-alpine AS builder

RUN apk add --no-cache \
      git \
      gcc \
      musl-dev \
      build-base

WORKDIR /src

# Go modules first (cacheable)
COPY go.mod go.sum ./
RUN go mod download

# Rest of the source
COPY . .

# Build hardened binary
RUN CGO_ENABLED=1 go build \
      -trimpath \
      -mod=readonly \
      -ldflags="-s -w -extldflags=-static -buildid=" \
      -o /${APP_NAME} ./cmd/${APP_NAME} \
    && strip --strip-all /${APP_NAME} || true

# -----------------------------
# 2) Final stage (Alpine)
# -----------------------------
FROM alpine:${ALPINE_VERSION} AS final

# Tor + cryptsetup + runtime libs
RUN apk add --no-cache \
      tor \
      cryptsetup \
      libssl3 \
      libcrypto3 \
      libevent \
      zlib \
    && rm -rf /var/cache/apk/* /usr/share/man /tmp/*

# Copy binary + torrc template
ARG APP_NAME
COPY --from=builder /${APP_NAME} /usr/local/bin/${APP_NAME}
COPY torrc.template /etc/tor/torrc.template

# torgo runs as tor user (106:112) inside the container
USER 106:112

ENTRYPOINT ["/usr/local/bin/torgo"]
