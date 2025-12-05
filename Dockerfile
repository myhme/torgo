# syntax=docker/dockerfile:1.7

##############################################
# Global build arguments
##############################################
ARG GO_VERSION=1.25
ARG ALPINE_VERSION=3.22
ARG APP_NAME=torgo

##############################################
# Builder stage (multi-arch, pure Go – no cgo)
##############################################
FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-alpine AS builder

ARG APP_NAME
ARG TARGETOS
ARG TARGETARCH

# Use Go's built-in cross-compiler (no cgo → no external GCC/asm)
ENV CGO_ENABLED=0 \
    GOOS=${TARGETOS} \
    GOARCH=${TARGETARCH} \
    GOMODCACHE=/tmp/go-cache

# Only what we actually need: git for modules, binutils for strip
RUN apk add --no-cache \
      git \
      binutils

WORKDIR /src

# Go module deps first (better layer cache)
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the source
COPY . .

# Build per-arch torgo binary
RUN go build \
      -trimpath \
      -mod=readonly \
      -ldflags="-s -w -buildid=" \
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

# Copy built binary from builder (correct arch for each image)
COPY --from=builder "/${APP_NAME}" "/usr/local/bin/${APP_NAME}"

# Tor configuration template
COPY torrc.template /etc/tor/torrc.template

# Optional hardened seccomp profile (if you mount it via volume, you can skip)
# COPY seccomp.json /etc/torgo/seccomp.json

# Run as Alpine tor user (uid=106, gid=112)
USER 106:112

ENTRYPOINT ["/usr/local/bin/torgo"]
