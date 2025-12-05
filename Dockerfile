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

# Only what we actually need: git for modules
RUN apk add --no-cache \
      git

WORKDIR /src

# Go module deps first (better layer cache)
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the source
COPY . .

# Build per-arch torgo binary (no external strip)
RUN go build \
      -trimpath \
      -mod=readonly \
      -ldflags="-s -w -buildid=" \
      -o "/${APP_NAME}" "./cmd/${APP_NAME}"

##############################################
# Final runtime stage (minimal Alpine)
##############################################
FROM alpine:${ALPINE_VERSION} AS final

ARG APP_NAME

# Tor + cryptsetup + required libs and tools
# Add util-linux (losetup) and e2fsprogs (mkfs.ext4) for LUKS-on-loop fallback.
RUN apk add --no-cache \
      tor \
      cryptsetup \
      libssl3 \
      libcrypto3 \
      libevent \
      zlib \
      util-linux \
      e2fsprogs \
    && rm -rf /var/cache/apk/* /usr/share/man /tmp/*

# Copy built binary from builder (correct arch for each image)
COPY --from=builder "/${APP_NAME}" "/usr/local/bin/${APP_NAME}"

# Tor configuration template
COPY torrc.template /etc/tor/torrc.template

# IMPORTANT:
# Do NOT drop to the tor user here – we want root inside container
# so secmem can tweak /proc/self/coredump_filter and similar.
# (Compose will still keep the container itself sandboxed.)
# USER 106:112    # ← removed on purpose

ENTRYPOINT ["/usr/local/bin/torgo"]
