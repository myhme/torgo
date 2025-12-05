# syntax=docker/dockerfile:1.7

# -------- Global build args (visible to all stages) --------
ARG GO_VERSION=1.25
ARG ALPINE_VERSION=3.22
ARG APP_NAME=torgo

# -------- Builder stage --------
FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-alpine AS builder

# Re-declare ARGs in this stage so they’re usable
ARG APP_NAME

# Minimal build deps
RUN apk add --no-cache \
      git \
      gcc \
      musl-dev \
      build-base

WORKDIR /src

# Go module deps first (for caching)
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the source
COPY . .

# Build static-ish torgo binary
# IMPORTANT: APP_NAME is now guaranteed to be set ("torgo" by default)
RUN CGO_ENABLED=1 go build \
      -trimpath \
      -mod=readonly \
      -ldflags="-s -w -extldflags=-static -buildid=" \
      -o "/${APP_NAME}" "./cmd/${APP_NAME}" \
    && strip --strip-all "/${APP_NAME}"

# If build fails (e.g. wrong path), the image build FAILS.
# No more "|| true" masking real errors.

# -------- Final runtime stage --------
FROM alpine:${ALPINE_VERSION} AS final

ARG APP_NAME

# Tor + cryptsetup + minimal libs
RUN apk add --no-cache \
      tor \
      cryptsetup \
      libssl3 \
      libcrypto3 \
      libevent \
      zlib \
    && rm -rf /var/cache/apk/* /usr/share/man /tmp/*

# Copy the built binary from builder
COPY --from=builder "/${APP_NAME}" "/usr/local/bin/${APP_NAME}"

# Tor configuration template (must be in repo root)
COPY torrc.template /etc/tor/torrc.template

# (Optional) copy seccomp profile, etc.
# COPY seccomp.json /etc/torgo/seccomp.json

# Run as tor user (uid/gid from Alpine tor package)
USER 106:112

ENTRYPOINT ["/usr/local/bin/torgo"]
