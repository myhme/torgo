# --- STAGE 0: BUILDER (Go application) ---
FROM golang:1.25-alpine AS builder
# Install build dependencies for Go CGO (musl-dev for static linking)
USER nobody
RUN apk add --no-cache --virtual .build-deps git gcc musl-dev
WORKDIR /src
COPY go.* ./
# Download Go modules
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
# Build the torgo binary. Note: The Go binary itself is static, but needs CGO.
# We build against musl which requires the musl dynamic linker to be copied later.
RUN CGO_ENABLED=1 go build -trimpath -ldflags="-s -w -extldflags=-static -buildid=" -o /torgo ./cmd/torgo \
    && strip --strip-all /torgo

# --- STAGE 1: TOR DEPENDENCIES (Dedicated to install 'tor' and dependencies) ---
FROM alpine:latest AS deps
# Install tor and its dependencies
RUN apk add --no-cache tor \
    # Remove documentation and unnecessary files to keep this stage small
    && rm -rf /var/cache/apk/* /usr/share/man /tmp/*

# --- STAGE 2: FINAL DISTROLESS IMAGE ---
FROM scratch
# ----------------------------------------------------------------------
# Copy essential files from the 'deps' stage (which has 'tor' installed)
# We copy the specific files required for the Tor binary to run on scratch.
# This approach is less brittle than attempting ldd across stages.
# ----------------------------------------------------------------------

# Dynamic Linker (ld-musl-*) - required for the Go CGO binary and Tor
# Note: For multi-arch, BuildKit picks the right one if available. We copy both common names.
COPY --from=deps /lib/ld-musl-x86_64.so.1 /lib/
COPY --from=deps /lib/ld-musl-aarch64.so.1 /lib/

# Essential dynamic libraries for Tor (libz, libssl, libcrypto, libevent etc.)
# We will copy the most common ones and rely on the 'deps' stage having them installed
# to resolve the correct path for the target architecture.

# ZLib - Fixes the original error
COPY --from=deps /lib/libz.so.1 /lib/

# Tor binary itself
COPY --from=deps /usr/bin/tor /usr/bin/tor

# System files required for Tor to run as an unprivileged user (UID: 106)
COPY --from=deps /etc/passwd /etc/passwd
COPY --from=deps /etc/group /etc/group

# ----------------------------------------------------------------------
# Copy application files
# ----------------------------------------------------------------------
COPY --from=builder /torgo /usr/local/bin/torgo
COPY torrc.template /etc/tor/torrc.template

# Restore the correct user/group setting
USER 106:112
ENTRYPOINT ["/usr/local/bin/torgo"]