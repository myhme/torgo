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
# Install tor and its core dynamic dependencies explicitly for better consistency
RUN apk add --no-cache tor libssl3 libcrypto3 libevent libz \
    && rm -rf /var/cache/apk/* /usr/share/man /tmp/*

# --- STAGE 2: FINAL DISTROLESS IMAGE ---
FROM scratch

# ----------------------------------------------------------------------
# Copy essential files from the 'deps' stage
# ----------------------------------------------------------------------

# 1. Dynamic Linker: Use wildcard to copy the correct linker for the target architecture. (FIXED)
COPY --from=deps /lib/ld-musl-*.so.1 /lib/

# 2. Tor's Core Dynamic Libraries: Copy the standard symlink names.
COPY --from=deps /lib/libz.so.1 /lib/
COPY --from=deps /usr/lib/libssl.so.3 /usr/lib/
COPY --from=deps /usr/lib/libcrypto.so.3 /usr/lib/
COPY --from=deps /usr/lib/libevent-2.1.so.7 /usr/lib/

# 3. Tor binary and system files
COPY --from=deps /usr/bin/tor /usr/bin/tor
COPY --from=deps /etc/passwd /etc/passwd
COPY --from=deps /etc/group /etc/group

# 4. Application files
COPY --from=builder /torgo /usr/local/bin/torgo
COPY torrc.template /etc/tor/torrc.template

# Restore the correct user/group setting
USER 106:112
ENTRYPOINT ["/usr/local/bin/torgo"]