FROM golang:1.25-alpine AS builder

# 1. Install build dependencies as root (default user).
# We install these here because apk/package managers often require root privileges.
RUN apk add --no-cache --virtual .build-deps git gcc musl-dev

# 2. Switch to the non-privileged user for the application build steps.
# This ensures that all Go commands run with minimal permissions.
USER nobody

WORKDIR /src
COPY go.* ./

# 3. Download Go modules. This step now succeeds because BuildKit's cache mount
# runs in the context of the 'nobody' user, and since the user is not root,
# BuildKit correctly handles permissions on the mounted volume.
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY . .

# 4. Build the application (CGO_ENABLED=1 is required for static linking with musl/Alpine).
RUN CGO_ENABLED=1 go build -trimpath -ldflags="-s -w -extldflags=-static -buildid=" -o /torgo ./cmd/torgo \
    && strip --strip-all /torgo

# --- Dependency Stage (No Change Needed, but using 'deps' alias for clarity) ---
FROM alpine:latest AS deps

# Install runtime dependencies for Tor.
RUN apk add --no-cache tor libssl3 libcrypto3 libevent zlib \
    && rm -rf /var/cache/apk/* /usr/share/man /tmp/*

# --- Final Scratch Image Stage (Minimal) ---
FROM scratch

# Copy Musl libc (dynamic linker) - use wildcard for multi-platform (e.g., amd64 vs aarch64)
COPY --from=deps /lib/ld-musl-*.so.1 /lib/

# Copy required Tor and system libraries from the 'deps' stage
COPY --from=deps /usr/lib/libz.so.1 /lib/
COPY --from=deps /usr/lib/libssl.so.3 /usr/lib/
COPY --from=deps /usr/lib/libcrypto.so.3 /usr/lib/
COPY --from=deps /usr/lib/libevent-2.1.so.7 /usr/lib/

# Copy the Tor binary and essential user/group files
COPY --from=deps /usr/bin/tor /usr/bin/tor
COPY --from=deps /etc/passwd /etc/passwd
COPY --from=deps /etc/group /etc/group

# Copy the built Go binary and the torrc template
COPY --from=builder /torgo /usr/local/bin/torgo
COPY torrc.template /etc/tor/torrc.template

# Run as the unprivileged user/group (UID 106 is often the default Tor user ID)
USER 106:112
ENTRYPOINT ["/usr/local/bin/torgo"]