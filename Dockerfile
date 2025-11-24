# --- Builder Stage ---
FROM golang:1.25-alpine AS builder
USER nobody
# FIX: Set GOMODCACHE to a writable location (like /tmp) to avoid 'permission denied'
# when running 'go mod download' as a non-root user with BuildKit cache mounts.
ENV GOMODCACHE=/tmp/go-cache
RUN apk add --no-cache --virtual .build-deps git gcc musl-dev
WORKDIR /src
COPY go.* ./
# Use the updated GOMODCACHE path as the cache target
RUN --mount=type=cache,target=$GOMODCACHE go mod download
COPY . .
RUN CGO_ENABLED=1 go build -trimpath -ldflags="-s -w -extldflags=-static -buildid=" -o /torgo ./cmd/torgo \
    && strip --strip-all /torgo

# --- Dependencies Stage (Inferred from your build logs) ---
FROM alpine:latest AS deps
# Install tor and all its required shared libraries (libssl3, libcrypto3, libevent, zlib)
RUN apk add --no-cache tor libssl3 libcrypto3 libevent zlib \
    && rm -rf /var/cache/apk/* /usr/share/man /tmp/*

# --- Final Stage ---
FROM scratch
# Copy musl C library, zlib, and tor's shared libraries from the deps stage
COPY --from=deps /lib/ld-musl-*.so.1 /lib/
COPY --from=deps /usr/lib/libz.so.1 /lib/
COPY --from=deps /usr/lib/libssl.so.3 /usr/lib/
COPY --from=deps /usr/lib/libcrypto.so.3 /usr/lib/
COPY --from=deps /usr/lib/libevent-2.1.so.7 /usr/lib/

# Copy the tor binary and system files
COPY --from=deps /usr/bin/tor /usr/bin/tor
COPY --from=deps /etc/passwd /etc/passwd
COPY --from=deps /etc/group /etc/group

# Copy the built application and configuration
COPY --from=builder /torgo /usr/local/bin/torgo
COPY torrc.template /etc/tor/torrc.template

# Use the non-root user that Tor runs as
USER 106:106
ENTRYPOINT ["/usr/local/bin/torgo"]