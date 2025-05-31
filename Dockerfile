# Stage 1: Build the Go application
FROM golang:1.24-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
# Ensure network access is available here for go mod download
RUN go mod download && go mod verify
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -a -installsuffix cgo -o torgo-app ./cmd/torgo

# Stage 2: Create the final image with S6 Overlay
FROM alpine:latest

ARG S6_OVERLAY_VERSION=v3.1.6.2 # You can update this to a newer stable version if available
ARG TARGETARCH # Docker build-time arch, e.g., amd64, arm64

# Install runtime dependencies: Tor, Privoxy, su-exec (for Tor user), ca-certificates, bash (for some scripts), curl, and wget
RUN apk add --no-cache tor privoxy su-exec ca-certificates bash curl wget

# Determine S6 architecture suffix based on TARGETARCH
# This RUN block downloads and extracts S6 Overlay
RUN echo "Building for TARGETARCH: ${TARGETARCH}" && \
    S6_ARCH_SUFFIX="" && \
    case "${TARGETARCH}" in \
        "amd64") S6_ARCH_SUFFIX="x86_64" ;; \
        "arm64") S6_ARCH_SUFFIX="aarch64" ;; \
        "arm") S6_ARCH_SUFFIX="arm" ;; # For armv7, S6 uses 'arm'. For armv6, it might be 'armel'. Check S6 releases.
        # Add other mappings if you build for other architectures, e.g.: \
        # "386") S6_ARCH_SUFFIX="i386" ;; \
        *) echo "Unsupported TARGETARCH for S6 Overlay: ${TARGETARCH}. Please check S6 Overlay releases for available architectures." >&2; exit 1 ;; \
    esac && \
    echo "Using S6 arch suffix: ${S6_ARCH_SUFFIX}" && \
    \
    echo "Downloading S6 Overlay noarch..." && \
    wget -q https://github.com/just-containers/s6-overlay/releases/download/${S6_OVERLAY_VERSION}/s6-overlay-noarch.tar.xz -O /tmp/s6-overlay-noarch.tar.xz && \
    \
    echo "Downloading S6 Overlay for ${S6_ARCH_SUFFIX}..." && \
    wget -q https://github.com/just-containers/s6-overlay/releases/download/${S6_OVERLAY_VERSION}/s6-overlay-${S6_ARCH_SUFFIX}.tar.xz -O /tmp/s6-overlay-arch.tar.xz && \
    \
    echo "Extracting S6 Overlay..." && \
    tar -C / -Jxpf /tmp/s6-overlay-noarch.tar.xz && \
    tar -C / -Jxpf /tmp/s6-overlay-arch.tar.xz && \
    \
    echo "Cleaning up downloaded S6 archives..." && \
    rm -rf /tmp/* && \
    # We can remove wget after use if not needed by other parts of the image runtime
    apk del wget

WORKDIR /app

# Copy the compiled Go application
COPY --from=builder /app/torgo-app .

# Copy Tor and Privoxy configurations, and healthcheck script
COPY torrc.template /etc/tor/torrc.template
COPY privoxy_config /etc/privoxy/config
COPY docker-healthcheck.sh /usr/local/bin/docker-healthcheck.sh

# Copy S6 service definitions and initialization scripts
# This assumes your S6 files are in a 'rootfs' directory at the build context root.
COPY rootfs/ / 

# Set permissions for scripts
# Ensure all scripts in cont-init.d and service run/finish scripts are executable
RUN chmod +x /usr/local/bin/docker-healthcheck.sh && \
    find /etc/s6-overlay/cont-init.d/ -type f -exec chmod +x {} \; && \
    find /etc/s6-overlay/s6-rc.d/ -type f \( -name 'run' -o -name 'finish' \) -exec chmod +x {} \;


# Create necessary directories for Tor
# Permissions for /var/lib/tor and /var/run/tor are best set by the cont-init script (01-tor-setup)
# or by Tor itself when run as the _tor user.
# The _tor user/group should be created by the 'tor' package installation from apk.
RUN mkdir -p /var/lib/tor /var/run/tor /etc/tor && \
    chown root:root /etc/tor
# torrc files will be root-owned, readable by _tor

EXPOSE 8080 9000 5300/tcp 5300/udp 8118

HEALTHCHECK --interval=1m --timeout=15s --start-period=3m --retries=3 \
  CMD ["/usr/local/bin/docker-healthcheck.sh"]

# S6 Overlay init process is the entrypoint
ENTRYPOINT ["/init"]
