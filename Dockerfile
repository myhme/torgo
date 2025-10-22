# Stage 1: Build the Go application
FROM golang:1.25-alpine AS builder
WORKDIR /app
RUN apk add --no-cache git
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Build a static, stripped binary for a smaller and more secure final image
RUN CGO_ENABLED=0 GOOS=linux go build -a -trimpath -ldflags="-s -w -buildid= -buildvcs=false" -o torgo-app ./cmd/torgo

# Stage 2: Create the final production image
FROM alpine:3.20

# --- S6-Overlay Installation ---
# Set S6-Overlay version
ENV S6_OVERLAY_VERSION=v3.2.1.0

# Install runtime dependencies, including curl for downloading S6
RUN apk add --no-cache \
    tor \
    privoxy \
    iptables \
    xz \
    bash \
    curl \
    ca-certificates && update-ca-certificates

# Use Docker's automatic build-time argument `TARGETARCH`
ARG TARGETARCH

# Download, verify (SHA256), and install S6-Overlay for the correct target architecture
# This block correctly maps amd64 -> x86_64 as per the official documentation
RUN set -eux; \
    case ${TARGETARCH} in \
        amd64) S6_ARCH="x86_64" ;; \
        arm64) S6_ARCH="aarch64" ;; \
        *) echo "Unsupported architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    echo "Downloading S6-Overlay for architecture: ${TARGETARCH} -> ${S6_ARCH}"; \
    curl -fsSL -o /tmp/s6-overlay-noarch.tar.xz https://github.com/just-containers/s6-overlay/releases/download/${S6_OVERLAY_VERSION}/s6-overlay-noarch.tar.xz; \
    curl -fsSL -o /tmp/s6-overlay.tar.xz https://github.com/just-containers/s6-overlay/releases/download/${S6_OVERLAY_VERSION}/s6-overlay-${S6_ARCH}.tar.xz; \
    curl -fsSL -o /tmp/sha256sum.txt https://github.com/just-containers/s6-overlay/releases/download/${S6_OVERLAY_VERSION}/sha256sum.txt; \
    cd /tmp; \
    grep 's6-overlay-noarch.tar.xz' sha256sum.txt > noarch.sha256; \
    grep "s6-overlay-${S6_ARCH}.tar.xz" sha256sum.txt > arch.sha256; \
    sha256sum -c noarch.sha256; \
    sha256sum -c arch.sha256; \
    tar -C / -Jxpf /tmp/s6-overlay-noarch.tar.xz; \
    tar -C / -Jxpf /tmp/s6-overlay.tar.xz; \
    rm -f /tmp/s6-overlay*.tar.xz /tmp/*.sha256 /tmp/sha256sum.txt


# --- torgo Application Setup ---
WORKDIR /app
COPY --from=builder /app/torgo-app .
COPY torrc.template /etc/tor/
COPY privoxy.conf.template /etc/privoxy/
COPY docker-healthcheck.sh /app/
RUN chmod +x /app/docker-healthcheck.sh


# --- S6-Overlay Service Configuration ---
# Copy the entire rootfs structure, which contains all service definitions
COPY rootfs/ /

# Healthcheck for container liveness
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD /app/docker-healthcheck.sh || exit 1

# The official S6-Overlay entrypoint is /init. It will run all setup scripts
# and then start and supervise all defined services.
ENTRYPOINT ["/init"]