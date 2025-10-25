# Stage 1: Build the Go application
FROM golang:1.25-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# Build a static, stripped binary for a smaller and more secure final image
RUN CGO_ENABLED=0 GOOS=linux go build -a -ldflags="-s -w" -o torgo-app ./cmd/torgo

# Stage 2: Create the final production image
FROM alpine:latest

# --- S6-Overlay Installation ---
# Set S6-Overlay version
ENV S6_OVERLAY_VERSION=v3.2.1.0

# Install runtime dependencies, including curl for downloading S6
RUN apk add --no-cache \
    tor \
    privoxy \
    iptables \
    xz
    
#    bash \
#    curl

# Ensure runtime user/group exist at build-time (read-only rootfs at runtime)
RUN addgroup -S _tor 2>/dev/null || true && \
    adduser -S -G _tor -h /var/lib/tor -s /sbin/nologin _tor 2>/dev/null || true

# Use Docker's automatic build-time argument `TARGETARCH`
ARG TARGETARCH

# Download and install S6-Overlay for the correct target architecture
# This block correctly maps amd64 -> x86_64 as per the official documentation
RUN case ${TARGETARCH} in \
        amd64) S6_ARCH="x86_64" ;; \
        arm64) S6_ARCH="aarch64" ;; \
        *) echo "Unsupported architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac && \
    echo "Downloading S6-Overlay for architecture: ${TARGETARCH} -> ${S6_ARCH}" && \
    curl -L -s https://github.com/just-containers/s6-overlay/releases/download/${S6_OVERLAY_VERSION}/s6-overlay-noarch.tar.xz -o /tmp/s6-overlay-noarch.tar.xz && \
    curl -L -s https://github.com/just-containers/s6-overlay/releases/download/${S6_OVERLAY_VERSION}/s6-overlay-${S6_ARCH}.tar.xz -o /tmp/s6-overlay.tar.xz && \
    tar -C / -Jxpf /tmp/s6-overlay-noarch.tar.xz && \
    tar -C / -Jxpf /tmp/s6-overlay.tar.xz && \
    rm -rf /tmp/*


# --- torgo Application Setup ---
WORKDIR /app
COPY --from=builder /app/torgo-app .
COPY torrc.template /etc/tor/
COPY privoxy.conf.template /etc/privoxy/
#COPY docker-healthcheck.sh /app/
#RUN chmod +x /app/docker-healthcheck.sh


# --- S6-Overlay Service Configuration ---
# Copy the entire rootfs structure, which contains all service definitions
COPY rootfs/ /


# The official S6-Overlay entrypoint is /init. It will run all setup scripts
# and then start and supervise all defined services.
ENTRYPOINT ["/init"]
