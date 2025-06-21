# Stage 1: Build the Go application
FROM golang:1.21-alpine AS builder
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
ENV ARCH=amd64

# Install runtime dependencies.
RUN apk add --no-cache \
    tor \
    privoxy \
    iptables \
    xz \
    bash \
    curl

# Add S6-Overlay from GitHub, which is the official installation method.
ADD https://github.com/just-containers/s6-overlay/releases/download/${S6_OVERLAY_VERSION}/s6-overlay-noarch.tar.xz /tmp/
ADD https://github.com/just-containers/s6-overlay/releases/download/${S6_OVERLAY_VERSION}/s6-overlay-${ARCH}.tar.xz /tmp/
RUN tar -C / -Jxpf /tmp/s6-overlay-noarch.tar.xz && \
    tar -C / -Jxpf /tmp/s6-overlay-${ARCH}.tar.xz && \
    rm -rf /tmp/*


# --- torgo Application Setup ---
WORKDIR /app
COPY --from=builder /app/torgo-app .
COPY torrc.template /etc/tor/
COPY privoxy.conf.template /etc/privoxy/
COPY docker-healthcheck.sh /app/
RUN chmod +x /app/docker-healthcheck.sh


# --- S6-Overlay Service Configuration ---
# Copy the entire rootfs structure, which contains all service definitions
# (including the crucial 'up' files), into the root of the image.
COPY rootfs/ /


# The official S6-Overlay entrypoint is /init. It will run all setup scripts
# and then start and supervise all defined services.
ENTRYPOINT ["/init"]