# ---- Build Stage ----
FROM golang:1.24-alpine AS builder
WORKDIR /app

# Install git for fetching Go modules if they are not vendored.
RUN apk add --no-cache git

# Copy module files first to leverage Docker cache
COPY go.mod go.sum ./
RUN go mod download && go mod verify

# Copy the entire application source code
# This includes cmd/ and internal/
COPY . .

# Build the application from the cmd directory
RUN CGO_ENABLED=0 GOOS=linux go build -a -ldflags="-w -s" -installsuffix cgo -o /torgo-app ./cmd/torgo

# ---- Runtime Stage ----
FROM alpine:3.21
# Install Tor, su-exec, ca-certificates, coreutils, and curl (for healthcheck)
RUN apk add --no-cache tor su-exec ca-certificates coreutils curl procps # procps for sysctl

WORKDIR /app
# Copy the built application from the builder stage
COPY --from=builder /torgo-app /app/torgo-app

COPY torrc.template /etc/tor/torrc.template
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# Copy the healthcheck script
COPY docker-healthcheck.sh /usr/local/bin/docker-healthcheck.sh
RUN chmod +x /usr/local/bin/docker-healthcheck.sh

# Create base directories.
RUN mkdir -p /var/lib/tor
RUN mkdir -p /var/run/tor

# Disable IPv6 at the container level
RUN echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf && \
    echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf && \
    echo "net.ipv6.conf.lo.disable_ipv6 = 1" >> /etc/sysctl.conf
# Note: Applying sysctl settings usually requires either a reboot or `sysctl -p`.
# In Docker, these settings might be applied when the container starts if the entrypoint allows,
# or they might require the container to be run with --privileged or specific sysctl capabilities
# depending on the Docker host and version. For a non-privileged container, this sets the stage.
# The entrypoint.sh could also attempt `sysctl -p` if needed, but that requires root.

# Expose the Go API port and the new common SOCKS/DNS proxy ports
EXPOSE 8080 
# Go management API (configurable via API_PORT)
EXPOSE 9000 
# Common SOCKS proxy port (configurable via COMMON_SOCKS_PROXY_PORT)
EXPOSE 5300 
# Common DNS proxy port (UDP/TCP) (configurable via COMMON_DNS_PROXY_PORT)

# Docker Healthcheck
HEALTHCHECK --interval=60s --timeout=15s --retries=3 --start-period=2m \
  CMD /usr/local/bin/docker-healthcheck.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
