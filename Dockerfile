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
RUN apk add --no-cache tor su-exec ca-certificates coreutils curl

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

# Expose the Go API port and the new common SOCKS/DNS proxy ports
EXPOSE 8080
# Go management API (configurable via API_PORT)
EXPOSE 9000
# Common SOCKS proxy port (configurable via COMMON_SOCKS_PROXY_PORT)
EXPOSE 5300
# Common DNS proxy port (UDP/TCP) (configurable via COMMON_DNS_PROXY_PORT)

# Docker Healthcheck
# It will use the environment variables set in docker-compose.yml or defaults in the script.
# Adjust interval, timeout, retries, and start period as needed.
# Start period gives the container time to initialize before health checks begin.
HEALTHCHECK --interval=60s --timeout=15s --retries=3 --start-period=2m \
  CMD /usr/local/bin/docker-healthcheck.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
