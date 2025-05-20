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
# Install Tor (which creates _tor user), su-exec, ca-certificates, and coreutils
RUN apk add --no-cache tor su-exec ca-certificates coreutils

WORKDIR /app
# Copy the built application from the builder stage
COPY --from=builder /torgo-app /app/torgo-app

COPY torrc.template /etc/tor/torrc.template
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# Create base directories.
# The 'tor' package installation should set appropriate permissions for /var/lib/tor.
# The entrypoint.sh script will handle permissions for /var/run/tor and instance-specific subdirectories.
RUN mkdir -p /var/lib/tor
RUN mkdir -p /var/run/tor

# Expose the Go API port and the new common SOCKS/DNS proxy ports
EXPOSE 8080
# Go management API (configurable via API_PORT)
EXPOSE 9000
# Common SOCKS proxy port (configurable via COMMON_SOCKS_PROXY_PORT)
EXPOSE 5300
# Common DNS proxy port (UDP/TCP) (configurable via COMMON_DNS_PROXY_PORT)

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
