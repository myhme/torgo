# Stage 1: Build the Go application
FROM golang:1.24-alpine AS builder

WORKDIR /app

# Copy go.mod and go.sum first to leverage Docker cache
COPY go.mod go.sum ./
RUN go mod download
RUN go mod verify

# Copy the rest of the application source code
COPY . .

# Build the application
# CGO_ENABLED=0 for a statically linked binary (good for Alpine)
# -ldflags="-s -w" to strip debug symbols and reduce binary size
RUN CGO_ENABLED=0 GOOS=linux go build -a -ldflags="-s -w" -o torgo-app ./cmd/torgo

# Stage 2: Create the final lightweight image
FROM alpine:latest

# Install Tor and su-exec (similar to gosu, for running Tor as non-root)
# ca-certificates is needed for HTTPS calls (e.g., IP checks, performance tests)
RUN apk add --no-cache tor su-exec ca-certificates tzdata

# Create a non-root user for Tor
# _tor is a common convention for the Tor user
RUN addgroup -S _tor && adduser -S -G _tor -h /var/lib/tor _tor

WORKDIR /app

# Copy the torrc template and entrypoint script
COPY torrc.template /etc/tor/torrc.template
COPY entrypoint.sh /app/entrypoint.sh
COPY docker-healthcheck.sh /app/docker-healthcheck.sh
RUN chmod +x /app/entrypoint.sh /app/docker-healthcheck.sh

# Copy the built application from the builder stage
COPY --from=builder /app/torgo-app /app/torgo-app

# Ensure Tor data directories are writable by the _tor user
# The entrypoint script will also handle permissions for instance-specific data dirs
RUN mkdir -p /var/lib/tor /var/run/tor && \
    chown -R _tor:_tor /var/lib/tor /var/run/tor && \
    chmod -R 700 /var/lib/tor /var/run/tor

# Expose default ports (can be overridden by docker-compose.yml or -p flag)
# API port, common SOCKS port, common DNS port (TCP/UDP)
EXPOSE 8080 9000 5300/tcp 5300/udp

# Set the entrypoint
ENTRYPOINT ["/app/entrypoint.sh"]

# Default command (not strictly necessary if entrypoint handles everything)
# CMD ["/app/torgo-app"]
