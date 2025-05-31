# Stage 1: Build the Go application
FROM golang:1.24-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
# Ensure network access is available here for go mod download
RUN go mod download && go mod verify
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -a -installsuffix cgo -o torgo-app ./cmd/torgo

# Stage 2: Create the final image
FROM alpine:latest

# Install runtime dependencies: Tor, Privoxy, su-exec (for Tor user), ca-certificates, bash, and curl.
# Tini is also included for process management.
RUN apk add --no-cache tor privoxy su-exec ca-certificates bash curl tini

WORKDIR /app

# Copy the compiled Go application
COPY --from=builder /app/torgo-app .

# Copy Tor and Privoxy configurations, entrypoint, and healthcheck script
COPY torrc.template /etc/tor/torrc.template
COPY privoxy_config /etc/privoxy/config
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
COPY docker-healthcheck.sh /usr/local/bin/docker-healthcheck.sh

# Set permissions for scripts
RUN chmod +x /usr/local/bin/entrypoint.sh && \
    chmod +x /usr/local/bin/docker-healthcheck.sh

# Create necessary directories for Tor
# The _tor user/group should be created by the 'tor' package installation from apk.
# Permissions are largely handled by entrypoint.sh before su-exec.
RUN mkdir -p /var/lib/tor /var/run/tor /etc/tor && \
    chown root:root /etc/tor # torrc files will be root-owned, readable by _tor

EXPOSE 8080 9000 5300/tcp 5300/udp 8118

HEALTHCHECK --interval=1m --timeout=15s --start-period=3m --retries=3 \
  CMD ["/usr/local/bin/docker-healthcheck.sh"]

# Use Tini as the init process, which will then execute entrypoint.sh
ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/entrypoint.sh"]
