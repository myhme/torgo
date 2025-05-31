# Stage 1: Build the Go application
FROM golang:1.21-alpine AS builder

WORKDIR /app

# For Go modules, ensure git is available if direct Git dependencies are used.
# Alpine's base image is minimal.
# RUN apk add --no-cache git

COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -a -installsuffix cgo -o torgo-app ./cmd/torgo

# Stage 2: Create the final image
FROM alpine:latest

# Install Tor, Privoxy, Tini, and ca-certificates (for HTTPS calls by torgo/Tor)
RUN apk add --no-cache tor privoxy tini ca-certificates

WORKDIR /app

COPY --from=builder /app/torgo-app .

COPY torrc.template /etc/tor/torrc.template
COPY privoxy_config /etc/privoxy/config # Privoxy config
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
COPY docker-healthcheck.sh /usr/local/bin/docker-healthcheck.sh

RUN chmod +x /usr/local/bin/entrypoint.sh && \
    chmod +x /usr/local/bin/docker-healthcheck.sh

# Create _tor user and group, and necessary directories
RUN addgroup -S _tor && \
    adduser -S -G _tor -h /var/lib/tor -s /sbin/nologin _tor && \
    mkdir -p /var/lib/tor /var/run/tor /etc/tor && \
    chown -R _tor:_tor /var/lib/tor /var/run/tor

EXPOSE 8080
# Torgo API
EXPOSE 9000
# Torgo SOCKS (used by Privoxy)
EXPOSE 5300/tcp
# Torgo DNS
EXPOSE 5300/udp
# Torgo DNS
EXPOSE 8118
# Privoxy HTTP

HEALTHCHECK --interval=1m --timeout=15s --start-period=2m --retries=3 \
  CMD ["/usr/local/bin/docker-healthcheck.sh"]

ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/entrypoint.sh"]
