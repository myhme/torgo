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
WORKDIR /app

# Install runtime dependencies: Tor, Privoxy, S6 Overlay, and iptables
RUN apk add --no-cache \
    tor \
    privoxy \
    s6-overlay \
    iptables

# Copy the built Go application from the builder stage
COPY --from=builder /app/torgo-app .

# Copy configuration templates and scripts
COPY torrc.template /etc/tor/
COPY privoxy.conf.template /etc/privoxy/
COPY entrypoint.sh /app/
COPY docker-healthcheck.sh /app/

# Make scripts executable
RUN chmod +x /app/entrypoint.sh /app/docker-healthcheck.sh

# Entrypoint to run the S6 Overlay system
ENTRYPOINT ["/bin/s6-entrypoint"]
CMD ["/app/entrypoint.sh"]