# Stage 1: Build the Go application
FROM golang:1.24-alpine AS builder

WORKDIR /app

# Install build dependencies for CGO (e.g., for net package)
RUN apk add --no-cache gcc musl-dev

# Copy go.mod and go.sum first to leverage Docker cache
COPY go.mod go.sum ./
RUN go mod download
RUN go mod verify

# Copy the rest of the application source code
# For a modular project, this will copy all subdirectories (cmd, internal, static, etc.)
COPY . .

# Build the application. The main package is now in cmd/torgo/
# The output binary will be named "torgo"
RUN CGO_ENABLED=1 GOOS=linux go build -ldflags="-s -w" -o /torgo ./cmd/torgo

# Stage 2: Create the final lightweight image
FROM alpine:latest

WORKDIR /app

# Install runtime dependencies:
RUN apk add --no-cache tor ca-certificates iptables su-exec dnsmasq curl bash net-tools

# Copy the built Go application binary from the builder stage
COPY --from=builder /torgo /usr/local/bin/torgo

# Copy static assets and scripts
COPY static/webui.html /app/static/webui.html
COPY torrc.transparent.template /app/torrc.transparent.template
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# Define the main configuration and data volume
VOLUME /data/config

# Create initial structure within /data/config.
# The entrypoint script will be responsible for more detailed setup.
RUN mkdir -p /data/config/tor_tp /data/config/dnsmasq /data/config/torgo_instances && \
    chown -R nobody:nobody /data/config

# Expose necessary ports
EXPOSE 2525
# API port for torgo (defined by -apiPort flag in main.go)
EXPOSE 9049 
# SOCKS5 Load Balancer port for torgo (defined by -lbPort flag in main.go)
EXPOSE 53/tcp 
# dnsmasq DNS port
EXPOSE 53/udp 
# dnsmasq DNS port

# Environment variables for paths used by entrypoint.sh and the application
ENV TOR_PATH="/usr/bin/tor"
ENV ADBLOCK_LIST_URL="https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
# BASE_TORRC_PATH for torgo's own instances can be set in CMD or docker run
# Default path for torgo's base torrc if user provides one via volume:
ENV TORGO_BASE_TORRC_PATH_DEFAULT="/data/config/torgo_base/base_torrc"


# USER directive is removed; entrypoint.sh handles user switching for torgo.

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
# Default CMD for torgo application.
# The -torrc flag for torgo now points to a potential base_torrc within /data/config.
# The -adblockHostsFile and -torgoInstanceBasePath are now set by entrypoint.sh
# but can be overridden if passed explicitly in docker run CMD.
CMD ["-host", "0.0.0.0", "-tor", "/usr/bin/tor", "-torrc", "/data/config/torgo_base/base_torrc"]
