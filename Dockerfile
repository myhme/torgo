# Stage 1: Build the Go application
FROM golang:1.24-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -a -installsuffix cgo -o torgo-app ./cmd/torgo

# Stage 2: Create the final image with S6 Overlay
FROM alpine:latest

ARG S6_OVERLAY_VERSION=v3.2.1.0

RUN apk add --no-cache tor privoxy su-exec ca-certificates bash curl

ADD https://github.com/just-containers/s6-overlay/releases/download/${S6_OVERLAY_VERSION}/s6-overlay-noarch.tar.xz /tmp/
ADD https://github.com/just-containers/s6-overlay/releases/download/${S6_OVERLAY_VERSION}/s6-overlay-$(uname -m).tar.xz /tmp/
RUN tar -C / -Jxpf /tmp/s6-overlay-noarch.tar.xz && \
    tar -C / -Jxpf /tmp/s6-overlay-$(uname -m).tar.xz && \
    rm -rf /tmp/*

WORKDIR /app
COPY --from=builder /app/torgo-app .
COPY torrc.template /etc/tor/torrc.template
COPY privoxy_config /etc/privoxy/config
COPY docker-healthcheck.sh /usr/local/bin/docker-healthcheck.sh
COPY rootfs/ / 
RUN chmod +x /usr/local/bin/docker-healthcheck.sh && \
    find /etc/s6-overlay -type f -name run -exec chmod +x {} \; && \
    find /etc/s6-overlay -type f -name finish -exec chmod +x {} \; && \
    find /etc/s6-overlay/cont-init.d -type f -exec chmod +x {} \;


RUN mkdir -p /var/lib/tor /var/run/tor /etc/tor && \
    chown root:root /etc/tor 
# Torrc files are root-owned, _tor reads them. _tor owns DataDir.

EXPOSE 8080 9000 5300/tcp 5300/udp 8118

HEALTHCHECK --interval=1m --timeout=15s --start-period=3m --retries=3 \
  CMD ["/usr/local/bin/docker-healthcheck.sh"]

ENTRYPOINT ["/init"]
