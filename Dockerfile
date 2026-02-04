# syntax=docker/dockerfile:1.7

##############################################
# Builder stage
##############################################
ARG GO_VERSION=1.25
ARG ALPINE_VERSION=3.23
ARG APP_NAME=torgo

FROM golang:${GO_VERSION}-alpine AS builder

ARG APP_NAME
ARG TARGETOS
ARG TARGETARCH

ENV GOOS=${TARGETOS} \
    GOARCH=${TARGETARCH}

RUN apk add --no-cache git gcc musl-dev

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Static PIE Build
RUN CGO_ENABLED=1 go build \
      -trimpath \
      -buildmode=pie \
      -ldflags='-s -w -linkmode external -extldflags "-static" -buildid=' \
      -o "/${APP_NAME}" "./cmd/${APP_NAME}"

##############################################
# Runtime stage (Zero Trust)
##############################################
FROM alpine:${ALPINE_VERSION} AS final

ARG APP_NAME

# Install Tor + Obfuscation
RUN apk add --no-cache \
      tor \
      obfs4proxy \
      libcap \
    && rm -rf /var/cache/apk/* /usr/share/man /tmp/*

COPY --from=builder "/${APP_NAME}" "/usr/local/bin/${APP_NAME}"

RUN mkdir -p /var/lib/tor-temp /etc/torgo \
    && chown -R tor:tor /var/lib/tor-temp /etc/torgo /usr/local/bin/${APP_NAME} \
    && chmod 700 /var/lib/tor-temp

COPY torrc.template /etc/tor/torrc.template
RUN chown tor:tor /etc/tor/torrc.template && chmod 644 /etc/tor/torrc.template

# === MEMORY PROTECTION: DISABLE CRASH DUMPS ===
ENV GOTRACEBACK=none

USER tor

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/torgo", "--selfcheck"]

ENTRYPOINT ["/usr/local/bin/torgo"]