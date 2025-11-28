# 2025 gVisor-Hardened Multi-Arch (ARM64/AMD64)
ARG GO_VERSION=1.23
ARG ALPINE_VERSION=3.20
ARG BUILD_USER_UID=1001
ARG BUILD_USER_GID=1001
ARG APP_NAME=torgo

# Builder: Reproducible Go
FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-alpine AS builder
ARG BUILD_USER_UID
ARG BUILD_USER_GID
ARG APP_NAME
RUN apk add --no-cache git gcc musl-dev build-base \
    && mkdir -p /build /cache /tmp/go-cache
RUN addgroup -S -g "${BUILD_USER_GID}" buildergroup \
 && adduser -S -D -u "${BUILD_USER_UID}" -G buildergroup builder \
 && chown -R builder:buildergroup /build /cache /tmp/go-cache
ENV CGO_ENABLED=1 GOCACHE=/cache/go-build GOMODCACHE=/tmp/go-cache GOPATH=/go GOFLAGS=-mod=readonly
WORKDIR /build
COPY go.* ./
USER builder
RUN --mount=type=cache,target=${GOMODCACHE},uid=${BUILD_USER_UID},gid=${BUILD_USER_GID} \
    --mount=type=cache,target=/cache/go-build,uid=${BUILD_USER_UID},gid=${BUILD_USER_GID} \
    go mod download
COPY --chown=builder:buildergroup . .
RUN --mount=type=cache,target=${GOMODCACHE},uid=${BUILD_USER_UID},gid=${BUILD_USER_GID} \
    --mount=type=cache,target=/cache/go-build,uid=${BUILD_USER_UID},gid=${BUILD_USER_GID} \
    CGO_ENABLED=1 go build -trimpath -ldflags='-s -w -extldflags=-static -buildid=' -o /${APP_NAME} ./cmd/${APP_NAME} \
    && strip --strip-all /${APP_NAME}

# Deps: Tor + cryptsetup + runtime libs (gVisor syscall compat)
FROM alpine:${ALPINE_VERSION} AS deps
ARG ALPINE_VERSION
RUN apk add --no-cache tor cryptsetup-libs luksmeta libdevmapper \
    libssl3 libcrypto3 libevent zlib \
    && rm -rf /var/cache/apk/* /usr/share/man /tmp/*

# Final: Scratch + gVisor-proof statics
FROM scratch AS final
ARG APP_NAME
LABEL org.opencontainers.image.title="torgo-gvisor-zt"
# Musl + libs (static-linked for runsc)
COPY --from=deps /lib/ld-musl-*.so.1 /lib/
COPY --from=deps /lib/libz.so.1 /lib/
COPY --from=deps /usr/lib/libssl.so.3 /usr/lib/
COPY --from=deps /usr/lib/libcrypto.so.3 /usr/lib/
COPY --from=deps /usr/lib/libevent-*.so.* /usr/lib/
# Tor + cryptsetup (gVisor traps dm-crypt calls)
COPY --from=deps /usr/bin/tor /usr/bin/tor
COPY --from=deps /usr/sbin/cryptsetup /usr/sbin/cryptsetup
# Passwd/group for UID 106:112 (tor user)
COPY --from=deps /etc/passwd /etc/passwd
COPY --from=deps /etc/group /etc/group
# App + template
COPY --from=builder /${APP_NAME} /usr/local/bin/${APP_NAME}
COPY torrc.template /etc/tor/torrc.template
USER 106:112  # Drop to tor (gVisor enforces)
ENTRYPOINT ["/usr/local/bin/torgo"]