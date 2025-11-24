FROM golang:1.25-alpine AS builder
USER nobody
RUN apk add --no-cache --virtual .build-deps git gcc musl-dev
WORKDIR /src
COPY go.* ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
RUN CGO_ENABLED=1 go build -trimpath -ldflags="-s -w -extldflags=-static -buildid=" -o /torgo ./cmd/torgo \
    && strip --strip-all /torgo

FROM scratch
COPY --from=alpine:latest /lib/ld-musl-aarch64.so.1 /lib/
COPY --from=alpine:latest /lib/libz.so.1 /lib/
COPY --from=alpine:latest /usr/bin/tor /usr/bin/tor
COPY --from=alpine:latest /etc/passwd /etc/passwd
COPY --from=alpine:latest /etc/group /etc/group
COPY --from=builder /torgo /usr/local/bin/torgo
COPY torrc.template /etc/tor/torrc.template
USER 106:112
ENTRYPOINT ["/usr/local/bin/torgo"]