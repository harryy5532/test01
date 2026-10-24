# syntax=docker/dockerfile:1.7

ARG GO_VERSION=1.27
ARG ALPINE_VERSION=3.24

FROM golang:${GO_VERSION}-alpine${ALPINE_VERSION} AS builder

ARG TARGETARCH=amd64
ARG GOAMD64_LEVEL=v2

WORKDIR /src

COPY go.mod ./
COPY main.go proxy.go supervisor.go cfedge.go nfedge.go bermuda.jpg ./

RUN set -eux; \
    case "${TARGETARCH}" in \
        amd64) export GOARCH=amd64 GOAMD64="${GOAMD64_LEVEL}" ;; \
        arm64) export GOARCH=arm64 GOARM64=v8.0 ;; \
        *) echo "Unsupported TARGETARCH: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    CGO_ENABLED=0 GOOS=linux \
    go build \
        -trimpath \
        -tags netgo,osusergo \
        -ldflags="-s -w -buildid=" \
        -o /out/bermuda-portal .; \
    test -s /out/bermuda-portal; \
    chmod 0555 /out/bermuda-portal

FROM alpine:${ALPINE_VERSION}

LABEL org.opencontainers.image.title="BERMUDA PORTAL" \
      org.opencontainers.image.description="BERMUDA PORTAL Institutional Edge Gateway" \
      org.opencontainers.image.version="4.0-northflank" \
      org.opencontainers.image.licenses="MIT"

RUN set -eux; \
    apk add --no-cache ca-certificates tzdata wget; \
    update-ca-certificates; \
    addgroup -g 10001 -S bermuda; \
    adduser -u 10001 -S -D -H -G bermuda -h /app -s /sbin/nologin bermuda; \
    mkdir -p /app /usr/local/bin /tmp/bp-runtime; \
    chown -R root:root /app /usr/local/bin; \
    chmod 0555 /app /usr/local/bin; \
    chmod 1777 /tmp; \
    chown -R 10001:10001 /tmp/bp-runtime; \
    chmod 0700 /tmp/bp-runtime

COPY --from=builder --chown=root:root /out/bermuda-portal /usr/local/bin/bermuda-portal

RUN set -eux; \
    chmod 0555 /usr/local/bin/bermuda-portal; \
    test -s /usr/local/bin/bermuda-portal

ENV BERMUDA_BACKEND_XH=127.0.0.1:18443 \
    BERMUDA_BACKEND_WS=127.0.0.1:18444 \
    BERMUDA_BACKEND_TR=127.0.0.1:18445 \
    BERMUDA_PATH_XH=/api/v1/sync \
    BERMUDA_PATH_WS=/api/v1/live \
    BERMUDA_PATH_TR=/api/v1/gateway \
    BERMUDA_HEALTH_PATH=/.well-known/hc-5b1e7c \
    GODEBUG=madvdontneed=1 \
    GOGC=100 \
    TZ=UTC \
    PORT=8080

USER 10001:10001
WORKDIR /app

EXPOSE 8080
STOPSIGNAL SIGTERM

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD wget -q -T 3 -O /dev/null "http://127.0.0.1:${PORT:-8080}/.well-known/hc-5b1e7c" || exit 1

CMD ["/usr/local/bin/bermuda-portal"]
