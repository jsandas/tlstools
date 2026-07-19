## build go binary
FROM golang:1.26 AS build

COPY . /go/src/tlstools

WORKDIR /go/src/tlstools

RUN go mod download

RUN CGO_ENABLED=0 go build ./cmd/tlstools

RUN CGO_ENABLED=0 go build ./cmd/tlstools-cli

## build base image
FROM debian:bookworm AS base

RUN apt-get update && apt upgrade -y \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -r appuser

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=ghcr.io/jsandas/debian-weakkeys /usr/share/openssl-blacklist/* /opt/tlstools/resources/weakkeys/

USER appuser

WORKDIR /opt/tlstools/bin

## build server image
FROM base AS server

COPY --from=build /go/src/tlstools/tlstools /opt/tlstools/bin

ENTRYPOINT ["/opt/tlstools/bin/tlstools"]

# build cli image
FROM base AS cli

COPY --from=build /go/src/tlstools/tlstools-cli /opt/tlstools/bin

ENTRYPOINT ["/opt/tlstools/bin/tlstools-cli"]
