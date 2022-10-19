## build go binary
FROM golang:1.18 as build

COPY . /go/src/tlstools

WORKDIR /go/src/tlstools

RUN go mod download

RUN apt-get update && apt install -y nmap

RUN CGO_ENABLED=0 go build ./cmd/tlstools

# RUN CGO_ENABLED=0 go build -o /usr/local/bin/tlstools ./cmd/tlstools-cli

## build base image
FROM debian as base

RUN apt-get update && apt upgrade -y \
    && apt-get install -y nmap \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -r appuser

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=ghcr.io/jsandas/debian-weakkeys /usr/share/openssl-blacklist/* /opt/tlstools/resources/weakkeys/
COPY resources/nmap /opt/tlstools/resources/nmap

USER appuser

WORKDIR /opt/tlstools/bin

## build server image
FROM base as server

COPY --from=build /go/src/tlstools/tlstools /opt/tlstools/bin

ENTRYPOINT ["/opt/tlstools/bin/tlstools"]

## build cli image
# FROM base as cli

# COPY --from=build /usr/local/bin/tlstools-cli /usr/local/bin/tlstools-cli

# ENTRYPOINT ["/usr/local/bin/tlstools-cli"]
