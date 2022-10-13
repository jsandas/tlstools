# build go binary
FROM golang:1.18 as build

COPY . /go/src/tlstools

WORKDIR /go/src/tlstools

RUN go mod download

RUN apt-get update && apt install -y nmap

RUN CGO_ENABLED=0 go build -o /usr/local/bin/tlstools ./cmd/tlstools

# RUN CGO_ENABLED=0 go build -o /usr/local/bin/tlstools ./cmd/tlstools-cli

# build final image
FROM debian as base

RUN apt-get update && apt upgrade -y \
    && apt-get install -y nmap \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -r appuser

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY vuln/weakkey/bin /usr/local/bin
COPY vuln/scripts /usr/local/bin/scripts

USER appuser

WORKDIR /usr/local/bin


FROM debian as server

COPY --from=build /usr/local/bin/tlstools /usr/local/bin/tlstools

ENTRYPOINT ["/usr/local/bin/tlstools"]