# build go binary
FROM golang:1.17 as build

COPY . /src/tlstools

WORKDIR /src/tlstools

RUN go mod download

RUN CGO_ENABLED=0 go build -o /usr/local/bin/tlstools

# build final image
FROM debian

RUN useradd -r appuser

# copy openssl files
COPY --from=ghcr.io/jsandas/openssl-tester/openssl:1.0.2-chacha /usr/local/bin/openssl /usr/local/bin/
COPY --from=ghcr.io/jsandas/openssl-tester/openssl:1.0.2-chacha /usr/local/lib/ssl /usr/local/lib/ssl

# copy tlstools files
COPY --from=build /usr/local/bin/tlstools /usr/local/bin/tlstools
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY vuln/weakkey/bin /usr/local/bin

USER appuser

ENTRYPOINT ["/usr/local/bin/tlstools"]