[![main](https://github.com/jsandas/tlstools/actions/workflows/release.yaml/badge.svg)](https://github.com/jsandas/tlstools/actions/workflows/release.yaml)
[![acceptance](https://github.com/jsandas/tlstools/actions/workflows/integration.yaml/badge.svg)](https://github.com/jsandas/tlstools/actions/workflows/integration.yaml)
[![unit](https://github.com/jsandas/tlstools/actions/workflows/unit.yaml/badge.svg)](https://github.com/jsandas/tlstools/actions/workflows/unit.yaml)
[![codecov](https://codecov.io/gh/jsandas/tlstools/branch/master/graph/badge.svg?token=BTCVS201GQ)](https://codecov.io/gh/jsandas/tlstools)

tlstools is an api for testing ssl related things

Supported functions:
* certificate installation
* which ssl/tls protocols are supported
* which common ssl/tls ciphers are supported
* heartbleed test
* debain weak key test
* sslv2 check
* starttls for non-http services
* submit csr/cert for parsing

Proposed functions:
* provide cipher bit/curve size in results
* parse openssl results
* check for preferred cipher order


To run unit test:
```
./run_unit_tests.sh
```


This programs depends on openssl for the protocol/cipher support check as the go tls library only implements a subset of possible ciphers.  This was determined to be less effort than forking the golang TLS library and maintaining that seperately.  The docker image contains specialy compiled versions of openssl which support many ciphers for TLS 1.2 and lower.

The openssl binary and required libraries are pulled from a docker image based on the following dockerfile:
```
https://github.com/jsandas/docker/blob/master/openssl-test/Dockerfile1.0.2-chacha
```

To view openssl supported ciphers, run the following inside the container:
```
openssl ciphers -V 'ALL:COMPLEMENTOFALL'
```

Example requests:
Collect certificate information:
```
curl "http://localhost:8080/api/v1/scan/certificate?host=www.google.com:443"
```
Collect server configuration:
```
curl "http://localhost:8080/api/v1/scan/configuration?host=www.google.com"
```
```
curl -X POST --data-binary @test.csr "http://localhost:8080/api/v1/parser/csr"
```


The integrations.yaml docker-compose file is intended to build and run containers for testing against different services.  

Currently insecure nginx and postfix containers are provided for integration testing

Build container:
```
make build
```

Run integration containers (for manual testing):
```
make run
```

Run unit tests:
```
make unit
```

Run unit tests in docker:
```
make unit_docker
```

Run integration tests:
```
make integration stop
```