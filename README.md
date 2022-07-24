[![main](https://github.com/jsandas/tlstools/actions/workflows/release.yaml/badge.svg)](https://github.com/jsandas/tlstools/actions/workflows/release.yaml)
[![acceptance](https://github.com/jsandas/tlstools/actions/workflows/acceptance.yaml/badge.svg)](https://github.com/jsandas/tlstools/actions/workflows/acceptance.yaml)
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
```
curl "http://localhost:8080/api/v1/scan?host=intranetlib.geneseo.edu:443"
```
```
curl "http://localhost:8080/api/v1/scan?host=www.google.com"
```
Or a real bad server:
```
curl "http://localhost:8080/api/v1/scan?host=kis.mhs.ch"
```
```
curl -X POST --data-binary @test.csr "http://localhost:8080/api/v1/parser/csr"
```


The acceptance.yaml docker-compose file is intended to build and run containers for testing against different services.  

Currently insecure nginx and postfix containers are provided for acceptance testing

Build containers:
```
docker-compose -f acceptance.yaml build
```

Run containers:
```
docker-compose -f acceptance.yaml up -d
```

Run acceptance tests:
```
./run_acceptance_tests.py
```