[![unit](https://github.com/jsandas/tlstools/actions/workflows/unit.yaml/badge.svg)](https://github.com/jsandas/tlstools/actions/workflows/unit.yaml)
[![acceptance](https://github.com/jsandas/tlstools/actions/workflows/acceptance.yml/badge.svg)](https://github.com/jsandas/tlstools/actions/workflows/acceptance.yml)
[![build](https://github.com/jsandas/tlstools/actions/workflows/main.yaml/badge.svg)](https://github.com/jsandas/tlstools/actions/workflows/main.yaml)

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


This programs depends on openssl for the protocol/cipher support check as the go tls library only implements a subset of available ciphers.  This was determined to be less effort than forking the golang TLS library and maintaining that seperately.  The docker image contains a specialy compile version of openssl which supports all ciphers for TLS 1.2 and lower.

The openssl binary and required libraries are pulled from a docker image based on the following dockerfile:
```
https://github.com/jsandas/docker/blob/master/openssl-test/Dockerfile
```

To view openssl supported ciphers:
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


The acceptance.yml docker-compose file is intended to build and run containers for testing against different services.  

Currently insecure nginx and postfix containers are provided for acceptance testing

Build containers:
```
docker-compose -f acceptance.yml build
```

Run containers:
```
docker-compose -f acceptance.yml up -d
```

Run acceptance tests:
```
./run_acceptance_tests.py
```