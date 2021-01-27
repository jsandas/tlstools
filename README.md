tlstools is an api for testing ssl related things

Supported functions:
* certificate installation
* which ssl/tls protocols are supported (DHE/MD5 with openssl)
* which common ssl/tls ciphers are supported
* heartbleed test
* debain weak key test

Proposed functions:
* provide cipher bit/curse size in results
* get DHE bit size
* sslv2 check
* preferred cipher order
* starttls for non-http services
* submit csr/cert for parsing


To run unit test:
```
./run_tests.sh
```


The docker image also includes a build of openssl 1.0.2 with sslv2/sslv3 support enabled for testing those protocols since go doesn't support.  Openssl is also used to test DHE ciphers.
The alernative was to fork the golang TLS library and maintain that seperately which wasn't appealing.

The binary and required files are pulled from a docker image based on the following dockerfile:
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

Currently nginx and postfix containers are provided

Build containers:
```
docker-compose -f acceptance.yml build
```

Run containers:
```
docker-compose -f acceptance.yml up -d
```
