#!/bin/bash

# setup for unit tests
(cd test_setup && ./gen-certs.sh)

# run unit tests
if [[ $1 == *"cov"* ]]; then
    go test -count=1 ./... -coverprofile=coverage.txt
else
    go test -count=1 ./...
fi