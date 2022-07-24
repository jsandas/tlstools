#!/bin/bash

# setup for unit tests
(cd test_setup && ./gen-certs.sh)

# run unit tests
if [[ $1 == *"cov"* ]]; then
    go test ./... -coverprofile=coverage.out -covermode=atomic
else
    go test ./...
fi