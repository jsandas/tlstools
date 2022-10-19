GOLANG_VERSION=$(shell cat go.mod | egrep "^go\s" | cut -d ' ' -f 2)

setup_local_dev:
	docker run --rm -v ${PWD}/resources/weakkeys:/tmp ghcr.io/jsandas/debian-weakkeys bash -c "/bin/cp /usr/share/openssl-blacklist/* /tmp"

build: 
	docker build -t tlstools --target server .
	# docker build -t tlstools-cli --target cli .

build_nocache:
	docker build --no-cache -t tlstools --target server .
	# docker build --no-cache -t tlstools-cli --target cli .

fresh: build_nocache run

integration: build run
	python3 test_setup/integration_tests.py

run: setup_local_dev build
	docker-compose -f test_setup/integrations.yaml pull --quiet --ignore-pull-failures
	docker-compose -f test_setup/integrations.yaml up -d

stop:
	docker-compose -f test_setup/integrations.yaml down

unit: setup_local_dev
	(cd test_setup && ./gen-certs.sh)
	go test -count=1 ./... -coverprofile=coverage.out -covermode=atomic

unit_docker: setup_local_dev
	docker build -t tlstools_build --target build .
	docker run -v ${PWD}:/go/src/tlstools -w /go/src/tlstools --rm tlstools_build \
	bash -c "(cd test_setup && ./gen-certs.sh) && go test -count=1 ./... -coverprofile=coverage.out -covermode=atomic"

