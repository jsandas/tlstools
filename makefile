GOLANG_VERSION=$(shell cat go.mod | egrep "^go\s" | cut -d ' ' -f 2)

build: 
	docker build -t tlstools .

build_nocache:
	docker build --no-cache -t tlstools .

fresh: build_nocache run

integration: build run
	python3 test_setup/integration_tests.py

run: build
	docker-compose -f test_setup/integrations.yaml pull --quiet --ignore-pull-failures
	docker-compose -f test_setup/integrations.yaml up -d

stop:
	docker-compose -f test_setup/integrations.yaml down

unit:
	(cd test_setup && ./gen-certs.sh)
	go test -count=1 ./... -coverprofile=coverage.out -covermode=atomic

unit_docker:
	docker build -t tlstools_build --target build .
	docker run -v ${PWD}:/go/src/tlstools -w /go/src/tlstools --rm tlstools_build \
	bash -c "(cd test_setup && ./gen-certs.sh) && go test -count=1 ./... -coverprofile=coverage.out -covermode=atomic"

