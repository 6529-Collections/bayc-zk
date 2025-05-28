BINARY_PROVER=./bin/prover
BINARY_VERIFIER=./bin/verifier

.PHONY: all build test lint clean release

all: build

build:
	go build -o $(BINARY_PROVER) ./cmd/prover
	go build -o $(BINARY_VERIFIER) ./cmd/verifier

test:
	go test ./...

lint:
	golangci-lint run ./...

clean:
	rm -rf bin examples/**/bayc_*.{bin,json}

release: build
	@echo "Add packaging logic here (tarball, versions, etc.)"