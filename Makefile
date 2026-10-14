SHELL := /bin/bash
BINARY := mcp-keel
CMD := ./cmd/mcp-keel
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.PHONY: all build test test-race test-e2e cover vet fmt tidy lint run clean

all: fmt vet test build

build:
	go build -ldflags "-X main.version=$(VERSION)" -o bin/$(BINARY) $(CMD)

test:
	go test ./...

test-race:
	go test -race ./...

# End-to-end smoke tests against a real API server (envtest) and the built
# binary over stdio. Requires the envtest assets; export KUBEBUILDER_ASSETS,
# for example: export KUBEBUILDER_ASSETS="$(setup-envtest use -p path)".
# Without the assets the tests skip instead of failing.
test-e2e:
	go test -tags=e2e -count=1 ./e2e/...

cover:
	go test -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

vet:
	go vet ./...

fmt:
	gofmt -s -w .

tidy:
	go mod tidy

lint:
	golangci-lint run

# Run the server against a config (defaults to configs/config.yaml).
run:
	go run $(CMD) -config $${CONFIG:-configs/config.yaml}

clean:
	rm -rf bin coverage.out
