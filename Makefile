.PHONY: build test lint vet clean

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/x90skysn3k/brutespray/v2/brutespray.version=$(VERSION)

build:
	go build -ldflags "$(LDFLAGS)" -o brutespray main.go

test:
	go test ./...

lint:
	golangci-lint run

vet:
	go vet ./...

clean:
	rm -f brutespray
