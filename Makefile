.PHONY: build test lint vet clean

build:
	go build -o brutespray main.go

test:
	go test ./...

lint:
	golangci-lint run

vet:
	go vet ./...

clean:
	rm -f brutespray
