.PHONY: test build vet

test:
	go test -race -count=1 ./...

vet:
	go vet ./...

build:
	go build -o .local/bin/teraland ./cmd/teraland
