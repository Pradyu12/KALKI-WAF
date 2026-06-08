.PHONY: build run test clean docker-build

build:
	go build -ldflags="-s -w" -o bin/kalki-proxy ./cmd/kalki-proxy/

run:
	go run ./cmd/kalki-proxy/

test:
	go test ./... -v -race

clean:
	rm -rf bin/ vendor/

docker-build:
	docker build -t kalki-proxy:latest .

lint:
	golangci-lint run ./...
