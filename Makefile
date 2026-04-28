APP := idp-auth-server-go
PKG := ./idp-auth-server-go
BIN_DIR := bin
BIN := $(BIN_DIR)/$(APP)

.PHONY: help tidy fmt lint test build run clean

help:
	@printf "Targets:\n"
	@printf "  make tidy   - tidy Go modules\n"
	@printf "  make fmt    - format Go source\n"
	@printf "  make lint   - run golangci-lint\n"
	@printf "  make test   - run unit tests\n"
	@printf "  make build  - build server binary\n"
	@printf "  make run    - run server locally\n"
	@printf "  make clean  - remove build artifacts\n"

tidy:
	go mod tidy

fmt:
	gofmt -w idp-auth-server-go/*.go

lint:
	golangci-lint run ./...

test:
	go test ./...

build:
	mkdir -p $(BIN_DIR)
	go build -o $(BIN) $(PKG)

run:
	go run $(PKG)

clean:
	rm -rf $(BIN_DIR)
