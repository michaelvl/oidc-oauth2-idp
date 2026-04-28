APP := idp-auth-server-go
PKG := ./idp-auth-server-go
BIN_DIR := bin
BIN := $(BIN_DIR)/$(APP)
KO_CONFIG_PATH ?= ./.ko.yaml
KO_IMPORTPATH ?= ./idp-auth-server-go
KO_DOCKER_REPO ?= ko.local
KO_TAGS ?= latest

.PHONY: help tidy fmt lint test build run container clean

help:
	@printf "Targets:\n"
	@printf "  make tidy   - tidy Go modules\n"
	@printf "  make fmt    - format Go source\n"
	@printf "  make lint   - run golangci-lint\n"
	@printf "  make test   - run unit tests\n"
	@printf "  make build  - build server binary\n"
	@printf "  make run    - run server locally\n"
	@printf "  make container - publish with ko\n"
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

container:
	KO_CONFIG_PATH=$(KO_CONFIG_PATH) KO_DOCKER_REPO=$(KO_DOCKER_REPO) ko publish --base-import-paths --tags="$(KO_TAGS)" "$(KO_IMPORTPATH)"

clean:
	rm -rf $(BIN_DIR)
