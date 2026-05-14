APP := idp-auth-server
PKG := ./idp-auth-server
BFF_APP := bff
BFF_PKG := ./bff/cmd/bff
BIN_DIR := bin
BIN := $(BIN_DIR)/$(APP)
BFF_BIN := $(BIN_DIR)/$(BFF_APP)
KO_CONFIG_PATH ?= ./.ko.yaml
KO_IMPORTPATH ?= ./idp-auth-server
KO_BFF_IMPORTPATH ?= ./bff/cmd/bff
KO_DOCKER_REPO ?= ko.local
KO_TAGS ?= latest

.PHONY: help tidy fmt lint test build build-bff run run-bff container container-bff clean

help:
	@printf "Targets:\n"
	@printf "  make tidy   - tidy Go modules\n"
	@printf "  make fmt    - format Go source\n"
	@printf "  make lint   - run golangci-lint\n"
	@printf "  make test   - run unit tests\n"
	@printf "  make build  - build server binary\n"
	@printf "  make build-bff - build bff binary\n"
	@printf "  make run    - run server locally\n"
	@printf "  make run-bff - run bff locally\n"
	@printf "  make container - publish with ko\n"
	@printf "  make container-bff - publish bff with ko\n"
	@printf "  make clean  - remove build artifacts\n"

tidy:
	go mod tidy

fmt:
	gofmt -w idp-auth-server/*.go

lint:
	golangci-lint run ./...

test:
	go test ./...

build:
	mkdir -p $(BIN_DIR)
	go build -o $(BIN) $(PKG)

build-bff:
	mkdir -p $(BIN_DIR)
	go build -o $(BFF_BIN) $(BFF_PKG)

run:
	go run $(PKG)

run-bff:
	go run $(BFF_PKG)

container:
	KO_CONFIG_PATH=$(KO_CONFIG_PATH) KO_DOCKER_REPO=$(KO_DOCKER_REPO) ko publish --base-import-paths --tags="$(KO_TAGS)" "$(KO_IMPORTPATH)"

container-bff:
	KO_CONFIG_PATH=$(KO_CONFIG_PATH) KO_DOCKER_REPO=$(KO_DOCKER_REPO) ko publish --base-import-paths --tags="$(KO_TAGS)" "$(KO_BFF_IMPORTPATH)"

clean:
	rm -rf $(BIN_DIR)
