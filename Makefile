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
IDP_URL ?= http://127.0.0.1:5001
CLIENT_METADATA_PORT ?= 9000
CLIENT_METADATA_DIR := $(BIN_DIR)/client-metadata

.PHONY: help tidy fmt lint test build build-bff run run-bff register-client serve-client-metadata container-idp container-bff containers clean

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
	@printf "  make register-client - register a demo client via RFC 7591 dynamic registration\n"
	@printf "  make serve-client-metadata - serve a demo client ID metadata document\n"
	@printf "  make container-idp - publish idp container with ko\n"
	@printf "  make container-bff - publish bff with ko\n"
	@printf "  make containers - publish idp and bff containers with ko\n"
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

# Dynamic client registration (RFC 7591) against a running IdP. The endpoint is
# open, so no credentials are needed. Override the target IdP with IDP_URL=...
register-client:
	curl -sS -X POST $(IDP_URL)/register \
	  -H 'Content-Type: application/json' \
	  -d '{"client_name":"demo-app","client_uri":"http://localhost:8080","redirect_uris":["http://localhost:8080/callback"],"grant_types":["authorization_code","refresh_token"],"response_types":["code"],"scope":"openid profile email offline_access","token_endpoint_auth_method":"client_secret_basic","contacts":["dev@example.com"]}'
	@printf "\nRegistered clients are listed at $(IDP_URL)/clients\n"

# Serve a demo client ID metadata document
# (draft-ietf-oauth-client-id-metadata-document-02), so that the URL below can be
# used directly as a client_id at /authorize. The document is generated rather
# than committed because its client_id must match the serving URL exactly, port
# included. This is a public client, so /authorize requires PKCE from it.
serve-client-metadata:
	mkdir -p $(CLIENT_METADATA_DIR)
	printf '{\n  "client_id": "http://127.0.0.1:$(CLIENT_METADATA_PORT)/client.json",\n  "client_name": "metadata-demo",\n  "client_uri": "http://localhost:8080",\n  "redirect_uris": ["http://localhost:8080/callback"],\n  "grant_types": ["authorization_code", "refresh_token"],\n  "response_types": ["code"],\n  "scope": "openid profile email offline_access",\n  "token_endpoint_auth_method": "none"\n}\n' > $(CLIENT_METADATA_DIR)/client.json
	@printf "Serving http://127.0.0.1:$(CLIENT_METADATA_PORT)/client.json - use that URL as client_id at $(IDP_URL)/authorize\n"
	cd $(CLIENT_METADATA_DIR) && python3 -m http.server $(CLIENT_METADATA_PORT) --bind 127.0.0.1

container-idp:
	KO_CONFIG_PATH=$(KO_CONFIG_PATH) KO_DOCKER_REPO=$(KO_DOCKER_REPO) ko publish --base-import-paths --tags="$(KO_TAGS)" "$(KO_IMPORTPATH)"

container-bff:
	KO_CONFIG_PATH=$(KO_CONFIG_PATH) KO_DOCKER_REPO=$(KO_DOCKER_REPO) ko publish --base-import-paths --tags="$(KO_TAGS)" "$(KO_BFF_IMPORTPATH)"

containers: container-idp container-bff

clean:
	rm -rf $(BIN_DIR)
