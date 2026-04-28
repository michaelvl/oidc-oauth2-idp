# idp-auth-server-go

Go implementation of the educational OIDC/OAuth2 Identity Provider from the
`oidc-oauth2-workshop` Python server, kept intentionally close to the original
flow and behavior.

## Run locally

From repo root:

```bash
make run
```

The server listens on `0.0.0.0:5001` by default.

## Useful URLs

- Index: `http://127.0.0.1:5001/`
- Discovery: `http://127.0.0.1:5001/.well-known/openid-configuration`
- JWKS: `http://127.0.0.1:5001/.well-known/jwks.json`
- Start auth flow (shows login page):

```text
http://127.0.0.1:5001/authorize?client_id=my-client&scope=openid+profile&redirect_uri=http://localhost:8080/callback&state=somestate
```

Login accepts any username and requires password `valid`.

## Environment variables

- `JWT_KEY` (default: `jwt-key`)
  - File path prefix used for generated RSA keys (`jwt-key` and `jwt-key.pub`).
- `APP_PORT` (default: `5001`)
  - HTTP listen port.
- `IDP_EXTERNAL_URL` (default: `http://127.0.0.1:5001`)
  - Public issuer URL used in discovery and token `iss` claims.
- `IDP_INTERNAL_URL` (default: value of `IDP_EXTERNAL_URL`)
  - Internal URL accepted in audience checks and included in token audiences.
- `API_BASE_URL` (default: `http://127.0.0.1:5002/api`)
  - API audience used when issuing access tokens.
- `ACCESS_TOKEN_LIFETIME` (default: `1200`)
  - Access token lifetime in seconds.
- `REFRESH_TOKEN_LIFETIME` (default: `3600`)
  - Refresh token lifetime in seconds.

## Development commands

From repo root:

- `make fmt` - format Go files
- `make lint` - run golangci-lint
- `make test` - run unit tests
- `make build` - build binary to `bin/idp-auth-server-go`
- `make container` - publish container image with `ko`
  - Defaults to `KO_DOCKER_REPO=ko.local`

## Container publishing

Container publishing uses `ko` and `.ko.yaml`.

Default local publish:

```bash
make container
```

Publish to a remote registry:

```bash
KO_DOCKER_REPO=ghcr.io/<owner>/<repo> KO_TAGS=latest,<sha> make container
```
