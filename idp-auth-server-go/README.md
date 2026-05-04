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

- `TEMPLATES_DIR` (default: `$KO_DATA_PATH/templates`)
  - Template/static directory used at runtime. Override this to select a bundled theme (for example `$KO_DATA_PATH/templates-ascii`) or point at a bind-mounted directory in containers.
- `KO_DATA_PATH` (default fallback for local runs: `idp-auth-server-go/kodata`)
  - Used to derive the default templates path when `TEMPLATES_DIR` is not set.
- `APP_PORT` (default: `5001`)
  - HTTP listen port.
- `IDP_EXTERNAL_URL` (default: `http://127.0.0.1:5001`)
  - Public issuer URL used in discovery and token `iss` claims.
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

## Templates in ko containers

The server loads templates from `TEMPLATES_DIR`.

- In ko-published images, templates are included from `idp-auth-server-go/kodata/templates` and available via `$KO_DATA_PATH/templates`.
- A second bundled ASCII theme is available at `idp-auth-server-go/kodata/templates-ascii` and can be selected with `TEMPLATES_DIR=$KO_DATA_PATH/templates-ascii`.
- To override templates at runtime, bind-mount a directory and set `TEMPLATES_DIR` to that mount path.

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
