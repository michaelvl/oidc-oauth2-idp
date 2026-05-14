Go implementation of
[github.com/michaelvl/oidc-oauth2-workshop](https://github.com/michaelvl/oidc-oauth2-workshop)

This repository contains two standalone components:

- `idp-auth-server`: an educational OAuth2/OIDC Identity Provider (IdP) with login, consent, token, UserInfo, discovery, JWKS, and logout endpoints.
- `bff`: a Backend-for-Frontend (BFF) that handles OIDC login/logout for browser clients, stores tokens in server-side sessions, and proxies API/static traffic.

## Components

### IdP (`idp-auth-server`)

The IdP runs independently and issues OAuth2/OIDC tokens. It serves HTML templates for authentication and consent and exposes OIDC metadata endpoints.

Environment variables:

- `APP_PORT` (default: `5001`): HTTP listen port.
- `IDP_EXTERNAL_URL` (default: `http://127.0.0.1:5001`): issuer/external base URL used in discovery and token claims.
- `EXTRA_AUDIENCES` (default: empty): comma-separated additional audiences accepted for access tokens.
- `ACCESS_TOKEN_LIFETIME` (default: `1200`): access token lifetime in seconds.
- `REFRESH_TOKEN_LIFETIME` (default: `3600`): refresh token lifetime in seconds.
- `TEMPLATES_DIR` (default: `$KO_DATA_PATH/templates`): path to HTML/CSS template assets.
- `KO_DATA_PATH` (default: `idp-auth-server/kodata`): base asset path used to resolve template defaults.

### BFF (`bff`)

The BFF runs independently from the IdP and can be wired to any compatible OIDC provider. It performs Authorization Code + PKCE, keeps tokens server-side, sets HTTP-only cookies, and forwards authenticated API requests.

Environment variables:

- `OIDC_ISSUER_URL` (required): OIDC issuer URL.
- `OIDC_CLIENT_ID` (required): OIDC client ID.
- `OIDC_CLIENT_SECRET` (required): OIDC client secret.
- `OIDC_REDIRECT_URI` (required): callback URL handled by the BFF (for example `http://localhost:8080/auth/callback`).
- `SESSION_SECRET` (required): session signing/encryption secret, minimum 32 bytes.
- `API_BASE_URL` (required): upstream API base URL for `/api/*` proxying.
- `STATIC_ASSETS_BASE_URL` (required): upstream static assets base URL for non-API routes.
- `SESSION_COOKIE_NAME` (default: `session`): cookie name for the BFF session.
- `REDIS_URL` (default: empty): Redis URL for shared session storage; if unset, in-memory sessions are used.
- `ACCESS_TOKEN_AUD` (default: empty): access token audience value (reserved/optional).
- `INSECURE_COOKIES` (default: `false`): if `true`, disables `Secure` on cookies for local HTTP development.
- `PORT` (default: `8080`): BFF listen port.
