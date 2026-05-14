Go implementation of
[github.com/michaelvl/oidc-oauth2-workshop](https://github.com/michaelvl/oidc-oauth2-workshop)

This repository contains two standalone components:

- `idp-auth-server`: an educational OAuth2/OIDC Identity Provider (IdP) with
  login, consent, token, UserInfo, discovery, JWKS, and logout endpoints.
- `bff`: a Backend-for-Frontend (BFF) that handles OIDC login/logout for browser
  clients, stores tokens in server-side sessions, and proxies API/static
  traffic.

## Components

### IdP (`idp-auth-server`)

The IdP is a self-contained OAuth2/OIDC authorization server intended for local
development, demos, and workshop-style flows. It owns the authentication UI
(login, consent, logout pages), issues JWT access tokens plus ID/refresh tokens,
and exposes discovery/JWKS metadata that clients and resource servers use to
validate tokens and discover endpoints.

⚠️ This IdP is intentionally permissive for demo/testing use. It accepts any
username and uses a fixed password (`valid`) in the login flow. Do not use it
for production or any environment where real authentication guarantees are
required.

At runtime, it serves both browser-facing pages and protocol endpoints from one
process, including `/authorize`, `/token`, `/userinfo`,
`/.well-known/openid-configuration`, and `/.well-known/jwks.json`.

Environment variables:

- `PORT` (default: `5001`): HTTP listen port.
- `IDP_EXTERNAL_URL` (default: `http://127.0.0.1:5001`): issuer/external base
  URL used in discovery and token claims.
- `EXTRA_AUDIENCES` (default: empty): comma-separated additional audiences
  accepted for access tokens.
- `ACCESS_TOKEN_LIFETIME` (default: `1200`): access token lifetime in seconds.
- `REFRESH_TOKEN_LIFETIME` (default: `3600`): refresh token lifetime in seconds.
- `TEMPLATES_DIR` (default: `$KO_DATA_PATH/templates`): path to HTML/CSS
  template assets.
- `KO_DATA_PATH` (default: `idp-auth-server/kodata`): base asset path used to
  resolve template defaults.

### BFF (`bff`)

The BFF is a browser-facing gateway that sits between the SPA and backend
services. It runs independently from the IdP and can be configured against any
compatible OIDC issuer. The browser talks only to the BFF origin; the BFF
handles login/session concerns and forwards requests to upstream services.

What it does:

- Runs Authorization Code + PKCE login flow (`/auth/login` -> IdP ->
  `/auth/callback`).
- Stores tokens server-side in session storage (Redis or in-memory fallback),
  not in browser JavaScript.
- Uses an HTTP-only session cookie and CSRF protection for authenticated browser
  traffic.
- Proxies API requests with injected bearer tokens and proxies static/SPA assets
  from a static upstream.

Paths and proxy behavior:

- `GET /auth/login`: starts OIDC login by redirecting to the configured issuer.
- `GET /auth/callback`: receives the authorization code, exchanges tokens,
  creates the BFF session.
- `POST /auth/logout`: destroys session and returns logout redirect target.
- `GET /auth/me`: returns current authenticated user claims from server-side
  session.
- `/api` and `/api/*`: reverse-proxied to `API_BASE_URL` with
  `Authorization: Bearer <access_token>` injected from session.
- `/` and non-API paths: reverse-proxied to `STATIC_ASSETS_BASE_URL` (SPA/static
  assets).

ASCII architecture:

```text
Browser (SPA)
     |
     | 1) /auth/login, /auth/callback, /auth/me, /api/*, /
     v
+-------------------+
| BFF (:8080)       |
| - session cookie  |
| - CSRF checks     |
| - token refresh   |
+-------------------+
   |            |
   | 2) OIDC    | 3) API + static-assets proxy
   v            v
+-----------+  +----------------+
| IdP       |  | Upstream apps  |
| (:5001)   |  | API (:8081)    |
| /authorize|  | Static (:8082) |
| /token    |  +----------------+
+-----------+
```

Environment variables:

- `OIDC_ISSUER_URL` (required): OIDC issuer URL.
- `OIDC_CLIENT_ID` (required): OIDC client ID.
- `OIDC_CLIENT_SECRET` (required): OIDC client secret.
- `OIDC_REDIRECT_URI` (required): callback URL handled by the BFF (for example
  `http://localhost:8080/auth/callback`).
- `SESSION_SECRET` (required): session signing/encryption secret, minimum 32
  bytes.
- `API_BASE_URL` (required): upstream API base URL for `/api/*` proxying.
- `STATIC_ASSETS_BASE_URL` (required): upstream static assets base URL for
  non-API routes.
- `SESSION_COOKIE_NAME` (default: `session`): cookie name for the BFF session.
- `REDIS_URL` (default: empty): Redis URL for shared session storage; if unset,
  in-memory sessions are used.
- `ACCESS_TOKEN_AUD` (default: empty): access token audience value
  (reserved/optional).
- `INSECURE_COOKIES` (default: `false`): if `true`, disables `Secure` on cookies
  for local HTTP development.
- `PORT` (default: `8080`): BFF listen port.
