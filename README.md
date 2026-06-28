Go implementations of/inspired-by
[github.com/michaelvl/oidc-oauth2-workshop](https://github.com/michaelvl/oidc-oauth2-workshop),
[https://github.com/michaelvl/oidc-bff-apigw-workshop](https://github.com/michaelvl/oidc-bff-apigw-workshop)
and
[https://github.com/michaelvl/oidc-oauth2-bff](https://github.com/michaelvl/oidc-oauth2-bff).

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
- `PROTECT_PICTURE_URL` (default: `false`): when `true`, avatar endpoints
  (`/avatars/*.svg`) require `Authorization: Bearer <access_token>`.
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

TL;DR path routing:

```text
                      ┌─ /auth/login    ─┐
                      ├─ /auth/callback ─┤
Client ──► BFF ──┬──► ├─ /auth/logout    ├──► [internal OIDC/Oauth2]
                 │    ├─ /auth/me       ─┤
                 │    ├─ /auth/avatar   ─┤
                 │    └─ /healthz       ─┘
                 │
                 ├──► /assets/*    ┐
                 │    /login       ├─ (no session) ────► STATIC_ASSETS_BASE_URL/*
                 │    /favicon.ico ┘
                 │
                 ├──► /*  ────── (session required) ───► STATIC_ASSETS_BASE_URL/*
                 │
                 └──► API_PATH_PREFIX/* ── (session required) ──► API_BASE_URL/API_UPSTREAM_PATH_PREFIX/*
```

What it does:

- Runs Authorization Code + PKCE login flow (`/auth/login` -> IdP ->
  `/auth/callback`).
- Stores tokens in configurable session storage (cookie, Redis, or in-memory),
  never exposing them to browser JavaScript.
- Uses an HTTP-only session cookie and CSRF protection for authenticated browser
  traffic.
- Proxies API requests with injected bearer tokens and proxies static/SPA assets
  from a static upstream.

Request flows and path handling:

- Public paths (no session required):
  - `/assets/*` and `/favicon.ico`. These are forwarded to the application
    backend. Backend is configured with `STATIC_ASSETS_BASE_URL`
  - `/login` - this is forwarded to the application backend and is intended for
    serving a welcome/login page. When user requests login, the application
    backend should redirect to the BFFs `/auth/login` path.
  - `GET /auth/login`, `GET /auth/callback` - OIDC/Oauth2 initiation and
    callback
  - `/healthz` health endpoint for the BFF.
- Authenticated BFF paths (returns `401` when not logged in):
  - `GET /auth/me`returns OIDC claims. When a `picture` claim exists, its value
    is rewritten to the BFF-local avatar endpoint (`/auth/avatar`) so the SPA
    does not need to load IdP-origin image URLs directly.
  - `GET /auth/avatar` proxies the user's avatar from the upstream IdP using the
    current session access token or `404` if no picture claim exists.
- Protected SPA navigation: all other non-API routes (including `/`) require a
  valid BFF session; unauthenticated requests are redirected to `GET /login`.
- API proxy paths: `API_PATH_PREFIX` and `API_PATH_PREFIX/*` are
  reverse-proxied to `API_BASE_URL` with `Authorization: Bearer <access_token>`
  injected from the server-side session. The prefix defaults to `/api` and is
  configurable via `API_PATH_PREFIX`.
- CSRF-protected writes: non-GET/HEAD/OPTIONS requests to `API_PATH_PREFIX/*`
  and `POST /auth/logout` must include `X-CSRF-Token` matching the session CSRF
  token (set in the `csrf_token` cookie after login).

Unauthenticated user opening `/` and signing in:

```text
Browser            BFF (:8080)       Static Assets (:8082)   IdP (:5001)
   |                   |                      |                   |
   |-- GET / --------->| (no session)         |                   |
   |<- 303 /login -----|                      |                   |
   |                   |                      |                   |
   |-- GET /login ---->|                      |                   |
   |                   |-- GET /login ------->|                   |
   |<- 200 (welcome) --|<- 200 ---------------|                   |
   |                   |                      |                   |
   | (user clicks login button)               |                   |
   |-- GET /auth/login>|                      |                   |
   |<- 303 /authorize--|                      |                   |
   |                   |                      |                   |
   |-- GET /authorize ------------------------------------------->|
   |<- 200 (login form) ------------------------------------------|
   |                   |                      |                   |
   | (user submits credentials)               |                   |
   |-- POST /... ------------------------------------------------>|
   |<- 302 /auth/callback?code=... -------------------------------|
   |                   |                      |                   |
   |-- GET /auth/callback?code=...>|          |                   |
   |                   |-- POST /token -------------------------->|
   |                   |<- tokens --------------------------------|
   |                   | (create session, set session cookie,     |
   |                   |  set csrf_token cookie)                  |
   |<- 303 / ----------|                      |                   |
   |                   |                      |                   |
   |-- GET / --------->|                      |                   |
   |                   |-- GET / ------------>|                   |
   |<- 200 (app) ------|<- 200 ---------------|                   |
```

Checking auth state from the SPA (`GET /auth/me`):

```text
Browser/SPA       BFF (:8080)
   |                  |
   |-- GET /auth/me ->|
   |<- 200 {claims} --|  (when session is valid)
   |<- 401 -----------|  (when no valid session)
```

Authenticated API request through the BFF (`API_PATH_PREFIX/*`, default `/api/*`):

```text
Browser/SPA       BFF (:8080)         API (:8081)
   |                  |                   |
   |-- GET /api/data->|                   |
   |                  | (check session)   |
   |                  |-- GET /api/data ->|
   |                  |   Authorization: Bearer <access_token>
   |                  |<- 200 ------------|
   |<- 200 -----------|                   |
```

State-changing requests from the SPA (for example `POST /api/*` or
`POST /auth/logout`) must include `X-CSRF-Token` from the `csrf_token` cookie.

Security headers added by the BFF (all responses):

- `Strict-Transport-Security: max-age=63072000; includeSubDomains`
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Content-Security-Policy: default-src 'self'; script-src 'self'`
- `Referrer-Policy: strict-origin-when-cross-origin`

Architecture:

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
- `OIDC_SCOPES` (default: `openid profile email offline_access`):
  space-separated list of OAuth2 scopes to request. Omit `offline_access` to
  disable token refresh.
- `BFF_EXTERNAL_URL` (required): external base URL of the BFF (for example
  `http://localhost:8080`). The BFF derives its OAuth2 callback URL
  (`/auth/callback`) and post-logout redirect URL (`/login`) from this value.
- `SESSION_SECRET` (required): session signing/encryption secret, minimum 32
  bytes.
- `API_BASE_URL` (required): upstream API base URL for API proxying.
- `API_PATH_PREFIX` (default: `/api`): URL path prefix the BFF intercepts and
  reverse-proxies to `API_BASE_URL`. For example, set to `/graphql` if the
  upstream uses that path. Must start with `/`; trailing slashes are ignored.
- `API_UPSTREAM_PATH_PREFIX` (default: same as `API_PATH_PREFIX`): path prefix
  used when forwarding requests to `API_BASE_URL`. The BFF strips
  `API_PATH_PREFIX` from the inbound path and prepends this value. Set to `/`
  to strip the prefix entirely (e.g. inbound `/api/users` → upstream `/users`),
  or to a different value to remap (e.g. `API_PATH_PREFIX=/api`,
  `API_UPSTREAM_PATH_PREFIX=/v2` maps `/api/users` → `/v2/users`).
- `STATIC_ASSETS_BASE_URL` (required): upstream static assets base URL for
  non-API routes.
- `SESSION_COOKIE_NAME` (default: `session`): cookie name for the BFF session.
- `SESSION_STORAGE_TYPE` (default: `memory`): session storage backend. Accepted
  values:
  - `memory` — in-process store; sessions are lost on restart and cannot be
    shared across replicas.
  - `redis` — Redis-backed store; requires `REDIS_URL`. Supports multiple
    replicas and survives restarts.
  - `cookie` — the full session is AES-256-GCM encrypted (using `SESSION_SECRET`
    as the key source) and stored directly in the browser cookie. No server-side
    state is required, making this suitable for stateless deployments, but the
    cookie size grows with token sizes (~1–2 KB typical). Tokens larger than
    ~3900 bytes after encryption will return an error; switch to a server-side
    backend in that case.
- `REDIS_URL` (default: empty): Redis connection URL (for example
  `redis://127.0.0.1:6379`). Required when `SESSION_STORAGE_TYPE=redis`.
- `INSECURE_COOKIES` (default: `false`): if `true`, disables `Secure` on cookies
  for local HTTP development.
- `CONTENT_SECURITY_POLICY` (default: `default-src 'self'; script-src 'self'`):
  overrides the BFF `Content-Security-Policy` response header value.
- `PORT` (default: `8080`): BFF listen port.
