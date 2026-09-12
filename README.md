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

The IdP is a self-contained OAuth2/OIDC authorization server for local
development and workshops. It owns the authentication UI (the login, consent and
logout pages), issues JWT access tokens plus ID and refresh tokens, and publishes
the discovery and JWKS metadata that clients and resource servers read to
validate tokens and find endpoints.

Warning: this IdP is deliberately permissive. It accepts any username and one
fixed password (`valid`). Do not use it for production or anywhere real
authentication guarantees matter.

One process serves both the browser pages and the protocol endpoints:
`/authorize`, `/token`, `/userinfo`, `/.well-known/openid-configuration` and
`/.well-known/jwks.json`.

Clients live in an in-memory registry holding RFC 7591 client metadata
(`redirect_uris`, `grant_types`, `response_types`, `scope`, ...). Every
registration also carries a non-standard `registration_method` field recording
how it came about:

- `automatic`: the client never asked to be registered. The first time a
  `client_id` appears at `/authorize`, the IdP synthesizes a registration from
  the request, and later requests merge in newly observed redirect URIs and
  scopes. Such a registration records `token_endpoint_auth_method: none`, because
  the IdP holds no secret for the client and never sees how it authenticates.
- `dynamic`: the client registered itself at `/register` using RFC 7591 dynamic
  client registration. Self-registered metadata is authoritative, and traffic
  at `/authorize` never widens it.
- `client_id_metadata_document`: the `client_id` is a URL that the IdP fetched to
  read the client's own metadata document, per
  [draft-ietf-oauth-client-id-metadata-document-02](https://www.ietf.org/archive/id/draft-ietf-oauth-client-id-metadata-document-02.txt).
  There is no registration call and no pre-shared secret; the document is
  authoritative, and the IdP re-fetches it when its cache entry expires.

The IdP enforces client authentication at `/token` for the latter two methods
only.

`/` lists active sessions and `/clients` lists the client registrations.

#### Dynamic client registration (`POST /register`)

The registration endpoint is open. It needs no initial access token, in keeping
with the rest of this IdP. The discovery document advertises it as
`registration_endpoint`. Post RFC 7591 client metadata and get back the
registration with a server-assigned `client_id`; the IdP ignores any
client-supplied `client_id`, `client_secret` or `registration_method`.

```sh
make register-client                      # against http://127.0.0.1:5001
make register-client IDP_URL=http://host  # against another IdP
```

Metadata defaults follow RFC 7591: `grant_types` defaults to
`["authorization_code"]`, `response_types` to `["code"]` and
`token_endpoint_auth_method` to `client_secret_basic`. The IdP issues a
`client_secret` with `client_secret_expires_at: 0`, meaning it never expires,
unless the client registers with `token_endpoint_auth_method: none`. It rejects a
registration with HTTP 400 and an RFC 7591 error, `invalid_client_metadata` or
`invalid_redirect_uri`, for malformed JSON, an unsupported grant type, response
type or auth method, a missing `redirect_uris` on the `authorization_code` grant,
or a redirect URI that is relative or carries a fragment.

#### Client ID metadata documents

A `client_id` that is a URL gets dereferenced. The IdP fetches it, expects a JSON
client metadata document, and registers the client from what it reads. Such a
client never calls `/register` and never gets a secret. It publishes its own
metadata at a stable URL and authenticates at `/token` with `private_key_jwt` or
with PKCE alone. The discovery document advertises this as
`client_id_metadata_document_supported: true`.

The IdP treats a `client_id` as a Client Identifier URL when it uses the `https`
scheme (or `http`, see below), has a host and a path, and carries no userinfo
component, no `.` or `..` path segments and no fragment. A query component is
allowed but logged at `Warn`. Anything else, such as a UUID or an opaque name,
falls through to automatic registration.

Comparison is string-based, per RFC 3986 section 6.2.1. The document's `client_id`
must equal the URL it was fetched from character for character, so
`https://ex.com/c` and `https://ex.com:443/c` are two different clients.

A minimal document:

```json
{
  "client_id": "http://127.0.0.1:9000/client.json",
  "client_name": "demo-app",
  "redirect_uris": ["http://localhost:8080/callback"],
  "grant_types": ["authorization_code"],
  "response_types": ["code"],
  "scope": "openid profile email",
  "token_endpoint_auth_method": "private_key_jwt",
  "jwks": {"keys": [{"kty": "RSA", "kid": "key-1", "use": "sig", "alg": "RS256", "n": "...", "e": "AQAB"}]}
}
```

```sh
make serve-client-metadata                          # http://127.0.0.1:9000/client.json
make serve-client-metadata CLIENT_METADATA_PORT=9100
```

The IdP rejects the document, and aborts the authorization request, if its
`client_id` is missing or does not match, if it carries a `client_secret` or
`client_secret_expires_at`, if `token_endpoint_auth_method` is anything other than
`none` (the default) or `private_key_jwt`, if it declares `private_key_jwt`
without a `jwks` or `jwks_uri`, or if it fails any of the RFC 7591 checks
`/register` applies. Unknown members are ignored, so a document may carry metadata
this IdP does not model.

**Fetching.** A `GET` with `Accept: application/json`. The response must be
exactly `200` with a JSON content type (`application/json` or any `*+json`) and at
most 5120 bytes. An oversized body is an error, not a truncation. The IdP does not
follow redirects. A `jwks_uri` goes through the same client and the same cap.

**SSRF protection.** The check runs on the resolved IP about to be dialed, not on
the hostname, which DNS rebinding would defeat. The blocked set is the RFC 6890
special-use ranges: loopback, private, link-local, multicast, unspecified, plus
`100.64.0.0/10`,
`192.0.0.0/24`, `192.0.2.0/24`, `198.18.0.0/15`, `198.51.100.0/24`,
`203.0.113.0/24`, `240.0.0.0/4`, `255.255.255.255/32`, `::/128`, `100::/64` and
`2001:db8::/32`. Loopback, and loopback alone, is allowed while the IdP itself
sits on a loopback address, which is what the `IDP_EXTERNAL_URL` default
`http://127.0.0.1:5001` means. Deploy with a real external URL and that exception
closes itself; every other range stays blocked either way.

**Caching.** The IdP caches documents per client ID URL. A `Cache-Control:
max-age=N` sets the lifetime, clamped to between 60 seconds and 24 hours; without
a usable cache header, `CLIENT_ID_METADATA_TTL` applies. Error responses and
malformed documents are never cached. Refresh is lazy. The next `/authorize` after
expiry re-fetches, and the client's JWK set is dropped along with its document, so
a key rotation lands on that refresh.

**`redirect_uri` enforcement.** The draft makes exact-match registration
mandatory, so `/authorize` now checks `redirect_uri` by exact string match against
the registration for both `client_id_metadata_document` and `dynamic` clients. A
mismatch renders an error page and is never redirected to, since redirecting to
an unregistered URI is the exact thing this check prevents. Warning: this is a
behaviour change for existing dynamically registered clients. A `redirect_uri`
that does not match one they registered now fails where it used to work.
`automatic` registrations are still unenforced, because their `redirect_uris` are
only observed traffic rather than anything the client asserted.

A metadata document client that declares `token_endpoint_auth_method: none` must
send a `code_challenge`. With neither a secret nor PKCE, nothing binds the
authorization code to it.

#### Client authentication at `/token`

A client must authenticate with the method it registered. A dynamically
registered client uses `client_secret_basic` (HTTP Basic) or `client_secret_post`
(a `client_secret` form field). A client registered from a client ID metadata
document uses `private_key_jwt`: an RFC 7523 assertion sent as
`client_assertion`, with `client_assertion_type:
urn:ietf:params:oauth:client-assertion-type:jwt-bearer`. The wrong secret, the
wrong method or credentials for a different client all get HTTP 401 and
`invalid_client`. Clients registered with `token_endpoint_auth_method: none` are
public, and PKCE is their only binding to the authorization code.

An assertion must carry `iss` and `sub` equal to the client ID URL, an `aud`
containing the token endpoint (the issuer URL is accepted too, since many client
libraries send that), an `exp` that is in the future and no more than 10 minutes
out, and a `jti` that has not been seen before. The IdP verifies it against a key
from the client's published JWK set, either an inline `jwks` or a `jwks_uri`
fetched through the same SSRF-guarded client and size cap, picking the key by
`kid` when the header carries one. `alg: none` and every HMAC algorithm are
rejected; the advertised signing algorithms are `RS256` and `ES256`. Seen `jti`
values live in memory until their assertions expire, so they do not survive a
restart, like the rest of this IdP's state.

`private_key_jwt` is advertised in discovery but is not accepted at `/register`:
that endpoint has no way to learn a client's public keys.

The client identity that is checked comes from server-side state (the
authorization code or refresh token), never from a `client_id` in the request.

Warning: registration is only partly enforced. Automatically registered and
entirely unknown clients are still served at `/token` with no client
authentication at all, since there is no secret to compare, so a leaked code or
refresh token is enough. `/authorize` still accepts unknown clients, and an
`automatic` registration still accepts a redirect URI that does not match it. The
`/clients` page shows issued client secrets in full, with no authentication.

Warning: a client ID metadata document may be served over plain `http`, which the
draft forbids. It is allowed here because clients under local development serve
their document over HTTP on localhost, and requiring TLS would mean a terminating
proxy for every demo. The relaxation is unconditional, gated by no environment
variable. Over cleartext the document, including the `jwks` that client
authentication rests on, is neither confidential nor integrity-protected in
transit. Anyone on the path can swap in their own keys and impersonate the client.
Do not carry this into anything resembling production.

Environment variables:

- `PORT` (default: `5001`): HTTP listen port.
- `IDP_EXTERNAL_URL` (default: `http://127.0.0.1:5001`): issuer/external base
  URL used in discovery and token claims.
- `PROTECT_PICTURE_URL` (default: `false`): when `true`, avatar endpoints
  (`/avatars/*.svg`) require `Authorization: Bearer <access_token>`.
- `EXTRA_AUDIENCES` (default: empty): comma-separated additional audiences
  accepted for access tokens.
- `EMAIL_DOMAIN` (default: `example.com`): domain used to synthesize the `email`
  claim as `<username>@<EMAIL_DOMAIN>`. The `email` and `email_verified` claims
  are added to the ID token and `/userinfo` response when the request includes
  the `email` scope.
- `ACCESS_TOKEN_LIFETIME` (default: `1200`): access token lifetime in seconds.
- `REFRESH_TOKEN_LIFETIME` (default: `3600`): refresh token lifetime in seconds.
- `CLIENT_ID_METADATA_FETCH_TIMEOUT` (default: `5`): timeout in seconds for
  fetching a client ID metadata document or a `jwks_uri`.
- `CLIENT_ID_METADATA_TTL` (default: `900`): how long in seconds a fetched client
  ID metadata document is cached when the response carries no usable
  `Cache-Control: max-age`. The 5 KB size cap, the 60 second to 24 hour clamp on
  a document-supplied `max-age`, and the loopback fetch allowance derived from
  `IDP_EXTERNAL_URL` are not configurable.
- `SUBJECT_TYPE` (default: `public`): subject identifier type, `public` or
  `pairwise`. In public mode every RP receives the same `sub` for a given user.
  In pairwise mode each RP receives a different, opaque `sub` derived from the
  RP's sector identifier (the host component of its `redirect_uri`), so RPs
  cannot correlate users across sites.
- `PAIRWISE_SALT` (required when `SUBJECT_TYPE=pairwise`): hex-encoded HMAC
  secret (minimum 16 bytes / 32 hex characters) used to derive pairwise subject
  identifiers. Example: `PAIRWISE_SALT=$(openssl rand -hex 32)`.
- `TEMPLATES_DIR` (default: `$KO_DATA_PATH/templates`): path to HTML/CSS
  template assets.
- `KO_DATA_PATH` (default: `idp-auth-server/kodata`): base asset path used to
  resolve template defaults.

### BFF (`bff`)

The BFF is a browser-facing gateway between the SPA and the backend services. It
runs independently of the IdP, and you can point it at any compatible OIDC issuer.
The browser only ever talks to the BFF origin; the BFF handles login and sessions
and forwards everything else upstream.

#### TL;DR path routing

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

#### What it does

- Runs Authorization Code + PKCE login flow (`/auth/login` -> IdP ->
  `/auth/callback`).
- Stores tokens in configurable session storage (cookie, Redis, or in-memory),
  never exposing them to browser JavaScript.
- Uses an HTTP-only session cookie and CSRF protection for authenticated browser
  traffic.
- Proxies API requests with injected bearer tokens and proxies static/SPA assets
  from a static upstream.

#### Request flows and path handling

- Public paths (no session required): controlled by `AUTH_BYPASS_PATHS` (see
  environment variables). The default set is:
  - `/assets/*` and `/favicon.ico`. These are forwarded to the application
    backend. Backend is configured with `STATIC_ASSETS_BASE_URL`
  - `/login` - this is forwarded to the application backend and is intended for
    serving a welcome/login page. When user requests login, the application
    backend should redirect to the BFFs `/auth/login` path.
  - `GET /auth/login`, `GET /auth/callback` - OIDC/Oauth2 initiation and
    callback
  - `/healthz` health endpoint for the BFF.
- Authenticated BFF paths (returns `401` when not logged in):
  - `GET /auth/me` returns OIDC claims from the current session's ID token.
    Response is `200 application/json` with the fields below, or `401` when no
    valid session exists, or `500` on an internal error.

    | Field     | Type   | Required | Notes                                                          |
    | --------- | ------ | -------- | -------------------------------------------------------------- |
    | `sub`     | string | yes      | Subject identifier, always present (required by OIDC)          |
    | `name`    | string | no       | Full display name, present only if the IdP includes it         |
    | `email`   | string | no       | Email address, present only if the IdP includes it             |
    | `picture` | string | no       | Rewritten to `/auth/avatar`; absent if the IdP omits the claim |

  - `GET /auth/avatar` proxies the user's avatar from the upstream IdP using the
    current session access token or `404` if no picture claim exists.
- Protected SPA navigation: all routes not matched by `AUTH_BYPASS_PATHS` or the
  API prefix require a valid BFF session; unauthenticated requests are redirected
  to `GET /login`. Set `AUTH_BYPASS_PATHS=/*` to make static assets fully public.
- API proxy paths: `API_PATH_PREFIX` and `API_PATH_PREFIX/*` are reverse-proxied
  to `API_BASE_URL` with `Authorization: Bearer <access_token>` injected from
  the server-side session. The prefix defaults to `/api` and is configurable via
  `API_PATH_PREFIX`.
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

Authenticated API request through the BFF (`API_PATH_PREFIX/*`, default
`/api/*`):

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

#### Security headers added by the BFF (all responses)

- `Strict-Transport-Security: max-age=63072000; includeSubDomains`
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Content-Security-Policy: default-src 'self'; script-src 'self'`
- `Referrer-Policy: strict-origin-when-cross-origin`

#### Architecture

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

#### Processing middlewares

| # | Middleware        | What it does                                                                                                                                                                                 |
| - | ----------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1 | `RequestLogger`   | Logs method, path, status code, duration, and remote address for every request                                                                                                               |
| 2 | `Recovery`        | Catches panics and returns a 500 JSON error                                                                                                                                                  |
| 3 | `SecurityHeaders` | Adds HSTS, `X-Content-Type-Options`, `X-Frame-Options`, CSP, and `Referrer-Policy` to every response                                                                                         |
| 4 | `AuthGuard`       | Redirects unauthenticated requests to `/login` for any path not in `AUTH_BYPASS_PATHS` and not the API prefix. The API prefix is always passed through here; `TokenForwarder` handles API auth independently with a 401. |
| 5 | `CSRFMiddleware`  | Validates `X-CSRF-Token` on non-GET/HEAD/OPTIONS requests to `/api/*` and `/auth/logout`; rejects with 403 on mismatch                                                                       |
| 6 | `TokenForwarder`  | For `/api/*`: reads the session, proactively refreshes the token if near expiry, injects `Authorization: Bearer <token>` into the upstream request, and returns 401 if no valid token exists |

#### Environment variables

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
  `API_PATH_PREFIX` from the inbound path and prepends this value. Set to `/` to
  strip the prefix entirely (e.g. inbound `/api/users` → upstream `/users`), or
  to a different value to remap (e.g. `API_PATH_PREFIX=/api`,
  `API_UPSTREAM_PATH_PREFIX=/v2` maps `/api/users` → `/v2/users`).
- `STATIC_ASSETS_BASE_URL` (required): upstream static assets base URL for
  non-API routes.
- `SESSION_COOKIE_NAME` (default: `session`): cookie name for the BFF session.
- `SESSION_STORAGE_TYPE` (default: `memory`): session storage backend. Accepted
  values:
  - `memory`: in-process store. Sessions are lost on restart and cannot be
    shared across replicas.
  - `redis`: Redis-backed store, requires `REDIS_URL`. Supports multiple
    replicas and survives restarts.
  - `cookie`: the full session is AES-256-GCM encrypted, keyed from
    `SESSION_SECRET`, and stored in the browser cookie itself. It needs no
    server-side state, which suits stateless deployments, but the cookie grows
    with the tokens it holds, typically 1 to 2 KB. Tokens over roughly 3900
    bytes after encryption return an error; use a server-side backend instead.
- `REDIS_URL` (default: empty): Redis connection URL (for example
  `redis://127.0.0.1:6379`). Required when `SESSION_STORAGE_TYPE=redis`.
- `AUTH_BYPASS_PATHS` (default: `/auth/ /assets/ /login /healthz /favicon.ico`):
  space-separated list of path prefixes that `AuthGuard` lets through without a
  session check. A trailing `*` is stripped (e.g. `/*` is treated as `/`), so
  `/*` makes all non-API paths public, which is what you want when the static
  assets should be reachable without login while the API stays protected.
- `INSECURE_COOKIES` (default: `false`): if `true`, disables `Secure` on cookies
  for local HTTP development.
- `CONTENT_SECURITY_POLICY` (default: `default-src 'self'; script-src 'self'`):
  overrides the BFF `Content-Security-Policy` response header value.
- `PORT` (default: `8080`): BFF listen port.
