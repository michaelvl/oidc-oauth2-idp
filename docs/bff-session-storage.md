# BFF Session Storage

The BFF supports three session storage backends, selected via the
`SESSION_STORAGE_TYPE` environment variable. All backends share the same
external interface: a single `HttpOnly`, `SameSite=Lax` cookie named by
`SESSION_COOKIE_NAME` (default: `session`) with a 24-hour TTL. The `Secure` flag
is set by default and should only be disabled via `INSECURE_COOKIES=true` when
running over plain HTTP in local development.

The session holds:

| Field               | Description                                       |
| ------------------- | ------------------------------------------------- |
| `AccessToken`       | OAuth2 access token                               |
| `RefreshToken`      | OAuth2 refresh token                              |
| `IDToken`           | Raw JWT ID token                                  |
| `CSRFToken`         | CSRF protection token                             |
| `AccessTokenExpiry` | When the access token expires (from `expires_in`) |

## Token Refresh

On every proxied API request (`/api/*`), the BFF checks whether the access token
is expired or within **60 seconds** of expiry. If so, and a refresh token is
present, the BFF calls the IdP's token endpoint with `grant_type=refresh_token`
before forwarding the request.

| Condition                                                                     | Result                                                                                            |
| ----------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------- |
| Token valid, not near expiry                                                  | Request forwarded unchanged                                                                       |
| Token within 60s of expiry, refresh succeeds                                  | New tokens stored, session cookie re-issued (rolling 24h TTL), request forwarded with fresh token |
| Token within 60s of expiry, refresh fails                                     | Warning logged; request forwarded with existing token (still valid)                               |
| Token already expired, refresh succeeds                                       | New tokens stored, session cookie re-issued, request forwarded with fresh token                   |
| Token already expired, refresh fails                                          | Session destroyed, `401` returned — browser must re-login                                         |
| `AccessTokenExpiry` is zero (sessions predating this field, dev memory store) | No refresh attempted                                                                              |

If the IdP returns a new refresh token (rotation), it replaces the stored one.
If the IdP returns a new ID token in the refresh response, it also replaces the
stored one.

The session cookie TTL resets to 24 hours on every successful refresh, giving a
rolling session lifetime as long as the user is active.

---

## Memory (development only)

**`SESSION_STORAGE_TYPE=memory`** (default)

Session data is stored in an in-process map. The cookie contains a random
43-character opaque token that acts as a lookup key.

This backend is **not suitable for production**:

- Sessions are lost on process restart.
- Cannot be shared across multiple BFF replicas.
- No persistence or durability guarantees.

Use it for local development where simplicity matters more than correctness.

---

## Redis

**`SESSION_STORAGE_TYPE=redis`**

Required additional config: `REDIS_URL` (e.g. `redis://localhost:6379/0`).

This backend uses a split-key design modelled on. The cookie value has the form:

```
<tokenID>.<secret>
```

- **`tokenID`** — a 32-byte random identifier, base64url-encoded; used to
  construct the Redis key
- **`secret`** — a 32-byte per-session AES-256-GCM encryption key,
  base64url-encoded

The Redis key is `{SESSION_COOKIE_NAME}-{tokenID}`, namespacing all sessions
under the configured cookie name. This means multiple BFF instances protecting
different applications can share a single Redis without their sessions
colliding.

The session JSON is encrypted with the per-session `secret` before being written
to Redis. The secret never touches the server — it only lives in the user's
browser cookie.

### Security properties

Neither side alone is sufficient to read a session:

| Where          | What is stored                     | What is absent     |
| -------------- | ---------------------------------- | ------------------ |
| Browser cookie | `tokenID` + encryption key         | The ciphertext     |
| Redis          | AES-256-GCM encrypted session blob | The decryption key |

An attacker who fully compromises Redis obtains only ciphertext with no keys. An
attacker who steals a cookie still needs Redis to obtain the ciphertext. Both
are required.

Each session has its own unique encryption key, so compromise of one session
does not expose others.

This backend supports multiple replicas and survives process restarts.

---

## Cookie

**`SESSION_STORAGE_TYPE=cookie`**

The entire session is AES-256-GCM encrypted using a key derived from
`SESSION_SECRET` (SHA-256 hash) and stored directly in the browser cookie. No
server-side storage is used.

### Cookie size

Browsers enforce a ~4096-byte limit per cookie. The encrypted session payload —
which includes the access token, refresh token, and ID token — easily reaches or
exceeds this. The BFF enforces a hard limit of **3900 bytes** on the encoded
cookie value and returns an error if it is exceeded.

In practice, the `cookie` backend is only viable when all tokens are short. If
the IdP issues large JWTs (e.g. tokens with many claims or embedded roles), the
session will exceed the limit and logins will fail. Use the `redis` backend when
token size is a concern.

### Security properties

Because the encryption key is the same for all sessions (derived from
`SESSION_SECRET`), there is no per-session key isolation: anyone who knows the
secret can decrypt any session cookie. The secret must be kept confidential and
rotated if compromised. Rotating the secret immediately invalidates all existing
sessions.

