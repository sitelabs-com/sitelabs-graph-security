<!-- menu -->
[Overview](overview.md) · [Callers](keys.md) · **Protections** · [Using it](fastapi.md) · [References](index.md)

**Protections:** **Admin login** · [Rate limits](rate-limits.md) · [TLS between servers](internal-tls.md)
<!-- /menu -->

# Admin login

> **For:** whoever runs a server's admin endpoints, and developers of a client. **You'll find:** why
> an admin key alone isn't enough, the challenge, the token, the lockout, the settings, computing an
> answer, and what it doesn't protect against.

An application's admin permissions (destroying data, changing the cluster) need a **login** as well
as an admin role. The login proves the caller holds an admin key without the key crossing the
network, and gives a short-lived token.

## The challenge

```
client                                             server
  │  GET /admin/challenge                               │
  │◄──────────────── {"nonce": "9f2c41...", "expires_in": 60}
  │                                                     │
  │  client = sha256(key)                               │
  │  hash   = sha256(client)     (the key's entry's)    │
  │  response = client XOR HMAC-SHA256(hash, nonce), hex│
  │  POST /admin/login {"nonce", "response"}            │
  │◄──────────────── {"token": "q8Zr...", "expires_in": 900}
  │                                                     │
  │  an admin call                                      │
  │  Authorization: Bearer q8Zr...                      │
```

* **A key alone doesn't reach an admin endpoint.** An admin's key works like a write key on the
  others; the admin endpoints need the token.
* **The answer is SCRAM's** (RFC 5802). The server computes the HMAC from the hash it holds, recovers
  `client`, and checks that its SHA-256 is the hash. So answering takes `sha256(key)`, which the entry
  doesn't give away: **a stolen `API_KEYS` can't log in.**
* **A nonce is used once:** it is gone after one answer, right or wrong, and after
  `ADMIN_CHALLENGE_SECONDS`. A captured answer can't be replayed.

## The token

* **It names the key that logged in and when it expires** (`ADMIN_TOKEN_SECONDS`), signed with
  `SESSION_SECRET` (HMAC-SHA256). The server keeps nothing of it, so it holds across a restart, and
  at every server with the same secret.
* **It works only while its key does:** removing or replacing the key in `API_KEYS` or
  `API_KEYS_FILE`, or giving it a role not built on admin, ends its logins at once (401: log in again).
* **`POST /admin/logout`** ends it early, at this server.
* **Each admin call still needs its permission:** a role `operator=admin-manage` may log in, but not
  call what needs `manage` ([Roles and permissions](roles.md)).

## The lockout

Wrong answers are counted per caller's address. After `ADMIN_MAX_FAILURES` in a row, that address
gets 429 (with `Retry-After`) for `ADMIN_LOCKOUT_SECONDS`, even for a right answer. Other addresses
are not affected. Behind a reverse proxy, the address is the one it passes on: set
`UVICORN_FORWARDED_ALLOW_IPS` to the proxy's addresses, or every client shares the proxy's.

## Settings

| Setting | Default | What it does |
|---|---|---|
| `ADMIN_TOKEN_SECONDS` | `900` | How long a login lasts |
| `ADMIN_CHALLENGE_SECONDS` | `60` | How long a challenge's nonce can be answered |
| `ADMIN_MAX_FAILURES` | `5` | Wrong answers in a row from one address before it is locked out... |
| `ADMIN_LOCKOUT_SECONDS` | `300` | ...for this long |
| `SESSION_SECRET` | made at startup | Signs the tokens: the same on every server, so a login works at all of them |

**With keys, but none with an admin role,** the admin endpoints are off (403). **With an identity
provider,** a token with the admin role reaches them with no challenge
([OAuth and OIDC](oauth-oidc.md)).

## Computing an answer

`graph_security.admin_auth.answer(key, nonce)` returns it. In any language: with `client` and `hash`
the hex strings above,

```python
bytes(a ^ b for a, b in zip(bytes.fromhex(client), hmac.new(hash.encode(), nonce.encode(), "sha256").digest())).hex()
```

Each application has a tool that logs in for you, reading the key from the environment, never the
command line (sitelabs-graph-database: `scripts/admin-token.py`; sitelabs-partitioned-graph:
`python -m app.tools admin`).

## Refusals

| Answer | When |
|---|---|
| **401** | No token, a malformed, unknown or expired one; a wrong answer, or a nonce unknown, used or expired; a token whose key is gone |
| **403** | The admin endpoints are off: no key has an admin role |
| **429**, with `Retry-After` | Too many wrong answers from this address; or 10,000 challenges outstanding |

Every login, right or refused, and every logout goes to the application's audit hook. Neither a key
nor a token is ever logged.

## What it doesn't protect against

* **Keys, not users:** no password policy or second factor. An identity provider gives both.
* **No transport security of its own:** tokens travel as bearer headers. Use TLS.
* **A logout is per server:** another server with the same secret takes the token until it expires,
  at most `ADMIN_TOKEN_SECONDS`.
