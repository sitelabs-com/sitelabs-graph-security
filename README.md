# sitelabs-graph-security

Security for the sitelabs graph servers, shared by
[sitelabs-graph-database](https://github.com/sitelabs-com/sitelabs-graph-database) and
[sitelabs-partitioned-graph](https://github.com/sitelabs-com/sitelabs-partitioned-graph): API keys,
roles and permissions, the admin login, browser sessions, OAuth 2.0 / OpenID Connect access tokens,
rate limits and TLS between the servers.

| Module | What |
|---|---|
| `graph_security.roles` | Roles and permissions. Each application describes its permissions in a `Catalogue` and registers it with `use()`; `read`, `write` and `admin` are built from it, and `CUSTOM_ROLES` adds more |
| `graph_security.keys` | `API_KEYS` and `API_KEYS_FILE`: `name:role:hash[:YYYY-MM-DD]` entries, hashed twice, read again when the file changes; `new_key()` |
| `graph_security.admin_auth` | The admin login: a challenge answered with an admin key, which never crosses the network; tokens signed with `SESSION_SECRET`; lockout after wrong answers |
| `graph_security.sessions` | Browser sessions: signed, HttpOnly cookies that may only query, ending with their key |
| `graph_security.oidc` | Access tokens from an identity provider (Keycloak, Auth0, Cognito, Entra ID, Okta): JWKS, issuer, audience, roles from a claim |
| `graph_security.limits` | Rate limits (token buckets) and work at once, per caller or role |
| `graph_security.internal_tls` | https between the servers with a private CA: the checks at startup, uvicorn's options, urllib and httpx clients |
| `graph_security.errors` | The refusals: `AdminRefused` and `KeyRefused`, with an HTTP status |
| `graph_security.settings` | `SecuritySettings`: every security setting, the same names and defaults in each application |

What stays in each application: its permissions (the `Catalogue`), which permission each endpoint
needs, its FastAPI checks, its own credentials (a replication key, a partition token), the sign-in
endpoints, and the names of its cookies and realms.

## Using it

```python
from graph_security.roles import Catalogue, use

CATALOGUE = use(Catalogue(
    {"query": "read queries", "write": "write queries", "load": "bulk loads", "manage": "the platform"},
    read={"query"}, write={"write", "load"}, admin_only={"manage"}))
BUILT_IN, parse_roles = CATALOGUE.built_in, CATALOGUE.parse_roles
```

Register the catalogue once, when the application's roles module is imported: functions called
without `roles` use it, and say so if there is none. The other modules read the settings by name
(`settings.api_keys`, `settings.oidc_issuer`, ...), from the application's own `Settings` or a
`SecuritySettings`.

## Installing

```bash
pip install "sitelabs-graph-security @ git+https://github.com/sitelabs-com/sitelabs-graph-security.git@v0.1.0"
pip install --no-deps -e ../sitelabs-graph-security       # while changing it with an application
```

Python 3.12 or later. It needs PyJWT with `cryptography`; `httpx` only for `internal_tls.httpx_client()`.

## Tests

```bash
pip install -e ".[test]"
python -m pytest
```

The tests make their own keys, tokens and certificates: no identity provider and no network.

## Licence

Apache License 2.0 ([LICENSE.txt](LICENSE.txt)); third-party names in [NOTICES.txt](NOTICES.txt).
