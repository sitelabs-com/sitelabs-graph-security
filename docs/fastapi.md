<!-- menu -->
[Overview](overview.md) · [Callers](keys.md) · [Protections](admin-login.md) · **Using it** · [References](index.md)

**Using it:** **In a FastAPI app** · [Development](development.md)
<!-- /menu -->

# In a FastAPI app

> **For:** developers of an application that runs this package. **You'll find:** registering the
> permissions, the parts the checks need, the checks on each call, the sign-in endpoints, the hooks,
> and the refusals.

## 1. The permissions

Register the application's catalogue once, when its roles module is imported. Functions called
without `roles` use it, and say so if there is none.

```python
from graph_security.roles import Catalogue, use

CATALOGUE = use(Catalogue(
    {"query": "read queries", "write": "write queries", "load": "bulk loads", "manage": "the platform"},
    read={"query"}, write={"write", "load"}, admin_only={"manage"}))
BUILT_IN, parse_roles = CATALOGUE.built_in, CATALOGUE.parse_roles
```

`query` is the permission a browser session keeps ([Browser sessions](sessions.md)): name the read
permission so, or sessions do nothing.

## 2. The parts

`Security` reads the application's security parts from each request, through `parts(request)`: an
object with `keys` (`graph_security.keys.ApiKeys`), `admin` (`admin_auth.AdminAuth`), `sessions`
(`sessions.Sessions`), `limits` (`limits.Limits`, or `None`) and `oidc` (`oidc.Oidc`, or `None`).
The application makes them at startup from its settings, usually on `app.state`.

## 3. The checks on each call

```python
from fastapi import Depends, Request
from graph_security.web import Security

SECURITY = Security(parts=lambda request: request.app.state,
                    settings=lambda request: get_settings(),
                    cookie="app_session", sso_cookie="app_sso",
                    on_caller=lambda request, p: ..., audit=...)

@app.post("/query", dependencies=[Depends(SECURITY.permission("query")), Depends(SECURITY.running)])
def query(request: Request, ...):
    SECURITY.demand(request, "write")              # once it knows the query writes
```

| | What it does |
|---|---|
| `SECURITY.permission(name)` | A dependency: the caller (a key, a token, a session, or anyone when open), whose role has the permission. An admin permission needs an admin login or token too. Counts the call against the caller's rate |
| `SECURITY.demand(request, name)` | The same check, in the middle of a call: for a permission only the request's content shows |
| `SECURITY.running` | A dependency: one of the caller's `MAX_RUNNING_PER_CALLER` places, while the call runs |
| `SECURITY.caller(request)` | The caller already identified, or `None` |
| `SECURITY.is_open(request)` | No keys and no identity provider: every endpoint open |

## 4. The sign-in endpoints

```python
app.include_router(SECURITY.session_router())
```

`GET`, `POST` and `DELETE /session`, and `/console/sso/start` and `/console/sso/callback` for signing
in at the identity provider ([Browser sessions](sessions.md)). The admin login's endpoints
(`/admin/challenge`, `/admin/login`, `/admin/logout`) stay in the application, calling `AdminAuth`
([Admin login](admin-login.md)).

## 5. The hooks

| Hook | Called |
|---|---|
| `on_caller(request, principal)` | As soon as the caller is known: for the logs and the application's request state |
| `on_admin(request)` | When a call needs an admin permission: for the audit log |
| `audit(action, message, level, **fields)` | For the sign-in lines (`session.start`, `session.end`) |

`cookie` and `sso_cookie` name the session cookie and the sign-in's: cookies are per host, not per
port, so applications on one host name theirs apart.

## 6. The refusals

The checks raise `KeyRefused` (callers) and `AdminRefused` (the admin login), from
`graph_security.errors`, each with an HTTP `status`, a message, and for 429 a `retry_after`. Answer
them with their status, and on a 401 with a `WWW-Authenticate` naming the realm for their `scope`
(`Bearer realm="app"`, `"app-admin"`). Both applications log every refusal in their audit log.

## Settings

The modules read the settings by name (`settings.api_keys`, `settings.oidc_issuer`, ...), from the
application's own `Settings` or a `SecuritySettings`: give the application's the same fields
([Settings](settings.md)).
