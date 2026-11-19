<!-- menu -->
[Overview](overview.md) · **Callers** · [Protections](admin-login.md) · [Using it](fastapi.md) · [References](index.md)

**Callers:** **API keys** · [Roles and permissions](roles.md) · [OAuth and OIDC](oauth-oidc.md) · [Browser sessions](sessions.md)
<!-- /menu -->

# API keys

> **For:** whoever gives clients their keys. **You'll find:** what a key is, the entry the server
> holds, changing keys without a restart, a key's last day, and what happens with no keys at all.

A client sends its key on every call, as `X-API-Key: <key>`. Each key has a **name** (the one in the
logs), a **role** ([Roles and permissions](roles.md)) and, if you like, a **last day**.

## The entry

The server never holds a key. It holds an entry for each, comma-separated in `API_KEYS`:

```
name:role:hash[:YYYY-MM-DD]
ann:read:3f1c9e...                    # ann, who may read
loader:write:9a0b47...:2027-03-31     # a key that stops working after 31 March 2027
alex:admin:77d2e1...
```

* **The hash** is the hex SHA-256 of the hex SHA-256 of the key. The server looks a key up by it, so a
  key can't be guessed by timing.
* **A stolen entry can't be used as a key,** nor to log in as an admin: the login needs the key's
  first hash, which the entry doesn't give away ([Admin login](admin-login.md)).
* **A malformed entry stops the server at startup,** naming it: an unknown role, a bad hash, a date
  that isn't one.
* **Give each client its own key,** so one can be taken back alone.

Each application has a tool that makes a key and prints it once, with its entry (sitelabs-graph-database:
`scripts/api-key.py`; sitelabs-partitioned-graph: `python -m app.tools apikey`). From code,
`graph_security.keys.new_key(name, role, days=0)` returns the key and its entry (`days`: how
long it lasts; 0, no last day).

## Changing keys without a restart

`API_KEYS` is read at startup. **`API_KEYS_FILE`** names a file of more entries, one a line (`#`
starts a comment), read again whenever the file changes: a key is added, removed or replaced with no
restart. A key removed or replaced stops working at once: its browser sessions and admin logins
with it.

| Setting | Default | What it does |
|---|---|---|
| `API_KEYS` | none | The entries, comma-separated |
| `API_KEYS_FILE` | none | A file of more entries, one a line, read again when it changes |

A key in both is refused at startup (the same name twice).

## A key's last day

An entry may end with its last day, `:YYYY-MM-DD`. The key works until the end of that day (UTC),
then answers 401 (`the key 'loader' expired at the end of 2027-03-31`). The server warns at startup
from two weeks before.

## With no keys

**With no keys at all and no identity provider, every endpoint is open,** the admin ones too, with
no login. That is for development only: in production (`ENVIRONMENT=production`), a server with no
key and no identity provider refuses to start, and so does one whose `API_KEYS_FILE` holds none.

## Refusals

| Answer | When |
|---|---|
| **401** | No key, a key that isn't in `API_KEYS` or `API_KEYS_FILE`, or one past its last day |
| **403** | A key whose role hasn't the permission the call needs ([Roles and permissions](roles.md#refusals)) |

Keys are never logged: only their names.
