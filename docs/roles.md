<!-- menu -->
[Overview](overview.md) · **Callers** · [Protections](admin-login.md) · [Using it](fastapi.md) · [References](index.md)

**Callers:** [API keys](keys.md) · **Roles and permissions** · [OAuth and OIDC](oauth-oidc.md) · [Browser sessions](sessions.md)
<!-- /menu -->

# Roles and permissions

> **For:** whoever gives clients their keys or their roles at the identity provider, and developers
> of an application. **You'll find:** how permissions and roles work, the built-in roles, making
> roles of your own, how keys, tokens and sessions get a role, and what a refusal says.

Every call needs a **permission**. A caller has a **role**, and a role is a set of permissions.

## Permissions are the application's

Each application names its permissions in a **catalogue**, and says which each endpoint needs. Some
are **admin permissions**: they need an [admin login](admin-login.md), or a token from the identity
provider, as well as the role.

| | Its permissions |
|---|---|
| sitelabs-graph-database | `query`, `write`, `load`; admin: `manage`, `backup`, `repair`, `leadership`, `diagnostics`, `procedures` ([its page](https://sitelabs-com.github.io/sitelabs-graph-database/security/roles/)) |
| sitelabs-partitioned-graph | `query`, `export`, `algorithms`, `write`, `delete`, `load`; admin: `standbys`, `resize`, `rollback`, `suspend`, `raise_deletes` ([its page](https://sitelabs-com.github.io/sitelabs-partitioned-graph/security/roles/)) |

```python
from graph_security.roles import Catalogue, use

CATALOGUE = use(Catalogue(
    {"query": "read queries", "write": "write queries", "load": "bulk loads", "manage": "the platform"},
    read={"query"}, write={"write", "load"}, admin_only={"manage"}))
```

## The built-in roles

| Role | Permissions |
|---|---|
| **read** | The catalogue's `read` set |
| **write** | read's, and the `write` set |
| **admin** | Every permission: write's with its key, and the admin permissions after logging in |

## Roles of your own

`CUSTOM_ROLES` holds them, comma-separated, each `name=base`, then `-permission` to take one away or
`+permission` to add one:

```bash
CUSTOM_ROLES=feeder=read+load,writer=write-load,operator=admin-manage
```

* **A name** is lower case: letters, digits, `_` and `-`, starting with a letter, up to 32
  characters, and not `read`, `write` or `admin`.
* **Only a role built on admin may log in as an admin,** and admin permissions can be added to no
  other role: `x=write+manage` is refused.
* **A role with nothing left,** or an unknown permission, is refused. The server names the entry and
  refuses to start.
* **Roles are read at startup.** Changing `CUSTOM_ROLES` takes a restart; keys can change without one
  ([API keys](keys.md#changing-keys-without-a-restart)).

## How a caller gets a role

* **An API key** names its role in its entry, `name:role:hash`, which may be a role of your own
  ([API keys](keys.md)).
* **A token from the identity provider** gets its roles from `OIDC_ROLE_MAP`, which may map a group
  to a role of your own: `OIDC_ROLE_MAP=feeder=graph-feeders`. A token with several roles has the
  permissions of all of them ([OAuth and OIDC](oauth-oidc.md)).
* **A browser session** keeps only `query`, whatever its role ([Browser sessions](sessions.md)).
  So an application whose read permission isn't called `query` gets sessions that do nothing.
* **With no keys and no identity provider** (development), every caller has every permission.

## Refusals

A call without the permission answers **403**, naming the permission, what it covers, the caller and
their role:

```json
{"error": "this needs the load permission (bulk loads); 'ann' has the role feeder, which hasn't it"}
```

The application decides what else a refusal does: both audit every refusal.

## What roles don't do

* **No rules per label or property.** A role that may query reads the whole graph. Put finer rules
  in the application in front of the server.
