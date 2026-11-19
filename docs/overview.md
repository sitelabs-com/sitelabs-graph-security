<!-- menu -->
**Overview** · [Callers](keys.md) · [Protections](admin-login.md) · [Using it](fastapi.md) · [References](index.md)

**Overview:** **Overview** · [Settings](settings.md)
<!-- /menu -->

# Overview

> **For:** whoever runs a sitelabs graph server, and developers of one. **You'll find:** what this
> package does, what stays in each application, and how an application uses it.

sitelabs-graph-security is the security the sitelabs graph servers share:
[sitelabs-graph-database](https://github.com/sitelabs-com/sitelabs-graph-database) and
[sitelabs-partitioned-graph](https://github.com/sitelabs-com/sitelabs-partitioned-graph) both run
it, with the same settings, the same names and the same behaviour. This site describes how each
mechanism works. Each application's own documentation says what is particular to it: its
permissions, its endpoints, its tools and how it is deployed.

## What it does

| Mechanism | In short | Page |
|---|---|---|
| **API keys** | Each client has a key with a name, a role and, if you like, a last day. The server holds only the keys' hashes. `API_KEYS_FILE` changes them without a restart | [API keys](keys.md) |
| **Roles and permissions** | Every call needs a permission. `read`, `write` and `admin` are built in; `CUSTOM_ROLES` makes more | [Roles and permissions](roles.md) |
| **An identity provider** | Access tokens from an OpenID Connect provider (Keycloak, Entra ID, Okta, Auth0, Cognito): users and MFA there, roles from a claim | [OAuth and OIDC](oauth-oidc.md) |
| **Browser sessions** | A signed cookie for a web page, signed in at the provider or with a key, that may only read | [Browser sessions](sessions.md) |
| **The admin login** | A challenge answered with an admin key, which never crosses the network, for a short-lived token | [Admin login](admin-login.md) |
| **Rate limits** | Calls a second, and work at once, per caller or role | [Rate limits](rate-limits.md) |
| **TLS between the servers** | https on every hop between an application's servers, with a private CA and client certificates | [TLS between servers](internal-tls.md) |

Every setting, with its default: [Settings](settings.md).

## What stays in each application

* **Its permissions** (a `Catalogue`), and which permission each endpoint needs.
* **Its own credentials** between its servers: sitelabs-partitioned-graph's `PARTITION_TOKEN`,
  sitelabs-graph-database's `REPLICATION_API_KEY`.
* **Its request state and audit log**, through hooks on `Security`.
* **The names of its cookies and realms**, so two applications on one host don't collide.
* **How it is deployed:** its Compose files or Ansible roles, its env files, its tools.

| | sitelabs-graph-database | sitelabs-partitioned-graph |
|---|---|---|
| Its security pages | [Security](https://sitelabs-com.github.io/sitelabs-graph-database/security/security/) | [Security](https://sitelabs-com.github.io/sitelabs-partitioned-graph/security/security/) |
| Its permissions | [Roles and permissions](https://sitelabs-com.github.io/sitelabs-graph-database/security/roles/) | [Roles and permissions](https://sitelabs-com.github.io/sitelabs-partitioned-graph/security/roles/) |
| Cookie, realm | `graphdb_session`, `graphdb` | `pgraph_session`, `pgraph` |

## The modules

| Module | What |
|---|---|
| `graph_security.roles` | Roles and permissions: an application's `Catalogue`, the built-in roles, `CUSTOM_ROLES` |
| `graph_security.keys` | `API_KEYS` and `API_KEYS_FILE`; `new_key()` |
| `graph_security.admin_auth` | The admin login: challenges, tokens, lockout |
| `graph_security.sessions` | Browser sessions: signed cookies |
| `graph_security.oidc` | Access tokens from an identity provider |
| `graph_security.limits` | Rate limits and work at once |
| `graph_security.internal_tls` | TLS between the servers: startup checks, uvicorn's options, clients |
| `graph_security.errors` | The refusals, `KeyRefused` and `AdminRefused`, with an HTTP status |
| `graph_security.settings` | `SecuritySettings`: every setting, the same names and defaults everywhere |
| `graph_security.web` | For FastAPI: `Security`, the checks on each call, and the sign-in endpoints |

## Installing

```bash
pip install "sitelabs-graph-security[fastapi] @ git+https://github.com/sitelabs-com/sitelabs-graph-security.git@v0.2.0"
pip install --no-deps -e ../sitelabs-graph-security       # while changing it with an application
```

Python 3.12 or later. It needs PyJWT with `cryptography`; FastAPI for `graph_security.web` (the
`fastapi` extra); `httpx` only for `internal_tls.httpx_client()`. An application pins it to a
release, and links to that release's site: this one's address names it
(`/sitelabs-graph-security/0.2/`). How an application uses it: [In a FastAPI app](fastapi.md).

## Versions

Each release is a tag `v<version>`, with an entry in [CHANGELOG.md](../CHANGELOG.md), and a site
of its own here. Before 1.0, a minor release (0.1 to 0.2) may change the API, said so in the
changelog with what to do; a patch release doesn't. The applications pin an exact tag.

The API is what the [modules](#the-modules) offer an application, the settings' names and defaults,
the refusals' statuses and scopes ([In a FastAPI app](fastapi.md#6-the-refusals)), and the
endpoints `session_router()` adds. The refusals' wording may be improved in any release.
