<!-- menu -->
[Overview](overview.md) · [Callers](keys.md) · [Protections](admin-login.md) · [Using it](fastapi.md) · **References**
<!-- /menu -->

# All documents

> **For:** anyone looking for the right document. **You'll find:** every document, by section.

sitelabs-graph-security is the security the sitelabs graph servers share. Start with the
[Overview](overview.md). What each release changed: [CHANGELOG.md](../CHANGELOG.md).

## Overview

| Document | What's in it |
|---|---|
| [Overview](overview.md) | What it does, what stays in each application, the modules, installing, versions |
| [Settings](settings.md) | Every setting, its default, and the page that explains it |

## Callers

| Document | What's in it |
|---|---|
| [API keys](keys.md) | The entry, changing keys without a restart, a key's last day, with no keys |
| [Roles and permissions](roles.md) | Permissions, the built-in roles, roles of your own, refusals |
| [OAuth and OIDC](oauth-oidc.md) | Tokens from an identity provider: the steps, each provider, how a token is checked |
| [Browser sessions](sessions.md) | Signing a web page in, what a session may do, the cookie |

## Protections

| Document | What's in it |
|---|---|
| [Admin login](admin-login.md) | The challenge, the token, the lockout |
| [Rate limits](rate-limits.md) | Calls a second and work at once, per caller and role |
| [TLS between servers](internal-tls.md) | https between an application's servers, the startup checks, the functions |

## Using it

| Document | What's in it |
|---|---|
| [In a FastAPI app](fastapi.md) | The permissions, the checks on each call, the sign-in endpoints, the hooks, the refusals |
| [Development](development.md) | The tests, releasing, the documentation site |

The applications' own documentation:
[sitelabs-graph-database](https://sitelabs-com.github.io/sitelabs-graph-database/),
[sitelabs-partitioned-graph](https://sitelabs-com.github.io/sitelabs-partitioned-graph/).
