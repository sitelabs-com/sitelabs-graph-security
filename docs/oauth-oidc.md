<!-- menu -->
[Overview](overview.md) · **Callers** · [Protections](admin-login.md) · [Using it](fastapi.md) · [References](index.md)

**Callers:** [API keys](keys.md) · [Roles and permissions](roles.md) · **OAuth and OIDC** · [Browser sessions](sessions.md)
<!-- /menu -->

# OAuth and OIDC

> **For:** whoever wants users and services to log in through an identity provider instead of API
> keys. **You'll find:** what it does, the steps to turn it on, each provider's settings, the
> settings, and what it doesn't do.

With `OAUTH_OIDC_ACTIVE=True`, a server accepts access tokens from an OpenID Connect provider:
Keycloak, Microsoft Entra ID, Okta, Auth0, Amazon Cognito or any other that issues signed JWTs. The
provider holds the users, their passwords and MFA; the server only checks the tokens it is sent,
and gives none itself. It is off by default.

| | API keys | With OIDC |
|---|---|---|
| Who the caller is | A key's name | The token's `preferred_username` (or the service's `client_id`) |
| Their role | The key's role | A claim in the token, mapped by `OIDC_ROLE_MAP` |
| A user joins or leaves | Edit the keys | At the provider; nothing on the server |
| Second factor | None | Whatever the provider requires |
| Admin endpoints | The challenge login with an admin key | A token with the admin role, and a recent login if you ask for one |

An application's own credentials between its servers (sitelabs-partitioned-graph's
`PARTITION_TOKEN`, sitelabs-graph-database's `REPLICATION_API_KEY`) don't go to the provider, so it
being away never stops them.

## 1. Put TLS in front

A token sent over plain HTTP can be taken and used by anyone who sees it until it expires. Put a
reverse proxy with TLS in front of the server before handing out tokens.

## 2. Set up the provider

1. **The API**, with an audience, say `graph-api`. Its tokens must carry it (`aud`).
2. **Roles or groups** for read, write and admin (and any roles of your own), say `graph-read`,
   `graph-write`, `graph-admin`. Give them to users and services, and make sure they appear in the
   access token.
3. **A client for each service,** with the client credentials grant, given the role it needs.
4. **For people,** the client they log in with: the device code flow, the provider's CLI, or a web
   page's client ([Browser sessions](sessions.md#at-the-identity-provider)).
5. **MFA** for everyone with the admin role, and **access tokens that last 5 to 15 minutes**: a
   token can't be taken back once issued, only left to expire.

| Provider | `OIDC_ISSUER` | `OIDC_ROLE_CLAIM` | `OIDC_AUDIENCE_CLAIM` |
|---|---|---|---|
| Keycloak | `https://<host>/realms/<realm>` | `realm_access.roles`; add an audience mapper so `aud` holds your API | `aud` |
| Microsoft Entra ID | `https://login.microsoftonline.com/<tenant id>/v2.0` | `roles` (the app roles you define) | `aud` (the API's application id) |
| Okta | `https://<org>.okta.com/oauth2/<authorization server>` | `groups` (add a groups claim), or `scp` | `aud` |
| Auth0 | `https://<tenant>.auth0.com/`, with its final `/` | `permissions` (with RBAC on), or a namespaced claim an Action adds | `aud` |
| Amazon Cognito | `https://cognito-idp.<region>.amazonaws.com/<user pool id>` | `cognito:groups` | `client_id`: its access tokens have no `aud`, so `OIDC_AUDIENCE` is the app client's id |

## 3. Set the server's settings

```bash
OAUTH_OIDC_ACTIVE=True
OIDC_ISSUER=https://idp.example.com/realms/graph
OIDC_AUDIENCE=graph-api
OIDC_ROLE_CLAIM=realm_access.roles
OIDC_ROLE_MAP=admin=graph-admin,write=graph-write,read=graph-read
# optional
OIDC_ADMIN_MAX_AGE_SECONDS=900        # admin endpoints: a login in the last 15 minutes
OIDC_ACCEPT_API_KEYS=True             # keys go on working while clients move over
```

The server refuses to start, naming each problem, without one of the four required settings, or
with one it can't use:

* an `http://` issuer or JWKS URL elsewhere than this machine;
* an algorithm that isn't asymmetric (`HS256`): only `RS256`, `RS384`, `RS512`, `ES256`, `ES384`,
  `ES512`, `PS256`, `PS384`, `PS512` and `EdDSA`;
* a role map entry naming a role that isn't built in or one of `CUSTOM_ROLES`.

`OIDC_*` settings set while `OAUTH_OIDC_ACTIVE=False` have no effect, and the server says so.

## How a token is checked

* **The signature,** with the provider's keys (JWKS), from its discovery document or `OIDC_JWKS_URL`.
  They are fetched when the first token arrives, again every `OIDC_JWKS_REFRESH_SECONDS` (an hour),
  and when a token names a key the server doesn't have. A server starts even when the provider can't
  be reached: tokens are refused with 503 until the keys are fetched, and keys already fetched go on
  being used while it is away.
* **The issuer, the audience** (in `OIDC_AUDIENCE_CLAIM`), **the expiry** and `nbf`, with
  `OIDC_LEEWAY_SECONDS` (60) for the clocks.
* **The roles:** the claim `OIDC_ROLE_CLAIM` (a dotted path such as `realm_access.roles`), mapped by
  `OIDC_ROLE_MAP`, `role=value` each. A token with none of the mapped values is refused (403). One with
  several has the permissions of all of them.
* **The caller's name** in the logs: `OIDC_NAME_CLAIM` (`preferred_username`), else `client_id`, `azp`
  or `sub`.
* **The admin endpoints** take a token with the admin role, no challenge login, and with
  `OIDC_ADMIN_MAX_AGE_SECONDS`, only if the user logged in that recently (`auth_time`).

A refusal says why, without the token: expired, another issuer, not for this API, a key the
provider doesn't list, or none of the roles. Tokens are never logged.

## Turning API keys off

Once every client uses tokens, set `OIDC_ACCEPT_API_KEYS=False`: `X-API-Key` is refused (401), the
admin challenge login is off (403), and the keys are ignored. Leave it `True` to keep a key as a way
in while the provider is down.

## Settings

| Setting | Default | What it does |
|---|---|---|
| `OAUTH_OIDC_ACTIVE` | `False` | Accept access tokens from an identity provider |
| `OIDC_ISSUER` | none | The provider's issuer (`https://`): its discovery document is read from there |
| `OIDC_AUDIENCE` | none | The audience a token must be for |
| `OIDC_ROLE_CLAIM` | none | The claim that holds the roles |
| `OIDC_ROLE_MAP` | none | `role=value` each: which claim value gives which role |
| `OIDC_AUDIENCE_CLAIM` | `aud` | Where the audience is (`client_id` for Cognito) |
| `OIDC_NAME_CLAIM` | `preferred_username` | The caller's name in the logs |
| `OIDC_JWKS_URL` | the discovery document's | The provider's keys |
| `OIDC_ALGORITHMS` | `RS256,ES256` | Signatures accepted: asymmetric ones only |
| `OIDC_LEEWAY_SECONDS` | `60` | Allowed for the clocks |
| `OIDC_JWKS_REFRESH_SECONDS` | `3600` | How often the keys are fetched again |
| `OIDC_ADMIN_MAX_AGE_SECONDS` | `0` (any) | The admin endpoints need a login this recent |
| `OIDC_ACCEPT_API_KEYS` | `True` | API keys and the admin login still work too |

The settings for a web page's sign-in (`OIDC_CONSOLE_*`) are in [Browser sessions](sessions.md).

## What it doesn't do

* **Take a token back** before it expires: not possible with a JWT. Keep access tokens short.
* **Issue tokens.** The server only checks them.
