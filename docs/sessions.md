<!-- menu -->
[Overview](overview.md) · **Callers** · [Protections](admin-login.md) · [Using it](fastapi.md) · [References](index.md)

**Callers:** [API keys](keys.md) · [Roles and permissions](roles.md) · [OAuth and OIDC](oauth-oidc.md) · **Browser sessions**
<!-- /menu -->

# Browser sessions

> **For:** whoever sets up a web page (a query console, dashboards) for people, not programs.
> **You'll find:** signing in at the identity provider or with a key, what a session may do, the
> cookie, the endpoints, and the settings.

A browser can stay signed in to a server, so a page needs no key typed each time. The session is a
cookie the server sets; the browser never holds a key or a token.

## Signing in

* **At the identity provider** (with `OIDC_CONSOLE_CLIENT_ID`): the page sends the browser to
  `/console/sso/start`, which sends it on to the provider's sign-in page. It comes back to
  `/console/sso/callback` with a code, which the server exchanges for an access token itself (the
  authorization code flow, with PKCE). It checks the token as it checks every token
  ([OAuth and OIDC](oauth-oidc.md#how-a-token-is-checked)), then sets the cookie. The token never
  reaches the browser.
* **With a key:** the page sends it once, `POST /session` with `X-API-Key`, and forgets it.
* **From a script:** `POST /session` with `X-API-Key` or `Authorization: Bearer` sets the same cookie.

**Signing out** (`DELETE /session`) drops the cookie, and the server remembers that session ended.
`GET /session` says who is signed in, and until when.

## What a session may do

**Only read.** Of its role's permissions a session keeps `query` alone: it can't write, load or log
in as an admin, whatever its role. A leaked cookie can't change the graph.

* **A session made with a key ends with the key:** removed from `API_KEYS_FILE`, replaced or expired,
  it stops working at the next call.
* **A session from the identity provider keeps the role it signed in with** until it ends, after
  `SESSION_SECONDS` (8 hours). Taking someone's role away at the provider counts from their next
  sign-in.
* **A role without `query`** can't make a session (403): it would do nothing.

## The cookie

* `HttpOnly` (no script can read it), `SameSite=Strict` (no other site's page can send it) and, over
  https, `Secure`.
* **Signed with `SESSION_SECRET`** (HMAC-SHA256). Give every server of an application the same one,
  and a session works at all of them, and across a restart. Without it, a secret is made at startup,
  and a restart signs everyone out.
* **Named by the application:** cookies are per host, not per port, so two applications on one host
  name theirs apart (sitelabs-graph-database: `graphdb_session`; sitelabs-partitioned-graph:
  `pgraph_session`).

## Settings

| Setting | Default | What it does |
|---|---|---|
| `SESSION_SECRET` | made at startup | Signs the sessions and the admin logins: 32 characters or more, the same on every server |
| `SESSION_SECONDS` | `28800` | How long a session lasts after signing in |
| `OIDC_CONSOLE_CLIENT_ID` | none | The page's client at the identity provider: signing in there needs it |
| `OIDC_CONSOLE_SCOPES` | `openid profile` | The scopes it asks for. Add the API's own when the provider needs one for the token's audience (Entra ID: `api://<id>/.default`; Cognito: its resource server's scope) |
| `OIDC_CONSOLE_AUTH_PARAMS` | none | More parameters for the provider's sign-in page: `audience=graph-api` for Auth0 |
| `OIDC_CONSOLE_REDIRECT_URI` | `<this server>/console/sso/callback` | Where the provider sends the browser back, when the address the server sees isn't the one the browser uses |

## At the identity provider

1. **A public client** (no secret) using the **authorization code** flow with **PKCE**. Its id is
   `OIDC_CONSOLE_CLIENT_ID`.
2. **Its redirect URI** is `https://<the server's public name>/console/sso/callback`, exactly.
3. **Its access tokens** must be the API's like any client's: the audience `OIDC_AUDIENCE`, and the
   roles in `OIDC_ROLE_CLAIM`.

The server calls the provider's token endpoint itself, so it must reach it. Behind a reverse proxy,
the callback address comes from the request: the proxy must pass the `Host` header, and the server
must believe its `X-Forwarded-Proto` (`UVICORN_FORWARDED_ALLOW_IPS`). Else set
`OIDC_CONSOLE_REDIRECT_URI`. Behind a load balancer with several servers, set it to the public
address, so the callback names it whichever server answers.

Every sign-in, refused or not, and every sign-out goes to the application's audit hook
(`session.start`, `session.end`).
