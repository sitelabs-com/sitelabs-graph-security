<!-- menu -->
**Overview** · [Callers](keys.md) · [Protections](admin-login.md) · [Using it](fastapi.md) · [References](index.md)

**Overview:** [Overview](overview.md) · **Settings**
<!-- /menu -->

# Settings

> **For:** whoever sets a server up. **You'll find:** every security setting, its default, and the
> page that explains it.

The settings have the same names, defaults and meaning in every application that runs this
package. Each is an environment variable, or a line in the application's `.env`; the application
reads them into its own `Settings`, with these fields (`graph_security.settings.SecuritySettings`
lists them).

## Keys and roles

| Setting | Default | What it does |
|---|---|---|
| `ENVIRONMENT` | `development` | `production`: keys (or an identity provider) and internal TLS are required |
| `API_KEYS` | none | The keys' entries, `name:role:hash[:YYYY-MM-DD]`, comma-separated ([API keys](keys.md)) |
| `API_KEYS_FILE` | none | More entries, one a line, read again when the file changes |
| `CUSTOM_ROLES` | none | Roles of your own, `name=base(+permission\|-permission)...` ([Roles and permissions](roles.md)) |

## Admin logins and browser sessions

| Setting | Default | What it does |
|---|---|---|
| `SESSION_SECRET` | made at startup | Signs admin logins and browser sessions: 32 characters or more, the same on every server |
| `SESSION_SECONDS` | `28800` | How long a browser session lasts ([Browser sessions](sessions.md)) |
| `ADMIN_TOKEN_SECONDS` | `900` | How long an admin login lasts ([Admin login](admin-login.md)) |
| `ADMIN_CHALLENGE_SECONDS` | `60` | How long a challenge can be answered |
| `ADMIN_MAX_FAILURES` | `5` | Wrong answers in a row from one address before it is locked out... |
| `ADMIN_LOCKOUT_SECONDS` | `300` | ...for this long |

## Rate limits

| Setting | Default | What it does |
|---|---|---|
| `RATE_LIMIT_PER_SECOND` | `0` (none) | Calls a second each caller may make ([Rate limits](rate-limits.md)) |
| `RATE_LIMIT_BURST` | `0` (twice the rate) | Calls at once before the rate applies |
| `RATE_LIMITS` | none | Another rate for some callers or roles |
| `MAX_RUNNING_PER_CALLER` | `0` (none) | Heavy calls one caller may have running at once |

## An identity provider

| Setting | Default | What it does |
|---|---|---|
| `OAUTH_OIDC_ACTIVE` | `False` | Accept access tokens from an identity provider ([OAuth and OIDC](oauth-oidc.md)) |
| `OIDC_ISSUER`, `OIDC_AUDIENCE`, `OIDC_ROLE_CLAIM`, `OIDC_ROLE_MAP` | none | Required with it |
| `OIDC_AUDIENCE_CLAIM` | `aud` | Where the audience is |
| `OIDC_NAME_CLAIM` | `preferred_username` | The caller's name in the logs |
| `OIDC_JWKS_URL` | the discovery document's | The provider's keys |
| `OIDC_ALGORITHMS` | `RS256,ES256` | Signatures accepted |
| `OIDC_LEEWAY_SECONDS` | `60` | Allowed for the clocks |
| `OIDC_JWKS_REFRESH_SECONDS` | `3600` | How often the keys are fetched again |
| `OIDC_ADMIN_MAX_AGE_SECONDS` | `0` (any) | The admin endpoints need a login this recent |
| `OIDC_ACCEPT_API_KEYS` | `True` | API keys and the admin login still work too |
| `OIDC_CONSOLE_CLIENT_ID` | none | A web page's client, for signing in there ([Browser sessions](sessions.md)) |
| `OIDC_CONSOLE_SCOPES` | `openid profile` | The scopes it asks for |
| `OIDC_CONSOLE_AUTH_PARAMS` | none | More parameters for the provider's sign-in page |
| `OIDC_CONSOLE_REDIRECT_URI` | `<this server>/console/sso/callback` | Where the provider sends the browser back |

## Metrics

| Setting | Default | What it does |
|---|---|---|
| `METRICS_BEARER_TOKEN` | none | Set: `GET /metrics` needs `Authorization: Bearer <token>` (401 without). A production server warns when it isn't set |

## TLS

| Setting | Default | What it does |
|---|---|---|
| `UVICORN_SSL_CERTFILE`, `UVICORN_SSL_KEYFILE` | none | This server's certificate and key ([TLS between servers](internal-tls.md)) |
| `UVICORN_SSL_CA_CERTS` | none | The CA callers' client certificates must come from |
| `UVICORN_SSL_CERT_REQS` | `none` | `none`, `optional` or `required` |
| `INTERNAL_TLS_CA_FILE` | none | The CA the other servers' certificates must come from |
| `INTERNAL_TLS_CERTFILE`, `INTERNAL_TLS_KEYFILE` | none | This server's client certificate |
| `INTERNAL_TLS_SERVER_NAME` | none | The name to check the servers' certificates against |
| `INTERNAL_TLS_REQUIRED` | `True` in production | Internal URLs must be https, and this server too |
| `UVICORN_FORWARDED_ALLOW_IPS` | `127.0.0.1,::1` | The reverse proxies whose `X-Forwarded-For` is believed: the lockout, the rate limits and the audit log see each client's own address. `*`: anyone, which a production server warns about. Not one of this package's settings: each application has it, under this name |

Each application has settings of its own beside these: its credentials between servers, its limits
and its deployment. Its configuration reference lists them all.
