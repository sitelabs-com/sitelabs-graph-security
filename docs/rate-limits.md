<!-- menu -->
[Overview](overview.md) · [Callers](keys.md) · **Protections** · [Using it](fastapi.md) · [References](index.md)

**Protections:** [Admin login](admin-login.md) · **Rate limits** · [TLS between servers](internal-tls.md)
<!-- /menu -->

# Rate limits

> **For:** whoever runs a server that several clients share. **You'll find:** the limit on calls a
> second and the limit on work at once, per caller and per role, and what a client sees past them.

So one client can't take a server for itself, it can limit each caller in two ways. Both are off by
default.

| Setting | Default | What it limits |
|---|---|---|
| `RATE_LIMIT_PER_SECOND` | `0` (no limit) | Calls a second each caller may make |
| `RATE_LIMIT_BURST` | `0` (twice the rate, at least 1) | How many calls may come at once before the rate applies |
| `RATE_LIMITS` | none | Another rate for some callers or roles: `name=rate[/burst]`, `role:name=rate[/burst]`; `0` for no limit |
| `MAX_RUNNING_PER_CALLER` | `0` (no limit) | The heavy calls one caller may have running at the same time: the application says which (queries, loads, ...) |

```bash
RATE_LIMIT_PER_SECOND=20                       # every caller: 20 calls a second, in bursts of 40
RATE_LIMITS=ingest=0,role:analyst=5/10         # the ingest key: no limit; analysts: 5 a second, bursts of 10
MAX_RUNNING_PER_CALLER=4                       # and no more than 4 heavy calls at once
```

* **The rate** is a token bucket per caller: it fills at the rate, up to the burst, and each call takes
  one.
* **Who a caller is:** a key's or a token's name (the one in the logs), or a browser session's. With
  no keys, the caller's address: behind a reverse proxy, the address it passes on
  (`UVICORN_FORWARDED_ALLOW_IPS`).
* **Which rate applies:** a caller's own in `RATE_LIMITS` wins over its role's, which wins over
  `RATE_LIMIT_PER_SECOND`.
* **A malformed `RATE_LIMITS` entry** stops the server at startup, naming it.

## Past a limit

The call answers **429**, with a `Retry-After` in seconds and the limit it hit, and does nothing:

```json
{"error": "too many calls from 'ann': 5 a second at most (RATE_LIMIT_PER_SECOND, RATE_LIMITS)"}
{"error": "'ann' already has 4 queries running (MAX_RUNNING_PER_CALLER=4): wait for one to finish"}
```

## What isn't limited

The application decides: both leave health checks and metrics out, since load balancers, container
health checks and Prometheus call them often. The admin login has a limit of its own
([Admin login](admin-login.md#the-lockout)).

## Limits

* **Each server counts on its own.** A caller sent to several servers gets the rate at each, and a
  server that takes over from another starts afresh.
* **No quotas over time,** such as rows a day: a reverse proxy, or the application in front, can add
  them.
