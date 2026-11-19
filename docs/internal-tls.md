<!-- menu -->
[Overview](overview.md) · [Callers](keys.md) · **Protections** · [Using it](fastapi.md) · [References](index.md)

**Protections:** [Admin login](admin-login.md) · [Rate limits](rate-limits.md) · **TLS between servers**
<!-- /menu -->

# TLS between servers

> **For:** whoever runs an application's servers on more than one host, or on a network they don't
> fully trust. **You'll find:** what is protected and how, the settings, the startup checks, and the
> functions an application calls.

Without it, an application's servers talk over plain HTTP and rely on the network being private.
With it, every hop between them is https, each certificate is checked against your own private CA,
and a server can answer only callers that present a certificate from it (mutual TLS). **It is on in
production** (`ENVIRONMENT=production`) and off in development: a production server without its
certificates refuses to start, naming what is missing. `INTERNAL_TLS_REQUIRED=False` turns it off
in production, with a warning at every start.

## One call

```
  caller                                                   server
      │ ── 1. TLS hello: the server's name ────────────────▶  │
      │ ◀─ 2. its certificate (from your CA) ───────────────  │
      │    checked against INTERNAL_TLS_CA_FILE, and its name  │
      │    against the URL (or INTERNAL_TLS_SERVER_NAME)       │
      │ ◀─ 3. "show me yours" ──────────────────────────────── │  UVICORN_SSL_CERT_REQS=required
      │ ── 4. its own certificate (INTERNAL_TLS_CERTFILE) ───▶ │  checked against UVICORN_SSL_CA_CERTS
      │ ══ encrypted from here on ══════════════════════════════│
      │ ── 5. the call, with the application's own secret ───▶ │  (PARTITION_TOKEN, REPLICATION_API_KEY)
```

Certificates are always checked. There is no setting to skip the check.

## Settings

A server listening:

| Setting | Default | What it does |
|---|---|---|
| `UVICORN_SSL_CERTFILE`, `UVICORN_SSL_KEYFILE` | none | This server's certificate and key: it speaks https only |
| `UVICORN_SSL_CA_CERTS` | none | The CA that callers' client certificates must come from |
| `UVICORN_SSL_CERT_REQS` | `none` | Client certificates: `none`, `optional` (checked when given), or `required` (mutual TLS) |

A server calling another:

| Setting | Default | What it does |
|---|---|---|
| `INTERNAL_TLS_CA_FILE` | none | The CA the other servers' certificates must come from. None: the system's trusted CAs |
| `INTERNAL_TLS_CERTFILE`, `INTERNAL_TLS_KEYFILE` | none | This server's client certificate, sent on every internal call |
| `INTERNAL_TLS_SERVER_NAME` | none | Check the application's servers' certificates against this name instead of their URLs' host: for servers with made-up names |
| `INTERNAL_TLS_REQUIRED` | `True` in production, `False` in development | Internal URLs must be `https://`, and this server must speak https; it refuses to start otherwise |

## The startup checks

`internal_tls.problems(settings, urls)` lists what stops a server starting, and the application
refuses to start on any:

* `INTERNAL_TLS_REQUIRED=True` and this server doesn't speak https, or one of its internal URLs (the
  `urls` the application names, such as `PARTITION_URLS`) is `http://`;
* a certificate, key or CA file that isn't there or can't be read;
* only one of a certificate and its key;
* `UVICORN_SSL_CERT_REQS` other than `none`, `optional` and `required`, or `required` without
  `UVICORN_SSL_CA_CERTS`.

`internal_tls.upgrade_members()` turns the `http://` server URLs an application kept from before
into `https://`, with the same host and port, and logs which.

## In an application

| Function | What |
|---|---|
| `internal_tls.uvicorn_options(settings)` | The keyword arguments for `uvicorn.run()`: the certificate, key, CA and client-certificate rule |
| `internal_tls.opener(settings)` | A `urllib` opener for the internal calls: the CA, the client certificate, the server name |
| `internal_tls.httpx_client(settings)` | The same as an `httpx.Client` (needs `httpx`) |
| `internal_tls.client_context(settings)` | The `ssl.SSLContext` behind both |
| `internal_tls.metrics_server_options(settings)` | The options for a separate metrics port that speaks https the same way |
| `internal_tls.problems(settings, {name: [urls]})` | The startup checks above |

## The certificates

* **One per server in production,** holding the names the others reach it by. A certificate serves
  and calls (it holds both serverAuth and clientAuth).
* **Keep the CA's key off the servers.** Every server needs the CA's certificate, its own certificate
  and its key, readable by the server's user.
* Each application has a script that makes a CA and certificates, and its deployment puts them in
  place: [sitelabs-graph-database](https://sitelabs-com.github.io/sitelabs-graph-database/security/internal-tls/),
  [sitelabs-partitioned-graph](https://sitelabs-com.github.io/sitelabs-partitioned-graph/security/internal-tls/).

## What it doesn't cover

* **Clients over the internet:** put a reverse proxy with a public certificate in front.
* **Services that can't ask for client certificates** (Perses): keep their ports private.
