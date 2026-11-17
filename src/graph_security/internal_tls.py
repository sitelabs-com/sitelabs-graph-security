# Copyright 2026 Sitelabs.com
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""TLS between the servers. The same settings in every application:

A server listening (uvicorn):
    UVICORN_SSL_CERTFILE, UVICORN_SSL_KEYFILE   its certificate and key: it speaks https only
    UVICORN_SSL_CA_CERTS                        the CA that callers' client certificates must come from
    UVICORN_SSL_CERT_REQS                       none (default), optional, or required: mutual TLS

A server calling another (the internal calls):
    INTERNAL_TLS_CA_FILE                        the CA the other server's certificate must come from
    INTERNAL_TLS_CERTFILE, INTERNAL_TLS_KEYFILE its own client certificate, sent on every internal call
    INTERNAL_TLS_SERVER_NAME                    check the cluster's servers' certificates against this
                                                name, not the URL's host (servers with generated names);
                                                monitoring's are checked against their URL's host
    INTERNAL_TLS_REQUIRED                       True: internal URLs must be https://, and a server
                                                refuses to start with any that isn't

Certificates are always checked: there is no setting to skip the check.
"""
from __future__ import annotations

import http.client
import logging
import os
import ssl
import urllib.request
from pathlib import Path

log = logging.getLogger(__name__)
CERT_REQS = {"none": ssl.CERT_NONE, "optional": ssl.CERT_OPTIONAL, "required": ssl.CERT_REQUIRED}


def listening(settings) -> bool:
    return bool(settings.uvicorn_ssl_certfile)


def uvicorn_options(settings) -> dict:
    """uvicorn.run()'s TLS arguments: none unless UVICORN_SSL_CERTFILE is set."""
    if not listening(settings):
        return {}
    return {"ssl_certfile": settings.uvicorn_ssl_certfile, "ssl_keyfile": settings.uvicorn_ssl_keyfile or None,
            "ssl_ca_certs": settings.uvicorn_ssl_ca_certs or None,
            "ssl_cert_reqs": CERT_REQS[(settings.uvicorn_ssl_cert_reqs or "none").lower()]}


def metrics_server_options(settings) -> dict:
    """prometheus_client.start_http_server()'s TLS arguments, for a process with no uvicorn port of its
    own (an ingest worker's /metrics): https with its internal certificate, and with a CA, Prometheus's
    client certificate required."""
    if not settings.internal_tls_certfile:
        return {}
    return {"certfile": settings.internal_tls_certfile, "keyfile": settings.internal_tls_keyfile or None,
            "client_cafile": settings.internal_tls_ca_file or None,
            "client_auth_required": bool(settings.internal_tls_ca_file)}


def client_context(settings, ca_file: str = "") -> ssl.SSLContext:
    """The context for internal calls: the system's CAs, or INTERNAL_TLS_CA_FILE's alone (`ca_file`, a
    more particular setting, first); and the client certificate, when there is one. Hostnames are
    always checked."""
    ctx = ssl.create_default_context(cafile=ca_file or settings.internal_tls_ca_file or None)
    if settings.internal_tls_certfile:
        ctx.load_cert_chain(settings.internal_tls_certfile, settings.internal_tls_keyfile or None)
    return ctx


def server_name(settings) -> str:
    return settings.internal_tls_server_name.strip()


def scheme(settings) -> str:
    """The scheme of this server's own URL, for the servers it starts or advertises."""
    return "https" if listening(settings) else "http"


def problems(settings, internal_urls: dict[str, list[str]], serves: bool = True) -> list[str]:
    """What stops a server starting: files that can't be read, settings that need others, and with
    INTERNAL_TLS_REQUIRED=True, internal URLs that aren't https:// (`internal_urls`: setting name ->
    the URLs it holds) and a server that doesn't speak https itself (`serves`: it has a port of its own)."""
    s, out = settings, []
    for name in ("uvicorn_ssl_certfile", "uvicorn_ssl_keyfile", "uvicorn_ssl_ca_certs",
                 "internal_tls_ca_file", "internal_tls_certfile", "internal_tls_keyfile"):
        path = getattr(s, name)
        if path and not (Path(path).is_file() and os.access(path, os.R_OK)):
            out.append(f"{name.upper()}={path}: no such file, or it can't be read")
    reqs = (s.uvicorn_ssl_cert_reqs or "none").lower()
    if reqs not in CERT_REQS:
        out.append(f"UVICORN_SSL_CERT_REQS={s.uvicorn_ssl_cert_reqs}: none, optional or required")
    if s.uvicorn_ssl_keyfile and not s.uvicorn_ssl_certfile:
        out.append("UVICORN_SSL_KEYFILE is set without UVICORN_SSL_CERTFILE")
    if reqs in ("optional", "required") and not (s.uvicorn_ssl_certfile and s.uvicorn_ssl_ca_certs):
        out.append(f"UVICORN_SSL_CERT_REQS={reqs} needs UVICORN_SSL_CERTFILE and UVICORN_SSL_CA_CERTS "
                   "(the CA that client certificates must come from)")
    if s.internal_tls_keyfile and not s.internal_tls_certfile:
        out.append("INTERNAL_TLS_KEYFILE is set without INTERNAL_TLS_CERTFILE")
    if s.internal_tls_required:
        explicit = "internal_tls_required" in getattr(s, "model_fields_set", {"internal_tls_required"})
        why = ("INTERNAL_TLS_REQUIRED=True" if explicit else
               "ENVIRONMENT=production needs internal TLS (docs/security/internal-tls.md; INTERNAL_TLS_REQUIRED=False "
               "turns it off)")
        if serves and not s.uvicorn_ssl_certfile:
            out.append(f"{why}: this server must speak https itself (UVICORN_SSL_CERTFILE)")
        for name, urls in internal_urls.items():
            plain = [u for u in urls if u and u.lower().startswith("http://")]
            if plain:
                out.append(f"{why}: {name} must be https:// ({', '.join(plain)})")
    if out:
        return out
    try:
        if s.internal_tls_ca_file or s.internal_tls_certfile:
            client_context(s)
        if s.uvicorn_ssl_certfile:
            ssl.create_default_context(ssl.Purpose.CLIENT_AUTH).load_cert_chain(
                s.uvicorn_ssl_certfile, s.uvicorn_ssl_keyfile or None)
    except (ssl.SSLError, OSError, ValueError) as ex:
        out.append(f"a certificate or key can't be used: {ex}")
    return out


def upgrade(url: str) -> str:
    return "https://" + url[len("http://"):] if url.lower().startswith("http://") else url


def upgrade_members(members: dict) -> dict:
    """A cluster's members ({"partitions": [...], "standbys": [...], "failed": [...], "instances": {...}})
    with every http:// server URL as https://, same host and port: for INTERNAL_TLS_REQUIRED=True on a
    cluster that ran without TLS before."""
    out = dict(members)
    changed = []
    for key in ("partitions", "standbys", "failed"):
        if isinstance(out.get(key), list):
            changed += [u for u in out[key] if isinstance(u, str) and u != upgrade(u)]
            out[key] = [upgrade(u) if isinstance(u, str) else u for u in out[key]]
    if isinstance(out.get("instances"), dict):
        out["instances"] = {upgrade(u): i for u, i in out["instances"].items()}
    if changed:
        log.warning("INTERNAL_TLS_REQUIRED=True: %d server URL(s) kept as http:// are https:// now: %s",
                    len(changed), ", ".join(changed))
    return out


class _Connection(http.client.HTTPSConnection):
    """An https connection whose certificate is checked against INTERNAL_TLS_SERVER_NAME."""

    server_name = ""

    def connect(self):
        http.client.HTTPConnection.connect(self)               # the TCP connection, no proxy tunnel
        self.sock = self._context.wrap_socket(self.sock, server_hostname=self.server_name or self.host)


class _Handler(urllib.request.HTTPSHandler):
    def __init__(self, context: ssl.SSLContext, name: str):
        super().__init__(context=context)
        self._name = name

    def https_open(self, req):
        name = self._name

        class Conn(_Connection):
            server_name = name
        return self.do_open(Conn, req, context=self._context)


def opener(settings) -> urllib.request.OpenerDirector:
    """A urllib opener for calls to the cluster's servers: client_context(), and INTERNAL_TLS_SERVER_NAME."""
    return urllib.request.build_opener(_Handler(client_context(settings), server_name(settings)))


def httpx_options(settings, ca_file: str = "") -> dict:
    """httpx.Client()'s TLS argument for internal calls."""
    return {"verify": client_context(settings, ca_file)}


def httpx_client(settings, ca_file: str = "", **kw):
    """An httpx.Client for calls to the cluster's servers: client_context(), and with
    INTERNAL_TLS_SERVER_NAME, every certificate checked against that name."""
    import httpx

    name = server_name(settings)
    if not name:
        return httpx.Client(**httpx_options(settings, ca_file), **kw)

    class Named(httpx.HTTPTransport):
        def handle_request(self, request):
            request.extensions["sni_hostname"] = name
            return super().handle_request(request)
    return httpx.Client(transport=Named(**httpx_options(settings, ca_file)), **kw)


def httpx_extensions(settings) -> dict:
    """httpx's per-request extensions for calls to the cluster's servers: the name their certificates are
    checked against, when INTERNAL_TLS_SERVER_NAME is set."""
    name = server_name(settings)
    return {"sni_hostname": name} if name else {}
