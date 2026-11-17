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

"""The checks on each call, and the sign-in endpoints, in a FastAPI application wired as the
applications wire them."""
from types import SimpleNamespace

import pytest
from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

from graph_security.admin_auth import AdminAuth, answer
from graph_security.errors import AdminRefused
from graph_security.keys import ApiKeys, new_key
from graph_security.limits import Limits
from graph_security.sessions import Sessions
from graph_security.settings import SecuritySettings
from graph_security.web import Security
from tests.test_oidc import OIDC, Provider, oidc

ADMIN, ADMIN_ENTRY = new_key("boss", "admin")
WRITER, WRITER_ENTRY = new_key("loader", "write")
READER, READER_ENTRY = new_key("reports", "read")
ENTRIES = [ADMIN_ENTRY, WRITER_ENTRY, READER_ENTRY]


def build(entries=ENTRIES, oidc_=None, limits=None, settings=None):
    keys = ApiKeys(entries)
    state = SimpleNamespace(keys=keys, admin=AdminAuth(keys, secret="s" * 64), sessions=Sessions(keys, b"x" * 32, cookie="t_session"),
                            limits=limits or Limits(), oidc=oidc_)
    seen, audited = [], []
    sec = Security(parts=lambda r: r.app.state.parts, settings=lambda r: settings or SecuritySettings(),
                   cookie="t_session", sso_cookie="t_sso", open_name="anyone",
                   on_caller=lambda r, p: seen.append(p.name), on_admin=lambda r: setattr(r.state, "audit", True),
                   audit=lambda action, message, *a, **kw: audited.append((action, kw.get("outcome"))))
    app = FastAPI()
    app.state.parts = state

    @app.exception_handler(AdminRefused)
    def _refused(request, ex):
        realm = {"admin": "t-admin", "api": "t"}[ex.scope]
        headers = {"WWW-Authenticate": f'Bearer realm="{realm}"'} if ex.status == 401 else {}
        if ex.retry_after:
            headers["Retry-After"] = str(ex.retry_after)
        return JSONResponse(status_code=ex.status, content={"error": str(ex)}, headers=headers)

    @app.get("/read")
    def read(p=Depends(sec.permission("query"))):
        return {"name": p.name, "role": p.role.name}

    @app.post("/write")
    def write(request: Request, p=Depends(sec.permission("query"))):
        sec.demand(request, "write")
        return {"name": p.name}

    @app.post("/manage", dependencies=[Depends(sec.running)])
    def manage(request: Request, p=Depends(sec.permission("manage"))):
        return {"name": p.name, "audit": getattr(request.state, "audit", False)}

    @app.post("/admin/login")
    def login(body: dict):
        return state.admin.login(body["nonce"], body["response"], "test")

    app.include_router(sec.session_router())
    return TestClient(app), state, seen, audited


def token(c, state, key=ADMIN):
    nonce = state.admin.challenge()["nonce"]
    return c.post("/admin/login", json={"nonce": nonce, "response": answer(key, nonce)}).json()["token"]


def k(key):
    return {"X-API-Key": key}


def test_each_role_gets_only_what_it_may_do():
    c, state, seen, _ = build()
    r = c.get("/read")
    assert r.status_code == 401 and "an API key is needed" in r.json()["error"]
    assert r.headers["www-authenticate"] == 'Bearer realm="t"'
    assert c.get("/read", headers=k("nonsense")).json()["error"] == "this API key is not one of API_KEYS"
    assert c.get("/read", headers=k(READER)).json() == {"name": "reports", "role": "read"} and seen[-1] == "reports"
    r = c.post("/write", headers=k(READER))
    assert r.status_code == 403 and "the write permission" in r.json()["error"]
    assert c.post("/write", headers=k(WRITER)).status_code == 200
    r = c.post("/manage", headers=k(WRITER))
    assert r.status_code == 403
    r = c.post("/manage")                                         # nothing at all: a login is asked for
    assert r.status_code == 401 and r.headers["www-authenticate"] == 'Bearer realm="t-admin"' 
    r = c.post("/manage", headers=k(ADMIN))                       # an admin key, but no login
    assert r.status_code == 401 and "needs a login" in r.json()["error"]
    assert r.headers["www-authenticate"] == 'Bearer realm="t-admin"'
    r = c.post("/manage", headers={"Authorization": "Bearer " + token(c, state)})
    assert r.json() == {"name": "boss", "audit": True}


def test_an_admin_login_ends_with_its_key():
    c, state, _, _ = build()
    t = token(c, state)
    r = c.get("/read", headers={"Authorization": "Bearer junk"})
    assert r.status_code == 401 and r.headers["www-authenticate"] == 'Bearer realm="t-admin"'
    state.keys.keys = ApiKeys([new_key("boss", "admin")[1], WRITER_ENTRY]).keys   # the admin key replaced
    r = c.post("/manage", headers={"Authorization": "Bearer " + t})
    assert r.status_code == 401 and "no longer an admin key" in r.json()["error"]
    state.keys.keys = ApiKeys([WRITER_ENTRY]).keys                # no admin key at all: the admin endpoints are off
    assert c.post("/manage", headers={"Authorization": "Bearer " + t}).status_code == 403


def test_with_no_keys_every_endpoint_is_open_and_there_is_nothing_to_sign_in_to():
    c, _, seen, _ = build(entries=[])
    assert c.get("/read").json() == {"name": "anyone", "role": "admin"}
    assert c.post("/manage").status_code == 200
    r = c.post("/session", headers=k("x"))
    assert r.status_code == 401 and "nothing to sign in to" in r.json()["error"]


def test_a_browser_session_only_reads_and_ends():
    c, _, _, audited = build()
    assert c.post("/session").status_code == 401                  # no key, no token
    r = c.post("/session", headers=k(WRITER))
    assert r.status_code == 200 and r.json()["name"] == "loader" and "t_session" in r.cookies
    assert ("session.start", "done") in audited
    assert c.get("/session").json()["signed_in"] and c.get("/read").json()["name"] == "loader"
    assert c.post("/write").status_code == 403                    # a session only reads
    r = c.post("/manage")                                         # a session is never an admin: log in
    assert r.status_code == 401 and r.headers["www-authenticate"] == 'Bearer realm="t-admin"'
    assert c.delete("/session").json() == {"signed_out": True}
    assert c.get("/session").json() == {"signed_in": False} and c.get("/read").status_code == 401


def test_tokens_from_an_identity_provider():
    p = Provider()
    c, _, _, _ = build(oidc_=oidc(p))
    assert c.get("/read", headers={"Authorization": "Bearer " + p.token()}).json() == {"name": "ann", "role": "read"}
    assert c.post("/manage", headers={"Authorization": "Bearer " + p.token(roles=["graph-admin"])}).status_code == 200
    assert c.post("/manage", headers={"Authorization": "Bearer " + p.token(roles=["graph-write"])}).status_code == 403
    assert c.get("/read", headers=k(READER)).status_code == 200    # keys still work
    r = c.get("/read")
    assert r.status_code == 401 and "a token from the identity provider is needed" in r.json()["error"]
    only = build(oidc_=oidc(p, oidc_accept_api_keys=False))[0]
    r = only.get("/read", headers=k(READER))
    assert r.status_code == 401 and "API keys are off" in r.json()["error"]
    assert only.get("/read", headers={"Authorization": "Bearer " + p.token()}).status_code == 200


def test_the_sign_in_at_the_identity_provider_starts_with_pkce():
    p = Provider()
    s = SecuritySettings(**OIDC, oidc_console_client_id="console")
    c, _, _, _ = build(oidc_=oidc(p), settings=s)
    p_fetch = p.fetch
    p.fetch = lambda url: {**p_fetch(url), "authorization_endpoint": "https://idp.example.com/auth"} \
        if url.endswith("openid-configuration") else p_fetch(url)
    c.app.state.parts.oidc = oidc(p)
    r = c.get("/console/sso/start", params={"next": "//evil.example.com"}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"].startswith("https://idp.example.com/auth?")
    assert "code_challenge_method=S256" in r.headers["location"] and "t_sso" in r.cookies
    r = c.get("/console/sso/callback", params={"state": "wrong", "code": "x"}, follow_redirects=False)
    assert r.status_code == 303 and "signin_error" in r.headers["location"]


def test_rate_limits_and_work_at_once():
    c, _, _, _ = build(limits=Limits(rate=1, burst=1))
    assert c.get("/read", headers=k(READER)).status_code == 200
    r = c.get("/read", headers=k(READER))
    assert r.status_code == 429 and r.headers["retry-after"] == "1"
    assert c.get("/read", headers=k(WRITER)).status_code == 200    # each caller its own
