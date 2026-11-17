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

"""The checks on each call, for FastAPI: who the caller is, whether their role may do what the call
does, their rate limit, and the browser sign-in endpoints.

    SECURITY = Security(parts=lambda request: request.app.state, settings=lambda request: get_settings(),
                        cookie="app_session", sso_cookie="app_sso", on_caller=..., audit=...)
    router = APIRouter(dependencies=[Depends(SECURITY.permission("query"))])
    SECURITY.demand(request, "write")                # inside an endpoint, once it knows it writes
    app.include_router(SECURITY.session_router())    # GET/POST/DELETE /session, /console/sso/...

`parts(request)` gives the object holding this server's `keys` (graph_security.keys.ApiKeys, or
anything like it), `admin` (admin_auth.AdminAuth), `sessions` (sessions.Sessions), `limits`
(limits.Limits) and `oidc` (oidc.Oidc, or None). They are looked up at every call, so they can be
replaced while the server runs.

A caller is, in this order:

1. **an access token** from the identity provider (`Authorization: Bearer <JWT>`), with OAUTH_OIDC_ACTIVE;
2. **an admin login's token** (`Authorization: Bearer <token>`, from POST /admin/login);
3. **a browser session's cookie**, when the call has no key: it may only query;
4. **an API key** (`X-API-Key`), unless OIDC_ACCEPT_API_KEYS=False.

With no keys and no identity provider (development), every caller is let in with the admin role,
the admin endpoints too. An admin-only permission (the catalogue's `admin_only`, or "admin": any
role built on admin) also needs a login: an admin login's token or an identity provider's (recent
enough, with OIDC_ADMIN_MAX_AGE_SECONDS). Refusals are KeyRefused or AdminRefused (401, 403, 429,
503): the application answers them (`scope` names the realm).
"""
from __future__ import annotations

import base64
import hashlib
import logging
import secrets
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Callable

from fastapi import APIRouter, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse, RedirectResponse

from graph_security.errors import AdminRefused, KeyRefused
from graph_security.keys import digest
from graph_security.oidc import Caller, exchange_code, looks_like_jwt
from graph_security.roles import Catalogue, Role, default
from graph_security.sessions import SSO_SECONDS

log = logging.getLogger(__name__)
TOKEN_NEEDED = ("a token from the identity provider is needed: Authorization: Bearer <access token> "
                "(docs/security/oauth-oidc.md)")


@dataclass(frozen=True)
class Principal:
    """Who is calling, and with what."""

    name: str
    role: Role
    logged_in: bool = False                     # an admin login's token, or an identity provider's
    claims: dict | None = field(default=None, compare=False, repr=False)   # the identity provider's token's
    open: bool = False                          # no keys and no identity provider: development
    key: str = field(default="", compare=False, repr=False)                # the API key it came with ("": none)


def bearer(request: Request) -> str:
    h = request.headers.get("authorization", "")
    return h[7:].strip() if h[:7].lower() == "bearer " else ""


def address(request: Request) -> str:
    return getattr(getattr(request, "client", None), "host", None) or "unknown"


def _noop(*args, **kwargs) -> None:
    return None


class Security:
    """One per application. `on_caller(request, principal)` is called as soon as the caller is known
    (for the logs, and the application's own request state); `on_admin(request)` when a call needs
    an admin permission (for the audit log); `audit(action, message, level=INFO, **fields)` writes
    the audit log's sign-in lines."""

    def __init__(self, parts: Callable[[Request], Any], settings: Callable[[Request], Any], *,
                 cookie: str, sso_cookie: str, catalogue: Catalogue | None = None, open_name: str = "",
                 on_caller: Callable[[Request, Principal], None] = _noop, on_admin: Callable[[Request], None] = _noop,
                 audit: Callable[..., None] = _noop,
                 admin_login_help: str = "GET /admin/challenge, then POST /admin/login, then Authorization: Bearer <token>",
                 key_help: str = "X-API-Key: <key>"):
        self.parts, self.settings = parts, settings
        self.cookie, self.sso_cookie = cookie, sso_cookie
        self._catalogue = catalogue
        self.open_name = open_name
        self.on_caller, self.on_admin, self.audit = on_caller, on_admin, audit
        self.admin_login_help, self.key_help = admin_login_help, key_help

    @property
    def catalogue(self) -> Catalogue:
        return self._catalogue or default()

    # -- who --------------------------------------------------------------------------------------- #
    def is_open(self, request: Request) -> bool:
        """No keys and no identity provider (development): every endpoint open, the admin ones too."""
        p = self.parts(request)
        return not p.oidc and not p.keys.enabled

    def identify(self, request: Request) -> Principal:
        """The caller; KeyRefused (401, 403, 503) for a missing or refused key or token, AdminRefused
        (401) for a dead admin login."""
        p = self.parts(request)
        if self.is_open(request):
            return Principal(self.open_name, self.catalogue.open, True, open=True)
        oidc, token = p.oidc, bearer(request)
        if token:
            if oidc and looks_like_jwt(token):
                c = oidc.verify(token)
                return Principal(c.name, c.role, True, c.claims)
            if oidc and not oidc.accept_api_keys:
                raise KeyRefused(401, TOKEN_NEEDED)
            name = p.admin.check(token)
            found = p.keys.named(name)
            if found is None:                                  # removed or expired since the token was checked
                raise AdminRefused(401, f"the key {name!r} logged in with is no longer in API_KEYS: log in again")
            return Principal(name, found.role, True)
        key = request.headers.get("x-api-key", "").strip()
        if not key:
            session = p.sessions.caller(request)
            if session is not None:
                return Principal(*session)
        if oidc and not oidc.accept_api_keys:
            raise KeyRefused(401, ("API keys are off (OIDC_ACCEPT_API_KEYS=False): " if key else "") + TOKEN_NEEDED)
        found = p.keys.find(key)
        if found is None:
            if not key:
                raise KeyRefused(401, f"{TOKEN_NEEDED}, or an API key: {self.key_help}" if oidc else
                                 f"an API key is needed: {self.key_help}")
            raise KeyRefused(401, "this API key is not one of API_KEYS")
        if found.expired(p.keys.clock()):
            raise KeyRefused(401, f"the API key {found.name!r} expired at the end of {found.last_day}: ask for a new one")
        return Principal(found.name, found.role, key=key)

    def identify_admin(self, request: Request) -> Principal:
        """The caller of an admin call: as identify(), but a call with no key and no token (a browser
        session is never an admin) is AdminRefused 401, asking for a login."""
        if not self.is_open(request) and not bearer(request) and not request.headers.get("x-api-key", "").strip():
            raise AdminRefused(401, f"an admin call needs a login: {self.admin_login_help}")
        return self.identify(request)

    def caller(self, request: Request) -> Principal | None:
        """The caller this request was checked as, or None."""
        return getattr(request.state, "principal", None)

    def _known(self, request: Request, principal: Principal) -> None:
        request.state.principal = principal
        self.on_caller(request, principal)

    # -- what it may do ---------------------------------------------------------------------------- #
    def allow(self, request: Request, principal: Principal, permission: str) -> None:
        """KeyRefused 403 unless the role has `permission` ("admin": any role built on admin); for an
        admin permission, AdminRefused 401 without a login."""
        cat = self.catalogue
        admin = permission == "admin" or permission in cat.admin_only
        if admin:
            self.on_admin(request)
        allowed = principal.role.admin if permission == "admin" else principal.role.may(permission)
        if not allowed:
            what = "an admin role" if permission == "admin" else f"the {permission} permission ({cat.permissions[permission]})"
            raise KeyRefused(403, f"this needs {what}; {principal.name!r} has the role {principal.role}, which hasn't it "
                                  "(docs/security/roles.md)")
        if admin and principal.claims is not None:
            self.parts(request).oidc.check_recent(Caller(principal.name, principal.role, principal.claims))
        if admin and not principal.logged_in:
            raise AdminRefused(401, f"an admin call needs a login: {self.admin_login_help}")

    def count(self, request: Request, principal: Principal) -> None:
        """The caller's rate limit, once per request (KeyRefused 429 past it)."""
        limits = self.parts(request).limits
        if limits is None or getattr(request.state, "counted", False):
            return
        request.state.counted = True
        limits.check(principal.name if not principal.open and principal.name else address(request), principal.role.name)

    def check(self, request: Request, permission: str) -> Principal:
        """The caller, if their role may do `permission`: identified, allowed and counted."""
        assert permission == "admin" or permission in self.catalogue.permissions, permission
        admin = permission == "admin" or permission in self.catalogue.admin_only
        principal = self.identify_admin(request) if admin else self.identify(request)
        self._known(request, principal)
        self.allow(request, principal, permission)
        self.count(request, principal)
        return principal

    def demand(self, request: Request, permission: str) -> Principal:
        """Inside an endpoint, once it knows what the call does: refused unless the caller may do it."""
        principal = self.caller(request)
        if principal is None:
            return self.check(request, permission)
        self.allow(request, principal, permission)
        return principal

    def permission(self, name: str):
        """A FastAPI dependency: the caller, whose role has this permission."""
        assert name == "admin" or name in self.catalogue.permissions, name

        async def dependency(request: Request) -> Principal:   # async: the caller stays on the request's context
            return self.check(request, name)
        dependency.__name__ = f"require_{name}"
        return dependency

    async def running(self, request: Request):
        """A FastAPI dependency: one of the caller's MAX_RUNNING_PER_CALLER places, while the call runs."""
        limits = self.parts(request).limits
        if limits is None:
            yield
            return
        p = self.caller(request)
        with limits.running(p.name if p is not None and not p.open and p.name else address(request)):
            yield

    # -- signing in from a browser ----------------------------------------------------------------- #
    def session_router(self) -> APIRouter:
        """GET, POST and DELETE /session, and the sign-in at the identity provider (/console/sso/...)."""
        return _session_router(self)


def secure(request: Request) -> bool:
    """Whether the browser reached us over https (itself, or through a proxy we believe: uvicorn sets the scheme)."""
    return request.url.scheme == "https"


def safe_next(value: str | None) -> str:
    """A path on this server to go to after signing in, or "": never another site."""
    v = (value or "").strip()
    if not v.startswith("/") or v.startswith("//") or "\\" in v or any(ord(c) < 32 for c in v):
        return ""
    return v


def _set(response, request: Request, name: str, value: str, seconds: int, path: str = "/",
         samesite: str = "strict") -> None:
    response.set_cookie(name, value, max_age=seconds, path=path, httponly=True, samesite=samesite,
                        secure=secure(request))


def _console_error(why: str) -> RedirectResponse:
    return RedirectResponse("/console?" + urllib.parse.urlencode({"signin_error": why[:300]}), status_code=303)


def _session_router(sec: Security) -> APIRouter:
    router = APIRouter(tags=["session"])

    def redirect_uri(request: Request) -> str:
        return sec.settings(request).oidc_console_redirect_uri or str(request.url_for("sso_callback"))

    def done(request: Request, response):
        response.delete_cookie(sec.sso_cookie, path="/console/sso", httponly=True, samesite="lax", secure=secure(request))
        return response

    @router.get("/session")
    def current(request: Request):
        """Who this browser is signed in as."""
        s = sec.parts(request).sessions
        claims = s.read(request.cookies.get(sec.cookie, ""))
        if claims is None:
            return {"signed_in": False}                # 200: the console asks at every load
        return {"signed_in": True, "name": claims["n"], "role": claims["r"],
                "expires_in": max(0, int(claims["e"] - s.clock()))}

    @router.post("/session")
    async def start(request: Request):
        """A session for the key (X-API-Key) or token (Authorization: Bearer) this call is made with."""
        p = sec.parts(request)
        key = request.headers.get("x-api-key", "").strip()
        if not (key or bearer(request)):
            raise KeyRefused(401, "send the key (X-API-Key) or a token (Authorization: Bearer) to sign in with")
        principal = sec.identify(request)
        if principal.open:
            raise KeyRefused(401, "this server needs no key (no API_KEYS): there is nothing to sign in to")
        sec._known(request, principal)
        sec.count(request, principal)
        found = p.keys.find(principal.key) if principal.key else None
        value, seconds = p.sessions.make(principal.name, principal.role, digest(principal.key) if found else "")
        sec.audit("session.start", f"browser session for {principal.name} ({principal.role})", outcome="done",
                  how="key" if found else "token")
        response = JSONResponse({"name": principal.name, "role": principal.role.name, "expires_in": seconds})
        _set(response, request, sec.cookie, value, seconds)
        return response

    @router.delete("/session")
    def end(request: Request):
        """Sign this browser out."""
        sessions = sec.parts(request).sessions
        value = request.cookies.get(sec.cookie, "")
        claims = sessions.read(value)
        sessions.end(value)
        if claims is not None:
            sec.on_caller(request, Principal(claims["n"], Role(claims["r"], "read", frozenset())))
            sec.audit("session.end", f"browser session of {claims['n']} ended", outcome="done")
        response = JSONResponse({"signed_out": True})
        response.delete_cookie(sec.cookie, path="/", httponly=True, samesite="strict", secure=secure(request))
        return response

    @router.get("/console/sso/start", include_in_schema=False)
    async def sso_start(request: Request, next: str | None = None):
        """To the identity provider's sign-in page, with a fresh state and PKCE challenge."""
        s, p = sec.settings(request), sec.parts(request)
        if p.oidc is None or not s.oidc_console_client_id:
            return _console_error("this server has no sign-in at an identity provider (OAUTH_OIDC_ACTIVE, "
                                  "OIDC_CONSOLE_CLIENT_ID)")
        try:
            authorize = await run_in_threadpool(p.oidc.endpoint, "authorization_endpoint")
        except Exception as ex:
            log.warning("the console's sign-in can't start: %s", ex)
            return _console_error("the identity provider can't be reached: try again shortly")
        state, verifier = secrets.token_urlsafe(24), secrets.token_urlsafe(48)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
        params = {"response_type": "code", "client_id": s.oidc_console_client_id, "redirect_uri": redirect_uri(request),
                  "scope": s.oidc_console_scopes, "state": state, "code_challenge": challenge,
                  "code_challenge_method": "S256"}
        for extra in s.oidc_console_auth_params:
            k, _, v = extra.partition("=")
            params.setdefault(k.strip(), v.strip())
        sep = "&" if "?" in authorize else "?"
        response = RedirectResponse(authorize + sep + urllib.parse.urlencode(params), status_code=303)
        pending = p.sessions.sso.sign({"s": state, "v": verifier, "n": safe_next(next), "e": round(time.time() + SSO_SECONDS)})
        _set(response, request, sec.sso_cookie, pending, SSO_SECONDS, path="/console/sso",
             samesite="lax")                         # it comes back from the provider's site: Strict wouldn't be sent
        return response

    @router.get("/console/sso/callback", name="sso_callback", include_in_schema=False)
    async def sso_callback(request: Request, code: str = "", state: str = "", error: str = "",
                           error_description: str = ""):
        """Back from the identity provider: the code exchanged for a token, which is checked, and the session set."""
        s, p = sec.settings(request), sec.parts(request)
        pending = p.sessions.sso.read(request.cookies.get(sec.sso_cookie, ""))
        if error:
            sec.audit("session.start", f"sign-in at the identity provider refused: {error}", logging.WARNING,
                      outcome="refused")
            return done(request, _console_error(f"{error}: {error_description}" if error_description else error))
        if p.oidc is None or pending is None or pending.get("e", 0) <= time.time() or not secrets.compare_digest(
                str(pending.get("s", "")), state or "-"):
            sec.audit("session.start", "sign-in at the identity provider refused: no sign-in under way, or another's",
                      logging.WARNING, outcome="refused")
            return done(request, _console_error("the sign-in expired or was not started here: sign in again"))
        try:
            token_url = await run_in_threadpool(p.oidc.endpoint, "token_endpoint")
            answer = await run_in_threadpool(exchange_code, token_url, {
                "grant_type": "authorization_code", "code": code, "redirect_uri": redirect_uri(request),
                "client_id": s.oidc_console_client_id, "code_verifier": pending["v"]})
            token = answer.get("access_token") if isinstance(answer, dict) else None
            if not isinstance(token, str):
                raise ValueError("the identity provider's answer has no access_token")
            c = p.oidc.verify(token)                   # as any token: issuer, audience, expiry, role
        except KeyRefused as ex:
            sec.audit("session.start", f"sign-in at the identity provider refused ({ex.status}): {ex}", logging.WARNING,
                      outcome="refused")
            return done(request, _console_error(str(ex)))
        except Exception as ex:
            sec.audit("session.start", f"sign-in at the identity provider failed: {type(ex).__name__}: {str(ex)[:200]}",
                      logging.WARNING, outcome="failed")
            return done(request, _console_error(str(ex)[:200] or type(ex).__name__))
        try:
            value, seconds = p.sessions.make(c.name, c.role)
        except KeyRefused as ex:
            return done(request, _console_error(str(ex)))
        sec.on_caller(request, Principal(c.name, c.role, True, c.claims))
        sec.audit("session.start", f"browser session for {c.name} ({c.role}), from the identity provider",
                  outcome="done", how="sso")
        response = done(request, RedirectResponse(pending.get("n") or "/console", status_code=303))
        _set(response, request, sec.cookie, value, seconds)
        return response

    return router
