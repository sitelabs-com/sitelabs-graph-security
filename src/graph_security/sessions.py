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

"""Browser sessions: a console's sign-in.

A session is a cookie (`cookie`, named by the application) that names who signed in, their role and when it ends
(SESSION_SECONDS, 8 hours, after signing in), signed with SESSION_SECRET (HMAC-SHA256). It is
HttpOnly (no script reads it), SameSite=Strict (no other site's page sends it) and, over https,
Secure. It is made by:

* **POST /session** with an API key (X-API-Key) or an access token (Authorization: Bearer), once;
* **signing in at the identity provider** (GET /console/sso/start), with OIDC_CONSOLE_CLIENT_ID:
  the server sends the browser to the provider (authorization code with PKCE), exchanges the
  code for an access token itself, checks it as it checks any token, and sets the cookie. The token
  never reaches the browser.

**A session only reads**: of its role's permissions it keeps `query` alone, so it can't write, load,
or log in as an admin, whatever its role. A session made with a key ends as soon as the key
is removed, replaced or expires (it is checked at every call). One made at the identity provider
keeps the role it signed in with until it ends. DELETE /session signs out: the cookie is dropped,
and this server remembers it ended.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import threading
import time
from typing import Callable

from graph_security.errors import KeyRefused
from graph_security.roles import Role

COOKIE = "graph_session"              # the default; each application names its own: cookies are per host, not per port
SSO_COOKIE = "graph_sso"                         # the sign-in under way: its state, PKCE verifier and where to go after
SESSION_PERMISSIONS = frozenset({"query"})
SSO_SECONDS = 600                               # a sign-in at the provider must come back within this


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class Signer:
    """Values signed with SESSION_SECRET, for a purpose (so one kind can't be passed off as another)."""

    def __init__(self, secret: bytes, purpose: str):
        self.secret, self.purpose = secret, purpose.encode()

    def _mac(self, body: str) -> str:
        return _b64(hmac.new(self.secret, self.purpose + b"|" + body.encode(), hashlib.sha256).digest())

    def sign(self, claims: dict) -> str:
        body = _b64(json.dumps(claims, separators=(",", ":")).encode())
        return f"{body}.{self._mac(body)}"

    def read(self, value: str) -> dict | None:
        body, _, sig = (value or "").partition(".")
        if not body or not sig or not hmac.compare_digest(sig, self._mac(body)):
            return None
        try:
            claims = json.loads(_unb64(body))
        except ValueError:
            return None
        return claims if isinstance(claims, dict) else None


def key_mark(entry_hash: str) -> str:
    """What a session or an admin login keeps of its key's entry: enough to tell it was replaced."""
    return hashlib.sha256(entry_hash.encode()).hexdigest()[:16]


class Sessions:
    def __init__(self, keys, secret: bytes, seconds: float = 28800.0, clock: Callable[[], float] = time.time,
                 cookie: str = COOKIE):
        self.keys, self.seconds, self.clock, self.cookie = keys, seconds, clock, cookie
        self.cookies = Signer(secret, "session")
        self.sso = Signer(secret, "sso")
        self._ended: dict[str, float] = {}
        self._lock = threading.Lock()

    def make(self, name: str, role: Role, entry_hash: str = "") -> tuple[str, int]:
        """(the cookie's value, its lifetime in seconds) for a caller who has just proved who they are."""
        now = self.clock()
        claims = {"n": name, "r": role.name, "b": role.base, "p": sorted(role.permissions & SESSION_PERMISSIONS),
                  "e": round(now + self.seconds), "i": secrets.token_hex(8)}
        if entry_hash:
            claims["k"] = key_mark(entry_hash)
        if not claims["p"]:
            raise KeyRefused(403, f"the role {role} has no query permission: a browser session would do nothing")
        return self.cookies.sign(claims), int(self.seconds)

    def read(self, value: str) -> dict | None:
        """A live session's claims, or None."""
        claims = self.cookies.read(value)
        if claims is None or not {"n", "r", "b", "p", "e", "i"} <= claims.keys() or claims["e"] <= self.clock():
            return None
        with self._lock:
            if claims["i"] in self._ended:
                return None
        if "k" in claims:                                       # made with a key: only while that key is
            key = self.keys.named(claims["n"])
            if key is None or not any(key_mark(h) == claims["k"] for h, k in self.keys.keys.items() if k is key):
                return None
        return claims

    def caller(self, request) -> tuple[str, Role] | None:
        """(name, role) of the request's session (its role cut to what a session may do), or None."""
        value = request.cookies.get(self.cookie)
        if not value:
            return None
        claims = self.read(value)
        if claims is None:
            return None
        return claims["n"], Role(claims["r"], "read", frozenset(claims["p"]) & SESSION_PERMISSIONS)   # sees its own queries only

    def end(self, value: str) -> None:
        claims = self.cookies.read(value)
        if claims and "i" in claims:
            with self._lock:
                now = self.clock()
                self._ended = {k: t for k, t in self._ended.items() if t > now}
                self._ended[claims["i"]] = float(claims.get("e", now))
