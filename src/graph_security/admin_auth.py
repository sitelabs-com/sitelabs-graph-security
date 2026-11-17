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

"""Logging in to the admin endpoints: a challenge, answered with a
key that has the admin role. The key never crosses the network, and what the server holds of it
(API_KEYS) isn't enough to log in.

    1. GET  /admin/challenge                       -> {"nonce": "9f2c...", "expires_in": 60}
    2. the client computes answer(key, nonce)
    3. POST /admin/login {"nonce", "response"}     -> {"token": "...", "expires_in": 900}
    4. Authorization: Bearer <token> on every admin call, until it expires or POST /admin/logout

**The answer** is SCRAM's (RFC 5802), without its channel: with client = sha256(key) and hash =
sha256(client), the server's entry, the response is client XOR HMAC-SHA256(hash, nonce). The server
computes the HMAC from its hash, recovers client, and checks that sha256(client) is the hash. So the
response proves the client knows sha256(key), which the entry doesn't give away.

* **A nonce is used once**, and only within ADMIN_CHALLENGE_SECONDS (60). A captured answer can't be
  replayed: its nonce is gone.
* **A token** names the key that logged in and when it expires (ADMIN_TOKEN_SECONDS, 900, after
  login), signed with SESSION_SECRET (HMAC-SHA256). So it holds across a restart, and at every server
  that shares SESSION_SECRET (another server of the cluster, one that takes over); without one, a
  random secret is made at startup, a restart logs everyone out, and a login works only at the
  server that gave it. It works only while the key it logged in with is in
  API_KEYS with an admin role: removing or replacing the key ends its logins. A logout ends the token
  at this server (it is remembered until it would have expired).
* **Wrong answers** are counted per caller's address: after ADMIN_MAX_FAILURES (5) in a row, that
  address is refused (429) for ADMIN_LOCKOUT_SECONDS (300).
* **No key with the admin role**: the admin endpoints are off (403), so nothing destructive can be
  reached.

No transport security of its own: put TLS in front. See docs/references/planning/TODO.md#security.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import secrets
import threading
import time
from typing import Callable

from graph_security.errors import AdminRefused  # noqa: F401  (re-exported)

log = logging.getLogger(__name__)


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _sign(entry_hash: str, nonce: str) -> bytes:
    return hmac.new(entry_hash.encode(), nonce.encode(), hashlib.sha256).digest()


def answer(key: str, nonce: str) -> str:
    """The response to a challenge, in hex (what a client computes)."""
    client = hashlib.sha256(key.encode()).hexdigest()
    entry_hash = hashlib.sha256(client.encode()).hexdigest()
    return _xor(bytes.fromhex(client), _sign(entry_hash, nonce)).hex()


def proves(response: str, entry_hash: str, nonce: str) -> bool:
    """Whether a response proves knowing the key behind this entry's hash."""
    try:
        proof = bytes.fromhex(response)
    except ValueError:
        return False
    if len(proof) != 32:
        return False
    client = _xor(proof, _sign(entry_hash, nonce)).hex()
    return hmac.compare_digest(hashlib.sha256(client.encode()).hexdigest(), entry_hash)


OIDC_ONLY = ("the admin login is off: OAUTH_OIDC_ACTIVE=True and OIDC_ACCEPT_API_KEYS=False, so an admin "
             "sends a token from the identity provider with the admin role (docs/security/oauth-oidc.md)")


class AdminAuth:
    def __init__(self, keys, challenge_seconds: float = 60.0, token_seconds: float = 900.0,
                 max_failures: int = 5, lockout_seconds: float = 300.0,
                 clock: Callable[[], float] = time.time, off: str = "", secret: str = ""):
        self.keys = keys                              # app/services/api_keys.py: who may log in
        self.off = off                                # why the login is off, when it is off on purpose
        self.challenge_seconds, self.token_seconds = challenge_seconds, token_seconds
        self.max_failures, self.lockout_seconds = max_failures, lockout_seconds
        self.clock = clock                            # wall-clock: tokens are checked by other servers too
        self.secret = (secret or secrets.token_hex(32)).encode()
        self.shared = bool(secret)                    # SESSION_SECRET: tokens outlive this process
        self._nonces: dict[str, float] = {}           # nonce -> when it expires
        self._ended: dict[str, float] = {}            # logged-out tokens' ids -> when they'd have expired
        self._failures: dict[str, tuple[int, float]] = {}   # caller -> (failures in a row, locked until)
        self._lock = threading.Lock()

    @property
    def enabled(self) -> bool:
        return bool(self.keys.admins)

    def _on(self) -> None:
        if not self.enabled:
            raise AdminRefused(403, self.off or "the admin endpoints are off: no key in API_KEYS has the admin role")

    def _sweep(self, now: float) -> None:
        self._nonces = {n: t for n, t in self._nonces.items() if t > now}
        self._ended = {k: t for k, t in self._ended.items() if t > now}

    def challenge(self) -> dict:
        self._on()
        nonce = secrets.token_hex(16)
        with self._lock:
            now = self.clock()
            self._sweep(now)
            if len(self._nonces) >= 10_000:            # a flood of challenges: don't grow without end
                raise AdminRefused(429, "too many challenges outstanding: try again shortly", 5)
            self._nonces[nonce] = now + self.challenge_seconds
        return {"nonce": nonce, "expires_in": int(self.challenge_seconds)}

    def login(self, nonce: str, response: str, caller: str) -> dict:
        """A token for a right answer to a live nonce, and whose it is. The nonce is used up either way."""
        self._on()
        with self._lock:
            now = self.clock()
            failures, until = self._failures.get(caller, (0, 0.0))
            if until > now:
                raise AdminRefused(429, f"too many wrong answers from {caller}: try again in "
                                        f"{until - now:.0f} s", int(until - now) + 1)
            live = self._nonces.pop(nonce, 0.0) > now
            hit = next(((n, h) for n, h in self.keys.admins if proves(response or "", h, nonce)), None)
            if not (live and hit):
                failures += 1
                locked = now + self.lockout_seconds if failures >= self.max_failures else 0.0
                self._failures[caller] = (0 if locked else failures, locked)
                raise AdminRefused(401, "the challenge was not answered: " +
                                   ("the nonce is unknown, used or expired" if not live else "wrong response"))
            self._failures.pop(caller, None)
            token = self._sign({"n": hit[0], "k": _hash(hit[1])[:16], "e": round(now + self.token_seconds),
                                "i": secrets.token_hex(8)})
        return {"token": token, "expires_in": int(self.token_seconds), "name": hit[0]}

    def _sign(self, claims: dict) -> str:
        body = _b64(json.dumps(claims, separators=(",", ":")).encode())
        return f"{PREFIX}{body}~{_b64(hmac.new(self.secret, body.encode(), hashlib.sha256).digest())}"

    def _claims(self, token: str) -> dict | None:
        if not token.startswith(PREFIX) or token.count("~") != 2:
            return None
        body, sig = token[len(PREFIX):].split("~")
        good = _b64(hmac.new(self.secret, body.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(sig, good):
            return None
        try:
            claims = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
        except ValueError:
            return None
        return claims if isinstance(claims, dict) and {"n", "k", "e", "i"} <= claims.keys() else None

    def check(self, token: str) -> str:
        """The name of the key that logged in; AdminRefused unless `token` is a live login's, and its
        key is still in API_KEYS with an admin role."""
        self._on()
        if not token:
            raise AdminRefused(401, "an admin call needs Authorization: Bearer <token>, from POST /admin/login")
        claims = self._claims(token)
        now = self.clock()
        if claims is None or claims["e"] <= now:
            raise AdminRefused(401, "the admin token is unknown or expired: log in again"
                               + ("" if self.shared else " (a server without SESSION_SECRET forgets its logins "
                                                         "when it restarts, and knows only its own)"))
        with self._lock:
            if claims["i"] in self._ended:
                raise AdminRefused(401, "the admin token was logged out: log in again")
        if not any(n == claims["n"] and _hash(h)[:16] == claims["k"] for n, h in self.keys.admins):
            raise AdminRefused(401, f"the key {claims['n']!r} that logged in is no longer an admin key in API_KEYS "
                                    "(removed, replaced or expired): log in again")
        return claims["n"]

    def logout(self, token: str) -> None:
        claims = self._claims(token)
        if claims is not None:
            with self._lock:
                self._sweep(self.clock())
                self._ended[claims["i"]] = float(claims["e"])


PREFIX = "pga1~"                                  # an admin login's token: never three dot-separated parts (a JWT's)


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()
