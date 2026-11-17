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

"""Access tokens from an OpenID Connect provider, with OAUTH_OIDC_ACTIVE=True.

The server is an OAuth 2.0 resource server: it checks the tokens a provider issued, and issues
none. A client sends `Authorization: Bearer <access token>`. A token is accepted when:

* it is a JWT signed with one of the provider's keys (its JWKS, found from OIDC_ISSUER's discovery
  document, or OIDC_JWKS_URL), by one of OIDC_ALGORITHMS: asymmetric only, so `none` and HS256 are
  never accepted;
* its `iss` is OIDC_ISSUER, it hasn't expired (`exp`, required) and isn't early (`nbf`), allowing
  OIDC_LEEWAY_SECONDS for the clocks;
* its audience claim (OIDC_AUDIENCE_CLAIM, `aud`; `client_id` for Cognito's access tokens) holds
  OIDC_AUDIENCE;
* its role claim (OIDC_ROLE_CLAIM, a dotted path such as `realm_access.roles`) holds a value that
  OIDC_ROLE_MAP maps to read, write, admin or one of CUSTOM_ROLES (graph_security.roles). With
  several, the caller has the permissions of all of them.

The caller's name, for the logs and the audit log, is OIDC_NAME_CLAIM, else `client_id`, `azp` or
`sub`. An admin endpoint also needs a login no older than OIDC_ADMIN_MAX_AGE_SECONDS (from
`auth_time`), when that is set.

The provider's keys are kept, and fetched again every OIDC_JWKS_REFRESH_SECONDS, or sooner when a
token names a key that isn't among them (at most every 30 s). A server that can't reach the
provider still starts; tokens are refused (503) until the keys are fetched, and keys already
fetched go on being used while the provider is away. Tokens are never logged.
"""
from __future__ import annotations

import json
import logging
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable

import jwt

from graph_security.errors import KeyRefused as Refused
from graph_security.roles import Role, built_in, combined, default

log = logging.getLogger(__name__)

ASYMMETRIC = ("RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA")
_MIN_REFETCH_SECONDS = 30.0                    # a token naming an unknown key fetches the keys at most this often
_MAX_DOCUMENT = 1024 * 1024                    # discovery documents and key sets are small


def parse_role_map(entries: list[str], roles: dict[str, Role] | None = None) -> dict[str, str]:
    """{the claim's value: a role's name} from OIDC_ROLE_MAP's `role=value` entries. ValueError
    names the first bad one."""
    roles = roles or built_in()
    out: dict[str, str] = {}
    for e in entries:
        role, sep, value = e.strip().partition("=")
        role, value = role.strip(), value.strip()
        if not sep or role not in roles or not value:
            raise ValueError(f"{e.strip()!r} is not role=value, with role read, write, admin or one of "
                             "CUSTOM_ROLES (such as admin=graph-admin)")
        if value in out and out[value] != role:
            raise ValueError(f"the value {value!r} is mapped to both {out[value]} and {role}")
        out[value] = role
    return out


def local(url: str) -> bool:
    """Whether a URL is on this machine (http is allowed there, for development and the tests)."""
    return (urllib.parse.urlparse(url).hostname or "") in ("localhost", "127.0.0.1", "::1")


def problems(settings, catalogue=None) -> list[str]:
    """What is wrong with the OIDC settings, for the application's checks at startup; nothing when it is off."""
    s, out = settings, []
    if not s.oauth_oidc_active:
        return out
    for name in ("oidc_issuer", "oidc_audience", "oidc_role_claim", "oidc_role_map"):
        if not getattr(s, name):
            out.append(f"{name.upper()} is required with OAUTH_OIDC_ACTIVE=True (docs/security/oauth-oidc.md)")
    for name in ("oidc_issuer", "oidc_jwks_url"):
        url = getattr(s, name)
        if url and not (url.startswith("https://") or (url.startswith("http://") and local(url))):
            out.append(f"{name.upper()}={url}: must be https:// (http:// only on this machine)")
    try:
        parse_role_map(s.oidc_role_map, (catalogue or default()).parse_roles(s.custom_roles))
    except ValueError as ex:
        out.append(f"OIDC_ROLE_MAP: {ex}")
    bad = [a for a in s.oidc_algorithms if a not in ASYMMETRIC]
    if bad or not s.oidc_algorithms:
        out.append(f"OIDC_ALGORITHMS: {', '.join(bad) or 'none'} - only asymmetric ones: {', '.join(ASYMMETRIC)}")
    return out


def fetch_json(url: str, timeout: float = 5.0) -> dict:
    """A JSON document from the provider."""
    if not (url.startswith("https://") or (url.startswith("http://") and local(url))):
        raise ValueError(f"won't fetch {url}: https:// only")
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:            # noqa: S310 (https, checked above)
        return json.loads(r.read(_MAX_DOCUMENT + 1)[:_MAX_DOCUMENT])


@dataclass(frozen=True)
class Caller:
    name: str
    role: Role
    claims: dict = field(repr=False, compare=False)


class Keys:
    """The provider's signing keys, by key id."""

    def __init__(self, url: Callable[[], str], fetch: Callable[[str], dict], refresh_seconds: float,
                 clock: Callable[[], float]):
        self.url, self.fetch, self.refresh_seconds, self.clock = url, fetch, refresh_seconds, clock
        self.keys: dict[str, jwt.PyJWK] = {}
        self.fetched = self.tried = float("-inf")
        self._lock = threading.Lock()

    def _refresh(self, now: float) -> None:
        self.tried = now
        try:
            data = self.fetch(self.url())
        except Exception as ex:                         # the provider away: keep what we have
            log.warning("can't fetch the identity provider's keys: %s: %s", type(ex).__name__, str(ex)[:200])
            return
        keys = {}
        for k in data.get("keys", []) if isinstance(data, dict) else []:
            if not isinstance(k, dict) or k.get("use", "sig") != "sig" or not k.get("kid"):
                continue
            try:
                keys[k["kid"]] = jwt.PyJWK(k)
            except jwt.PyJWTError:                      # a kind of key this library can't use
                continue
        if keys:
            self.keys, self.fetched = keys, now
            log.info("the identity provider's signing keys: %d", len(keys))
        else:
            log.warning("the identity provider's key set has no signing keys this server can use")

    def get(self, kid: str) -> jwt.PyJWK | None:
        with self._lock:
            now = self.clock()
            stale = now - self.fetched > self.refresh_seconds
            if (stale or kid not in self.keys) and now - self.tried >= _MIN_REFETCH_SECONDS:
                self._refresh(now)
            return self.keys.get(kid)

    @property
    def have_any(self) -> bool:
        return bool(self.keys)


def _claim(claims: dict, path: str) -> Any:
    """A claim by its dotted path (`realm_access.roles`); a claim whose name has a dot is tried whole first."""
    if path in claims:
        return claims[path]
    v: Any = claims
    for part in path.split("."):
        if not isinstance(v, dict) or part not in v:
            return None
        v = v[part]
    return v


def _values(v: Any) -> list[str]:
    if isinstance(v, str):
        return v.split()                                # a scope claim: "pgraph.read pgraph.write"
    if isinstance(v, (list, tuple)):
        return [x for x in v if isinstance(x, str)]
    return []


class Oidc:
    """Checks access tokens. `fetch` and `clock` are for the tests."""

    def __init__(self, settings, fetch: Callable[[str], dict] = fetch_json,
                 clock: Callable[[], float] = time.time, roles: dict[str, Role] | None = None):
        s = settings
        self.known = roles or default().parse_roles(s.custom_roles)
        self.issuer = s.oidc_issuer                     # exactly as the tokens' iss (Auth0's ends with /)
        self.audience, self.audience_claim = s.oidc_audience, s.oidc_audience_claim or "aud"
        self.role_claim, self.roles = s.oidc_role_claim, parse_role_map(s.oidc_role_map, self.known)
        self.name_claim = s.oidc_name_claim
        self.algorithms = list(s.oidc_algorithms)
        self.leeway, self.admin_max_age = s.oidc_leeway_seconds, s.oidc_admin_max_age_seconds
        self.accept_api_keys = s.oidc_accept_api_keys
        self.fetch, self.clock = fetch, clock
        self._jwks_url = s.oidc_jwks_url
        self._discovery: dict | None = None
        self.keys = Keys(self.jwks_url, fetch, s.oidc_jwks_refresh_seconds, clock)

    def discovery(self) -> dict:
        """The provider's discovery document (whose issuer must be ours), fetched once."""
        if self._discovery is None:
            doc = self.fetch(self.issuer.rstrip("/") + "/.well-known/openid-configuration")
            if not isinstance(doc, dict) or str(doc.get("issuer", "")).rstrip("/") != self.issuer.rstrip("/"):
                raise ValueError(f"the discovery document's issuer is {doc.get('issuer')!r}, not OIDC_ISSUER")
            self._discovery = doc
        return self._discovery

    def endpoint(self, name: str) -> str:
        """An https endpoint from the discovery document: authorization_endpoint, token_endpoint."""
        uri = str(self.discovery().get(name, ""))
        if not (uri.startswith("https://") or (uri.startswith("http://") and local(uri))):
            raise ValueError(f"the discovery document's {name} {uri!r} is not https://")
        return uri

    def jwks_url(self) -> str:
        """OIDC_JWKS_URL, else the discovery document's jwks_uri."""
        if not self._jwks_url:
            doc = self.discovery()
            uri = doc.get("jwks_uri", "")
            if not (uri.startswith("https://") or (uri.startswith("http://") and local(uri))):
                raise ValueError(f"the discovery document's jwks_uri {uri!r} is not https://")
            self._jwks_url = uri
        return self._jwks_url

    def verify(self, token: str) -> Caller:
        """The caller a token names; Refused: 401 for a token refused, 403 for one with no
        mapped role, 503 while the provider's keys can't be fetched."""
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError:
            raise Refused(401, "the bearer token is not a JWT from the identity provider") from None
        alg, kid = header.get("alg"), header.get("kid")
        if alg not in self.algorithms:
            raise Refused(401, f"the token's algorithm {alg!r} is not one of OIDC_ALGORITHMS")
        key = self.keys.get(kid) if isinstance(kid, str) else None
        if key is None:
            if not self.keys.have_any:
                raise Refused(503, "the identity provider's keys can't be fetched yet: try again shortly")
            raise Refused(401, "the token is signed with a key the identity provider doesn't list")
        try:
            claims = jwt.decode(token, key.key, algorithms=[alg], issuer=self.issuer, leeway=self.leeway,
                                options={"require": ["exp", "iss"], "verify_aud": False})
        except jwt.ExpiredSignatureError:
            raise Refused(401, "the token has expired: get a new one from the identity provider") from None
        except jwt.InvalidIssuerError:
            raise Refused(401, "the token is from another issuer than OIDC_ISSUER") from None
        except jwt.PyJWTError as ex:
            raise Refused(401, f"the token was refused: {type(ex).__name__}") from None
        if self.audience not in _values(_claim(claims, self.audience_claim)):
            raise Refused(401, f"the token is not for this API: its {self.audience_claim} doesn't hold OIDC_AUDIENCE")
        name = next((str(claims[c]) for c in (self.name_claim, "client_id", "azp", "sub")
                     if c and isinstance(claims.get(c), (str, int))), "?")
        held = {self.roles[v] for v in _values(_claim(claims, self.role_claim)) if v in self.roles}
        if not held:
            raise Refused(403, f"the token of {name!r} has none of the roles in OIDC_ROLE_MAP "
                                  f"(its {self.role_claim} claim)")
        return Caller(name, combined([self.known[r] for r in sorted(held)]), claims)

    def check_recent(self, caller: Caller) -> None:
        """For the admin endpoints: a login within OIDC_ADMIN_MAX_AGE_SECONDS, when it is set."""
        if self.admin_max_age <= 0:
            return
        at = caller.claims.get("auth_time")
        if not isinstance(at, (int, float)) or self.clock() - at > self.admin_max_age:
            raise Refused(403, f"an admin call needs a login within {self.admin_max_age:g} s "
                                  "(OIDC_ADMIN_MAX_AGE_SECONDS): log in again at the identity provider")


def exchange_code(token_url: str, form: dict, timeout: float = 10.0) -> dict:
    """The provider's answer to an authorization code (the console's sign-in): its access_token."""
    if not (token_url.startswith("https://") or (token_url.startswith("http://") and local(token_url))):
        raise ValueError(f"won't send a code to {token_url}: https:// only")
    req = urllib.request.Request(token_url, data=urllib.parse.urlencode(form).encode(), method="POST",
                                 headers={"Accept": "application/json",
                                          "Content-Type": "application/x-www-form-urlencoded"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:        # noqa: S310 (https, checked above)
            return json.loads(r.read(_MAX_DOCUMENT + 1)[:_MAX_DOCUMENT])
    except urllib.error.HTTPError as ex:                                # the provider's refusal, as it says it
        try:
            body = json.loads(ex.read(4096))
            why = body.get("error_description") or body.get("error") or ""
        except ValueError:
            why = ""
        raise ValueError(f"the identity provider refused the code ({ex.code}{': ' + str(why)[:200] if why else ''})") from None


def looks_like_jwt(token: str) -> bool:
    """A JWT has three parts; the admin login's own tokens have one."""
    return token.count(".") == 2
