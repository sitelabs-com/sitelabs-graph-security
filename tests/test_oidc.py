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

"""Access tokens from an OpenID Connect provider, with no provider: the tests make their own keys,
sign their own tokens and answer the discovery document and the key set themselves."""
import dataclasses
import json
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from graph_security.errors import KeyRefused
from graph_security.oidc import Oidc, looks_like_jwt, parse_role_map, problems
from graph_security.settings import SecuritySettings

ISSUER = "https://idp.example.com/realms/graph"
JWKS = ISSUER + "/protocol/openid-connect/certs"
OIDC = dict(oauth_oidc_active=True, oidc_issuer=ISSUER, oidc_audience="graph-api", oidc_role_claim="realm_access.roles",
            oidc_role_map=["admin=graph-admin", "write=graph-write", "read=graph-read"])


class Provider:
    """The identity provider's side: keys, the documents it serves, and tokens it signs."""

    def __init__(self):
        self.rsa = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.ec = ec.generate_private_key(ec.SECP256R1())
        self.kids = {"rsa-1": self.rsa}
        self.fetched: list[str] = []
        self.down = False

    def jwks(self) -> dict:
        keys = []
        for kid, k in self.kids.items():
            alg = jwt.algorithms.RSAAlgorithm if isinstance(k, rsa.RSAPrivateKey) else jwt.algorithms.ECAlgorithm
            keys.append({**json.loads(alg.to_jwk(k.public_key())), "kid": kid, "use": "sig"})
        return {"keys": keys}

    def fetch(self, url: str) -> dict:
        self.fetched.append(url)
        if self.down:
            raise ConnectionError("the provider is away")
        if url == ISSUER + "/.well-known/openid-configuration":
            return {"issuer": ISSUER, "jwks_uri": JWKS, "token_endpoint": ISSUER + "/token"}
        if url == JWKS:
            return self.jwks()
        raise AssertionError(url)

    def token(self, roles=("graph-read",), kid="rsa-1", alg="RS256", lifetime=300, key=None, **claims) -> str:
        now = int(time.time())
        body = {"iss": ISSUER, "aud": "graph-api", "sub": "u-1", "preferred_username": "ann", "iat": now,
                "exp": now + lifetime, "realm_access": {"roles": list(roles)}, **claims}
        return jwt.encode(body, key or self.kids[kid], algorithm=alg, headers={"kid": kid})


def oidc(provider, clock=None, **more) -> Oidc:
    return Oidc(SecuritySettings(**{**OIDC, **more}), fetch=provider.fetch, clock=clock or time.time)


def test_the_settings_it_needs():
    for name in ("OIDC_ISSUER", "OIDC_AUDIENCE", "OIDC_ROLE_CLAIM", "OIDC_ROLE_MAP"):
        assert any(e.startswith(name + " is required") for e in problems(SecuritySettings(oauth_oidc_active=True)))
    assert problems(SecuritySettings(**OIDC)) == [] and problems(SecuritySettings()) == []
    bad = problems(SecuritySettings(**{**OIDC, "oidc_issuer": "http://idp.example.com", "oidc_algorithms": ["HS256"],
                                       "oidc_role_map": ["boss=graph-admin"]}))
    assert any("must be https://" in e for e in bad) and any("OIDC_ALGORITHMS: HS256" in e for e in bad)
    assert any("OIDC_ROLE_MAP" in e and "boss=graph-admin" in e for e in bad)
    assert problems(SecuritySettings(**{**OIDC, "oidc_issuer": "http://127.0.0.1:8180/realms/x"})) == []
    assert problems(SecuritySettings(**{**OIDC, "custom_roles": ["boss=admin"], "oidc_role_map": ["boss=x"]})) == []
    assert parse_role_map(["admin=ops", "read=analysts"]) == {"ops": "admin", "analysts": "read"}
    with pytest.raises(ValueError, match="both admin and read"):
        parse_role_map(["admin=x", "read=x"])


def test_a_good_token_names_its_caller_and_every_role_it_has():
    p, t = Provider(), [1000.0]
    o = oidc(p, clock=lambda: t[0])
    c = o.verify(p.token(roles=["graph-read", "graph-write", "something-else"]))
    assert (c.name, c.role.name, c.role.base) == ("ann", "read+write", "write")
    assert c.role.may("write") and not c.role.may("manage")
    assert p.fetched == [ISSUER + "/.well-known/openid-configuration", JWKS]       # found by discovery
    p.kids["ec-1"] = p.ec
    t[0] += 31
    assert o.verify(p.token(kid="ec-1", alg="ES256", roles=["graph-admin"])).role.name == "admin"   # a new key, fetched


def test_tokens_refused():
    p = Provider()
    o = oidc(p)
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    for token, status, why in [
            ("abc", 401, "not a JWT"),
            (p.token(lifetime=-120), 401, "expired"),
            (p.token(iss="https://evil.example.com"), 401, "another issuer"),
            (p.token(aud="another-api"), 401, "not for this API"),
            (p.token(key=other), 401, "refused"),
            (p.token(roles=["nobody"]), 403, "none of the roles"),
            (jwt.encode({"iss": ISSUER}, "s" * 32, algorithm="HS256", headers={"kid": "rsa-1"}), 401, "HS256")]:
        with pytest.raises(KeyRefused, match=why) as ex:
            o.verify(token)
        assert ex.value.status == status and ex.value.scope == "api"


def test_the_provider_away():
    p = Provider()
    p.down = True
    with pytest.raises(KeyRefused, match="can't be fetched yet") as ex:
        oidc(p).verify(p.token())
    assert ex.value.status == 503


def test_an_admin_call_can_need_a_recent_login():
    p = Provider()
    o = oidc(p, oidc_admin_max_age_seconds=600)
    old = o.verify(p.token(roles=["graph-admin"], auth_time=int(time.time()) - 3600))
    with pytest.raises(KeyRefused, match="login within 600 s"):
        o.check_recent(old)
    o.check_recent(o.verify(p.token(roles=["graph-admin"], auth_time=int(time.time()))))


def test_custom_roles_and_what_looks_like_a_jwt():
    p = Provider()
    o = oidc(p, custom_roles=["feeder=read+load"], oidc_role_map=["feeder=graph-feed"])
    assert o.verify(p.token(roles=["graph-feed"])).role.permissions == {"query", "load"}
    assert looks_like_jwt(p.token()) and not looks_like_jwt("pga1~abc~def") and not looks_like_jwt("")
    assert dataclasses.is_dataclass(SecuritySettings)
