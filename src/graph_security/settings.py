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

"""The security settings, the same names and defaults in every application. An application's own
Settings has these fields (or this dataclass's); the modules read them by name, so either will do.

    environment                   development or production
    api_keys, api_keys_file       the keys (graph_security.keys)
    custom_roles                  more roles (graph_security.roles)
    session_secret, session_seconds                                  admin logins and browser sessions
    admin_token_seconds, admin_challenge_seconds, admin_max_failures, admin_lockout_seconds
    rate_limit_per_second, rate_limit_burst, rate_limits, max_running_per_caller   (graph_security.limits)
    oauth_oidc_active, oidc_*     access tokens from an identity provider (graph_security.oidc)
    metrics_bearer_token          GET /metrics needs "Authorization: Bearer <token>" when set
    uvicorn_ssl_*, internal_tls_* TLS between the servers (graph_security.internal_tls)
"""
from __future__ import annotations

from dataclasses import dataclass, field, fields


@dataclass
class SecuritySettings:
    environment: str = "development"
    # keys and roles
    api_keys: list[str] = field(default_factory=list)            # name:role:hash[:YYYY-MM-DD] each
    api_keys_file: str = ""                                      # more entries, one a line, read again when it changes
    custom_roles: list[str] = field(default_factory=list)        # name=base(+permission|-permission)... each
    # admin logins and browser sessions
    session_secret: str = ""                                     # signs both; the same on every server ("": made at startup)
    session_seconds: float = 28800.0
    admin_token_seconds: float = 900.0
    admin_challenge_seconds: float = 60.0
    admin_max_failures: int = 5
    admin_lockout_seconds: float = 300.0
    # rate limits
    rate_limit_per_second: float = 0.0
    rate_limit_burst: int = 0
    rate_limits: list[str] = field(default_factory=list)
    max_running_per_caller: int = 0
    # OAuth 2.0 / OpenID Connect
    oauth_oidc_active: bool = False
    oidc_issuer: str = ""
    oidc_audience: str = ""
    oidc_role_claim: str = ""
    oidc_role_map: list[str] = field(default_factory=list)
    oidc_audience_claim: str = "aud"
    oidc_name_claim: str = "preferred_username"
    oidc_jwks_url: str = ""
    oidc_algorithms: list[str] = field(default_factory=lambda: ["RS256", "ES256"])
    oidc_leeway_seconds: float = 60.0
    oidc_jwks_refresh_seconds: float = 3600.0
    oidc_admin_max_age_seconds: float = 0.0
    oidc_accept_api_keys: bool = True
    oidc_console_client_id: str = ""
    oidc_console_scopes: str = "openid profile"
    oidc_console_auth_params: list[str] = field(default_factory=list)
    oidc_console_redirect_uri: str = ""
    # metrics
    metrics_bearer_token: str = ""
    # TLS
    uvicorn_ssl_certfile: str = ""
    uvicorn_ssl_keyfile: str = ""
    uvicorn_ssl_ca_certs: str = ""
    uvicorn_ssl_cert_reqs: str = "none"
    internal_tls_ca_file: str = ""
    internal_tls_certfile: str = ""
    internal_tls_keyfile: str = ""
    internal_tls_server_name: str = ""
    internal_tls_required: bool = False


NAMES = tuple(f.name for f in fields(SecuritySettings))
