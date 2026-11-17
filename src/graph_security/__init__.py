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

"""Security for the sitelabs graph servers: API keys, roles and permissions, the admin login,
browser sessions, OAuth 2.0 / OpenID Connect access tokens, rate limits and internal TLS.

    graph_security.roles         roles and permissions (each application registers its Catalogue)
    graph_security.keys          API_KEYS and API_KEYS_FILE
    graph_security.admin_auth    the admin login: a challenge answered with an admin key
    graph_security.sessions      browser sessions, signed cookies
    graph_security.oidc          access tokens from an identity provider
    graph_security.limits        rate limits and work at once, per caller
    graph_security.internal_tls  TLS between the servers
    graph_security.errors        the refusals (401, 403, 429, 503)
"""
__version__ = "0.1.0"
