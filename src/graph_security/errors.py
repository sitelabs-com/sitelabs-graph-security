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

"""The refusals: each has an HTTP status (401, 403, 429 or 503) and a message for the caller, answered
as {"error": ...}. `scope` tells an application which realm to name in WWW-Authenticate: "admin" for
the admin login, "api" for a key, a token or a session."""
from __future__ import annotations


class AdminRefused(Exception):
    """A login or an admin call refused: `status` is 401, 403 or 429."""

    scope = "admin"

    def __init__(self, status: int, message: str, retry_after: int | None = None):
        super().__init__(message)
        self.status, self.retry_after = status, retry_after


class KeyRefused(AdminRefused):
    """A call without a key, with an unknown or expired one, or a token refused (401); a role without
    the permission (403); too many calls (429); the identity provider's keys not fetched yet (503)."""

    scope = "api"
