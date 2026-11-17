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

"""Browser sessions: signed cookies that only read, ending with their key."""
from types import SimpleNamespace

import pytest

from graph_security.errors import KeyRefused
from graph_security.keys import ApiKeys, new_key
from graph_security.sessions import Sessions, Signer, key_mark

KEY, ENTRY = new_key("ann", "write")


def request(cookies):
    return SimpleNamespace(cookies=cookies)


def test_a_session_only_reads_and_is_signed(catalogue):
    keys = ApiKeys([ENTRY])
    s = Sessions(keys, b"x" * 32, cookie="app_session")
    (h,) = keys.keys
    value, seconds = s.make("ann", keys.keys[h].role, h)
    assert seconds == 28800
    name, role = s.caller(request({"app_session": value}))
    assert name == "ann" and role.permissions == {"query"} and not role.admin
    assert s.caller(request({"graph_session": value})) is None                  # the application's cookie only
    assert Sessions(keys, b"y" * 32).read(value) is None                        # another secret
    assert Signer(b"x" * 32, "sso").read(value) is None                         # another purpose
    with pytest.raises(KeyRefused, match="no query permission") as ex:
        s.make("w", catalogue.parse_roles(["w=write-query"])["w"])
    assert ex.value.status == 403


def test_a_session_ends_with_its_key_its_time_or_a_sign_out():
    keys = ApiKeys([ENTRY])
    now = [1000.0]
    s = Sessions(keys, b"x" * 32, seconds=60, clock=lambda: now[0])
    (h,) = keys.keys
    value, _ = s.make("ann", keys.keys[h].role, h)
    assert s.read(value)["k"] == key_mark(h)
    s.end(value)
    assert s.read(value) is None
    value, _ = s.make("ann", keys.keys[h].role, h)
    now[0] += 61
    assert s.read(value) is None
    now[0] = 1000.0
    value, _ = s.make("ann", keys.keys[h].role, h)
    keys.keys = ApiKeys([new_key("ann", "write")[1]]).keys                       # the key replaced
    assert s.read(value) is None
