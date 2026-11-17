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

"""The admin login: a challenge answered with an admin key, which never crosses the network."""
import pytest

from graph_security.admin_auth import AdminAuth, AdminRefused, answer, proves
from graph_security.keys import ApiKeys, digest, new_key

ADMIN, ADMIN_ENTRY = new_key("boss", "admin")
WRITER, WRITER_ENTRY = new_key("loader", "write")


def test_only_an_admin_key_logs_in_and_the_hash_alone_cannot():
    auth = AdminAuth(ApiKeys([ADMIN_ENTRY, WRITER_ENTRY]))
    for key in (WRITER, digest(ADMIN)):                            # digest(ADMIN) is what API_KEYS holds
        nonce = auth.challenge()["nonce"]
        with pytest.raises(AdminRefused, match="wrong response"):
            auth.login(nonce, answer(key, nonce), "a")
    nonce = auth.challenge()["nonce"]
    login = auth.login(nonce, answer(ADMIN, nonce), "a")
    assert login["name"] == "boss" and auth.check(login["token"]) == "boss"


def test_the_login_refuses_replays_and_locks_out_guessing():
    auth = AdminAuth(ApiKeys([ADMIN_ENTRY]), max_failures=2)
    nonce = auth.challenge()["nonce"]
    response = answer(ADMIN, nonce)
    assert ADMIN not in response and proves(response, digest(ADMIN), nonce) and not proves(response, digest(ADMIN), "x")
    auth.login(nonce, response, "a")
    with pytest.raises(AdminRefused, match="nonce is unknown"):
        auth.login(nonce, response, "a")                           # a replay
    with pytest.raises(AdminRefused, match="wrong response"):
        auth.login(auth.challenge()["nonce"], "00" * 32, "a")      # the second failure in a row
    with pytest.raises(AdminRefused, match="too many wrong answers") as ex:
        auth.login(auth.challenge()["nonce"], response, "a")
    assert ex.value.status == 429 and ex.value.retry_after
    with pytest.raises(AdminRefused, match="no key in API_KEYS has the admin role") as ex:
        AdminAuth(ApiKeys([WRITER_ENTRY])).challenge()
    assert ex.value.status == 403 and ex.value.scope == "admin"


def test_a_login_holds_at_every_server_with_the_same_secret_and_ends_with_its_key():
    one = AdminAuth(ApiKeys([ADMIN_ENTRY]), secret="s" * 64)
    nonce = one.challenge()["nonce"]
    token = one.login(nonce, answer(ADMIN, nonce), "10.0.0.1")["token"]
    assert AdminAuth(ApiKeys([ADMIN_ENTRY]), secret="s" * 64).check(token) == "boss"   # another server, a restart
    with pytest.raises(AdminRefused, match="knows only its own"):
        AdminAuth(ApiKeys([ADMIN_ENTRY])).check(token)
    with pytest.raises(AdminRefused, match="no longer an admin key"):
        AdminAuth(ApiKeys([new_key("boss", "admin")[1]]), secret="s" * 64).check(token)
    with pytest.raises(AdminRefused, match="expired"):
        AdminAuth(ApiKeys([ADMIN_ENTRY]), secret="s" * 64, clock=lambda: 1e12).check(token)
    one.logout(token)
    with pytest.raises(AdminRefused, match="logged out"):
        one.check(token)
    with pytest.raises(AdminRefused, match="needs Authorization: Bearer"):
        one.check("")
