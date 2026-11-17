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

"""API keys: entries, hashes, last days, and API_KEYS_FILE read again when it changes."""
import time

import pytest

from graph_security.keys import ApiKeys, digest, new_key, parse_keys, read_file


def test_a_key_and_its_entry():
    key, entry = new_key("a.b@c", "write")
    name, role, h = entry.split(":")
    assert (name, role, h) == ("a.b@c", "write", digest(key)) and key not in entry
    ((hash_, k),) = parse_keys([entry]).items()
    assert hash_ == digest(key) and k.name == "a.b@c" and k.role.name == "write" and k.expires is None
    for bad, why in [("x:read:" + "0" * 63, "is not name:role:hash"), ("x:root:" + "0" * 64, "the role 'root'"),
                     ("x:read:" + "0" * 64 + ":2020-02-31", "is not a date")]:
        with pytest.raises(ValueError, match=why):
            parse_keys([bad])
    with pytest.raises(ValueError, match="used twice"):
        parse_keys([entry, entry])
    with pytest.raises(ValueError, match="role must be one of"):
        new_key("n", "root")


def test_a_custom_role_needs_its_roles(catalogue):
    custom = catalogue.parse_roles(["feeder=read+load"])
    key, entry = new_key("fee", "feeder", roles=custom)
    with pytest.raises(ValueError, match="the role 'feeder'"):
        parse_keys([entry])                                        # without CUSTOM_ROLES
    assert ApiKeys([entry], custom).who(key)[1].permissions == {"query", "load"}


def test_a_key_works_until_the_end_of_its_last_day():
    today = time.time()
    key, entry = new_key("temp", "read", days=1, today=today)
    assert entry.rsplit(":", 1)[1] == time.strftime("%Y-%m-%d", time.gmtime(today + 86400))
    now = [today]
    keys = ApiKeys([entry], clock=lambda: now[0])
    assert keys.who(key)[0] == "temp" and keys.named("temp") is not None
    assert [k.name for k in keys.expiring(3 * 86400)] == ["temp"]
    now[0] += 3 * 86400
    assert keys.find(key).expired(now[0]) and keys.who(key) is None and keys.named("temp") is None


def test_who_may_log_in_and_lookups_by_hash():
    admin, admin_entry = new_key("boss", "admin")
    reader, reader_entry = new_key("reports", "read")
    keys = ApiKeys([admin_entry, reader_entry])
    assert keys.enabled and [n for n, _ in keys.admins] == ["boss"]
    assert keys.find(digest(admin)) is None and keys.find("") is None       # the hash is not the key
    assert not ApiKeys([]).enabled


def test_the_key_file_is_read_again_when_it_changes(tmp_path):
    f = tmp_path / "keys"
    first, first_entry = new_key("first", "read")
    second, second_entry = new_key("second", "read")
    f.write_text(f"# the keys\n{first_entry}  # a comment\n")
    assert read_file(str(f)) == [first_entry]
    keys = ApiKeys([], file=str(f))
    assert keys.who(first)[0] == "first"
    f.write_text(f"{second_entry}\n")
    assert keys.refresh(force=True) and keys.who(first) is None and keys.who(second)[0] == "second"
    f.write_text("broken\n")                                       # the keys from before stay
    assert not keys.refresh(force=True) and keys.who(second)[0] == "second"
    assert not keys.refresh()                                     # looked at no more than every 2 s
