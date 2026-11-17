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

"""Roles: the built-in ones from a catalogue, CUSTOM_ROLES, and a caller holding several."""
import pytest

from graph_security import roles
from graph_security.roles import Catalogue, combined, valid_name


def test_the_built_in_roles_follow_the_catalogue(catalogue):
    r = catalogue.built_in
    assert r["read"].permissions == {"query"}
    assert r["write"].permissions == {"query", "write", "load"}
    assert r["admin"].permissions == set(catalogue.permissions) and r["admin"].admin and not r["write"].admin
    assert catalogue.open is r["admin"] and roles.built_in() is r


def test_custom_roles_add_and_remove_permissions(catalogue):
    out = catalogue.parse_roles(["feeder=read+load", "writer = write-load", "operator=admin-manage"])
    assert out["feeder"].permissions == {"query", "load"} and out["feeder"].base == "read"
    assert out["writer"].permissions == {"query", "write"}
    assert "manage" not in out["operator"].permissions and out["operator"].admin
    for bad, why in [("x", "is not name=base"), ("read=write", "built in"), ("a=read,a=write", None),
                     ("a=read+nothing", "no permission 'nothing'"), ("a=read+manage", "admin permission"),
                     ("a=read-query", "no permissions left"), ("A=read", "is not name=base")]:
        with pytest.raises(ValueError, match=why or "defined twice"):
            catalogue.parse_roles(bad.split(","))


def test_a_catalogue_must_be_consistent():
    with pytest.raises(ValueError, match="not in the permissions: x"):
        Catalogue({"query": ""}, read={"query", "x"}, write=set(), admin_only=set())
    with pytest.raises(ValueError, match="admin-only ones: query"):
        Catalogue({"query": ""}, read={"query"}, write=set(), admin_only={"query"})


def test_several_roles_have_every_permission_of_each(catalogue):
    out = catalogue.parse_roles(["feeder=read+load"])
    both = combined([out["feeder"], out["write"]])
    assert both.name == "feeder+write" and both.base == "write" and both.permissions == {"query", "write", "load"}
    assert combined([out["read"]]) is out["read"]
    assert valid_name("ops-2") and not valid_name("Ops") and not valid_name("2ops")


def test_without_a_catalogue_the_defaults_say_so(monkeypatch):
    monkeypatch.setattr(roles, "_default", None)
    with pytest.raises(RuntimeError, match="roles.use"):
        roles.built_in()
