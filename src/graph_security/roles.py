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

"""Roles and what each may do: the mechanism, with each application's own permissions.

An application describes its permissions once, in a `Catalogue`, and registers it with `use()`:

    CATALOGUE = use(Catalogue(
        {"query": "read queries", "write": "write queries", "load": "bulk loads", "manage": "the platform"},
        read={"query"}, write={"write", "load"}, admin_only={"manage"}))

Three roles are built in, each built on the one before:

* **read**: the catalogue's `read` permissions;
* **write**: read's, and its `write` permissions;
* **admin**: every permission, and, after logging in with its key (graph_security.admin_auth), the
  admin endpoints.

More come from CUSTOM_ROLES, each built on one of them, adding or removing permissions:

    CUSTOM_ROLES=feeder=read+load,writer=write-load,operator=admin-manage

An API key (API_KEYS) or OIDC_ROLE_MAP may then name `feeder`, `writer` or `operator`. A token with
several roles has the permissions of all of them. Only a role built on admin may log in to the admin
endpoints, and only it may be given an admin-only permission.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

BASES = ("read", "write", "admin")
_NAME = re.compile(r"[a-z][a-z0-9_-]{0,31}")
_ENTRY = re.compile(r"([a-z][a-z0-9_-]{0,31})=(read|write|admin)((?:[+-][a-z_]+)*)")


@dataclass(frozen=True)
class Role:
    name: str
    base: str                                  # read, write or admin: what it was built on
    permissions: frozenset

    def may(self, permission: str) -> bool:
        return permission in self.permissions

    @property
    def admin(self) -> bool:
        """Whether it may log in to the admin endpoints."""
        return self.base == "admin"

    def __str__(self) -> str:
        return self.name


class Catalogue:
    """An application's permissions: {name: what it allows}, the ones read and write add, and the
    ones only a role built on admin may have."""

    def __init__(self, permissions: dict[str, str], read, write, admin_only):
        self.permissions = dict(permissions)
        read, write, admin_only = frozenset(read), frozenset(write), frozenset(admin_only)
        unknown = (read | write | admin_only) - set(self.permissions)
        if unknown:
            raise ValueError(f"not in the permissions: {', '.join(sorted(unknown))}")
        if (read | write) & admin_only:
            raise ValueError(f"read and write can't have admin-only ones: {', '.join(sorted((read | write) & admin_only))}")
        self.admin_only = admin_only
        self.grants = {"read": read, "write": read | write, "admin": frozenset(self.permissions)}
        self.built_in = {b: Role(b, b, self.grants[b]) for b in BASES}
        self.open = self.built_in["admin"]     # a server with no keys (development): every endpoint open

    def parse_roles(self, entries: list[str]) -> dict[str, Role]:
        """{name: Role}: the built-in roles, and CUSTOM_ROLES' `name=base(+permission|-permission)...`
        entries. ValueError names the first bad one."""
        out = dict(self.built_in)
        for e in entries:
            e = e.strip().replace(" ", "")
            m = _ENTRY.fullmatch(e)
            if not m:
                raise ValueError(f"{e!r} is not name=base(+permission|-permission)..., with base read, write or admin "
                                 "(such as analyst=read-export)")
            name, base, changes = m.groups()
            if name in out:
                raise ValueError(f"the role {name!r} is " + ("built in" if name in self.built_in else "defined twice"))
            perms = set(self.grants[base])
            for sign, perm in re.findall(r"([+-])([a-z_]+)", changes):
                if perm not in self.permissions:
                    raise ValueError(f"{name}: no permission {perm!r} (one of {', '.join(self.permissions)})")
                if sign == "+":
                    if perm in self.admin_only and base != "admin":
                        raise ValueError(f"{name}: {perm} is an admin permission: build the role on admin")
                    perms.add(perm)
                else:
                    perms.discard(perm)
            if not perms:
                raise ValueError(f"{name}: no permissions left")
            out[name] = Role(name, base, frozenset(perms))
        return out


_default: Catalogue | None = None


def use(catalogue: Catalogue) -> Catalogue:
    """Make `catalogue` the one used where no roles are passed (the application's, set once at import)."""
    global _default
    _default = catalogue
    return catalogue


def default() -> Catalogue:
    if _default is None:
        raise RuntimeError("no permission catalogue: the application must call graph_security.roles.use() first")
    return _default


def built_in() -> dict[str, Role]:
    """The default catalogue's read, write and admin roles."""
    return default().built_in


def valid_name(name: str) -> bool:
    return bool(_NAME.fullmatch(name))


def combined(roles: list[Role]) -> Role:
    """The role of a caller holding several (a token's): every permission of each, built on the highest base."""
    if len(roles) == 1:
        return roles[0]
    base = max((r.base for r in roles), key=BASES.index)
    perms = frozenset().union(*(r.permissions for r in roles))
    return Role("+".join(sorted({r.name for r in roles})), base, perms)
