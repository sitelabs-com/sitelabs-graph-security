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

"""API keys: parsing, hashing and reading them again when API_KEYS_FILE changes.

    API_KEYS=reports:read:3f1c...:2027-03-31,loader:write:9a0b...,alex:admin:77d2...

Each entry is `name:role:hash`, and optionally `:YYYY-MM-DD`, the last day it works (UTC). A server
never holds a key: hash = sha256(sha256(key)), both in hex (new_key() makes a key and its entry). A
client sends its key as `X-API-Key: <key>`. The role is read, write, admin, or one of CUSTOM_ROLES
(graph_security.roles).

**API_KEYS_FILE**: more entries, one a line (`#` comments), read again whenever the file changes, so
keys are added, removed or replaced without a restart. A file that can't be read or parsed is
logged, and the keys from before stay. A key removed (or expired) stops working at once, and so do
its admin logins.
"""
from __future__ import annotations

import calendar
import hashlib
import logging
import os
import re
import secrets
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from graph_security.errors import KeyRefused  # noqa: F401  (re-exported)
from graph_security.roles import Role, built_in

log = logging.getLogger(__name__)
_ENTRY = re.compile(r"([A-Za-z0-9_.@-]{1,64}):([a-z][a-z0-9_-]{0,31}):([0-9a-f]{64})(?::(\d{4}-\d{2}-\d{2}))?")
_RELOAD_SECONDS = 2.0                              # API_KEYS_FILE is looked at no more often than this


@dataclass(frozen=True)
class Key:
    name: str
    role: Role
    expires: float | None = None                   # the end of its last day (UTC), or None: never

    def expired(self, now: float) -> bool:
        return self.expires is not None and now >= self.expires

    @property
    def last_day(self) -> str:
        return time.strftime("%Y-%m-%d", time.gmtime(self.expires - 1)) if self.expires else ""


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def digest(key: str) -> str:
    """What API_KEYS holds of a key."""
    return _sha(_sha(key))


def new_key(name: str, role: str = "read", days: int = 0, roles: dict[str, Role] | None = None,
            today: float | None = None) -> tuple[str, str]:
    """(a new key, its API_KEYS entry), lasting `days` from today (0: no end)."""
    roles = roles or built_in()
    if role not in roles:
        raise ValueError(f"role must be one of {', '.join(roles)}, not {role!r}")
    key = secrets.token_urlsafe(32)
    entry = f"{name}:{role}:{digest(key)}"
    if days:
        entry += ":" + time.strftime("%Y-%m-%d", time.gmtime((time.time() if today is None else today) + days * 86400))
    parse_keys([entry], roles)
    return key, entry


def _end_of(day: str) -> float:
    return calendar.timegm(time.strptime(day, "%Y-%m-%d")) + 86400


def parse_keys(entries: list[str], roles: dict[str, Role] | None = None) -> dict[str, Key]:
    """{hash: Key} from API_KEYS' entries. ValueError names the first bad one (by its name, never
    its hash), a name used twice and a role that isn't built in or one of CUSTOM_ROLES."""
    roles = roles or built_in()
    out: dict[str, Key] = {}
    names = set()
    for i, e in enumerate(entries, 1):
        m = _ENTRY.fullmatch(e.strip())
        if not m:
            label = e.split(":", 1)[0][:64] if ":" in e else f"entry {i}"
            raise ValueError(f"{label!r} is not name:role:hash[:YYYY-MM-DD] (hash 64 hex characters; "
                             "new_key() makes them)")
        name, role, h, day = m.groups()
        if role not in roles:
            raise ValueError(f"{name!r} has the role {role!r}, which is not read, write, admin or one of CUSTOM_ROLES")
        if name in names:
            raise ValueError(f"the name {name!r} is used twice")
        try:
            expires = _end_of(day) if day else None
        except ValueError:
            raise ValueError(f"{name!r}: {day} is not a date (YYYY-MM-DD)") from None
        names.add(name)
        out[h] = Key(name, roles[role], expires)
    return out


def read_file(path: str) -> list[str]:
    """API_KEYS_FILE's entries: one a line (or comma-separated), `#` starting a comment."""
    out = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0]
        out += [x.strip() for x in line.split(",") if x.strip()]
    return out


class ApiKeys:
    def __init__(self, entries: list[str], roles: dict[str, Role] | None = None, file: str = "",
                 clock: Callable[[], float] = time.time):
        self.entries, self.roles, self.file, self.clock = list(entries), roles or built_in(), file, clock
        self._lock = threading.Lock()
        self._stamp, self._looked = self._file_stamp(), clock()
        self.keys = parse_keys(self.entries + (read_file(file) if file else []), self.roles)
        self.reloads = 0

    def _file_stamp(self):
        if not self.file:
            return None
        try:
            st = os.stat(self.file)
            return st.st_mtime_ns, st.st_size, st.st_ino
        except OSError:
            return "missing"

    def refresh(self, force: bool = False) -> bool:
        """Read API_KEYS_FILE again if it changed; whether the keys changed."""
        if not self.file:
            return False
        now = self.clock()
        with self._lock:
            if not force and now - self._looked < _RELOAD_SECONDS:
                return False
            self._looked = now
            stamp = self._file_stamp()
            if stamp == self._stamp and not force:
                return False
            self._stamp = stamp
            try:
                keys = parse_keys(self.entries + read_file(self.file), self.roles)
            except (OSError, ValueError, UnicodeDecodeError) as ex:
                log.error("API_KEYS_FILE %s can't be used, so the keys from before stay: %s", self.file, ex,
                          extra={"event": "keys.reload_failed"})
                return False
            before = {k.name for k in self.keys.values()}
            after = {k.name for k in keys.values()}
            self.keys, self.reloads = keys, self.reloads + 1
        log.warning("API keys read again from %s: %d keys (added: %s; removed: %s)", self.file, len(keys),
                    ", ".join(sorted(after - before)) or "none", ", ".join(sorted(before - after)) or "none",
                    extra={"event": "keys.reloaded"})
        return True

    @property
    def enabled(self) -> bool:
        self.refresh()
        return bool(self.keys)

    @property
    def admins(self) -> list[tuple[str, str]]:
        """(name, hash) of every live key with an admin role: who may log in."""
        self.refresh()
        now = self.clock()
        return [(k.name, h) for h, k in self.keys.items() if k.role.admin and not k.expired(now)]

    def find(self, key: str) -> Key | None:
        """The key's entry (expired or not), or None."""
        if not key:
            return None
        self.refresh()
        return self.keys.get(digest(key))

    def who(self, key: str) -> tuple[str, Role] | None:
        """(name, role) of a live key, or None."""
        k = self.find(key)
        return (k.name, k.role) if k is not None and not k.expired(self.clock()) else None

    def named(self, name: str) -> Key | None:
        """The live key of this name (an admin's, a browser session's, at each of its calls), or None."""
        self.refresh()
        now = self.clock()
        return next((k for k in self.keys.values() if k.name == name and not k.expired(now)), None)

    def expiring(self, within_seconds: float) -> list[Key]:
        """Keys that have expired, or will within this long: for the warnings at startup."""
        now = self.clock()
        return sorted((k for k in self.keys.values() if k.expires is not None and k.expires - now <= within_seconds),
                      key=lambda k: k.expires)
