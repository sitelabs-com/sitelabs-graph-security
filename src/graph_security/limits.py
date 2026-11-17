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

"""Rate limits and quotas per caller, so one client can't take a server for itself.

* **A rate**: RATE_LIMIT_PER_SECOND calls a second, with bursts of RATE_LIMIT_BURST (a token
  bucket), for each caller: a key's or a token's name, else (a server that needs no keys) the
  caller's address. RATE_LIMITS sets another for some callers, by name (`reports=2`) or by role
  (`role:loader=0.5/5`), 0 for no limit. Past it: 429, with Retry-After.
* **Work at once**: MAX_RUNNING_PER_CALLER calls running at the same time for one caller (which
  calls count is the application's choice: `work` names them in the refusal). Past it: 429.

Health, readiness, metrics and monitoring aren't limited, and the admin login has its own lockout.
Each count is this server's own: servers count apart.
"""
from __future__ import annotations

import math
import threading
import time
from contextlib import contextmanager
from typing import Callable

from graph_security.errors import KeyRefused


def parse_limits(entries: list[str]) -> dict[str, tuple[float, int]]:
    """{name or "role:<name>": (rate, burst)} from RATE_LIMITS. ValueError names the first bad one."""
    out = {}
    for e in entries:
        who, sep, value = e.strip().partition("=")
        rate, _, burst = value.partition("/")
        try:
            r, b = float(rate), int(burst) if burst else 0
        except ValueError:
            r = b = -1
        if not sep or not who.strip() or r < 0 or b < 0 or not math.isfinite(r):
            raise ValueError(f"{e.strip()!r} is not name=rate[/burst] or role:name=rate[/burst] (such as reports=2, "
                             "role:loader=0.5/5; 0: no limit)")
        out[who.strip()] = (r, b)
    return out


def _burst(rate: float, burst: int) -> float:
    return float(burst) if burst else max(1.0, 2 * rate)


class Limits:
    def __init__(self, rate: float = 0.0, burst: int = 0, overrides: list[str] | None = None,
                 max_running: int = 0, clock: Callable[[], float] = time.monotonic, work: str = "calls"):
        self.rate, self.burst, self.work = rate, burst, work
        self.overrides = parse_limits(overrides or [])
        self.max_running = max_running
        self.clock = clock
        self._buckets: dict[str, tuple[float, float]] = {}     # caller -> (tokens, when last filled)
        self._running: dict[str, int] = {}
        self._lock = threading.Lock()
        self.refused = {"rate": 0, "running": 0}

    @property
    def enabled(self) -> bool:
        return bool(self.rate or self.max_running or any(r for r, _ in self.overrides.values()))

    def _for(self, name: str, role: str) -> tuple[float, float]:
        rate, burst = self.overrides.get(name) or self.overrides.get(f"role:{role}") or (self.rate, self.burst)
        return rate, _burst(rate, burst)

    def check(self, name: str, role: str = "") -> None:
        """Count a call by `name`; KeyRefused (429) past its rate."""
        rate, burst = self._for(name, role)
        if not rate:
            return
        with self._lock:
            now = self.clock()
            tokens, at = self._buckets.get(name, (burst, now))
            tokens = min(burst, tokens + (now - at) * rate)
            if tokens < 1:
                self._buckets[name] = (tokens, now)
                self.refused["rate"] += 1
                wait = (1 - tokens) / rate
                raise KeyRefused(429, f"too many calls from {name!r}: {rate:g} a second at most "
                                      "(RATE_LIMIT_PER_SECOND, RATE_LIMITS)", math.ceil(wait))
            self._buckets[name] = (tokens - 1, now)
            if len(self._buckets) > 100_000:                   # callers by address: don't grow without end
                self._buckets = {k: v for k, v in self._buckets.items() if now - v[1] < 3600}

    @contextmanager
    def running(self, name: str):
        """Hold one of `name`'s MAX_RUNNING_PER_CALLER places while the work runs; KeyRefused (429) when none is free."""
        if not self.max_running:
            yield
            return
        with self._lock:
            n = self._running.get(name, 0)
            if n >= self.max_running:
                self.refused["running"] += 1
                raise KeyRefused(429, f"{name!r} already has {n} {self.work} running "
                                      f"(MAX_RUNNING_PER_CALLER={self.max_running}): wait for one to finish", 1)
            self._running[name] = n + 1
        try:
            yield
        finally:
            with self._lock:
                left = self._running.get(name, 1) - 1
                if left:
                    self._running[name] = left
                else:
                    self._running.pop(name, None)
