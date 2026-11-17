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

"""Rate limits and work at once, per caller."""
import pytest

from graph_security.errors import KeyRefused
from graph_security.limits import Limits, parse_limits


def test_a_rate_with_bursts_and_overrides_by_name_or_role():
    now = [0.0]
    lim = Limits(rate=2, burst=2, overrides=["vip=0", "role:loader=1/1"], clock=lambda: now[0])
    lim.check("ann", "read")
    lim.check("ann", "read")
    with pytest.raises(KeyRefused) as ex:
        lim.check("ann", "read")
    assert ex.value.status == 429 and ex.value.retry_after == 1 and lim.refused["rate"] == 1
    for _ in range(10):
        lim.check("vip", "read")                                       # no limit for this caller
    lim.check("lou", "loader")
    with pytest.raises(KeyRefused):
        lim.check("lou", "loader")
    now[0] += 1
    lim.check("ann", "read")                                           # filled again
    assert lim.enabled and not Limits().enabled
    with pytest.raises(ValueError):
        parse_limits(["nonsense"])


def test_work_at_once():
    one = Limits(max_running=1, work="queries")
    with one.running("ann"):
        with pytest.raises(KeyRefused, match="already has 1 queries running .*MAX_RUNNING_PER_CALLER=1"):
            with one.running("ann"):
                pass
        with one.running("bob"):                                       # each caller its own
            pass
    with one.running("ann"):                                           # free again
        pass
