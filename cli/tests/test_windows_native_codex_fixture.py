# Copyright 2026 Cisco Systems, Inc. and its affiliates
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
#
# SPDX-License-Identifier: Apache-2.0

"""The Windows native CI Codex fixture stays selectable by setup (GAP-0273).

Setup refuses Codex below CODEX_APP_SERVER_STDIO_MIN_VERSION, and the
Windows harnesses read the hook contract back from the registration, so
the fixture must be at or above the floor and every Codex contract setup
can bind must be known to both harnesses.
"""

from __future__ import annotations

import re
from pathlib import Path

from defenseclaw.agent_selection import CODEX_APP_SERVER_STDIO_MIN_VERSION
from defenseclaw.connector_contracts import compare_agent_versions, hook_contract_manifest

ROOT = Path(__file__).resolve().parents[2]
NATIVE_CI = ROOT / "scripts/windows-native-ci.ps1"
RUN_WINDOWS = ROOT / "scripts/live-connector-e2e/run-windows.ps1"


def _fixture_version() -> str:
    versions = set(re.findall(r'"codex-cli (\d+\.\d+\.\d+)"', NATIVE_CI.read_text(encoding="utf-8")))
    versions |= set(re.findall(r"'codex-cli (\d+\.\d+\.\d+)'", NATIVE_CI.read_text(encoding="utf-8")))
    assert len(versions) == 1, versions
    return versions.pop()


def _selectable_codex_contracts() -> list[str]:
    contracts = hook_contract_manifest()["connectors"]["codex"]["contracts"]
    return [
        contract["contract_id"]
        for contract in contracts
        if not contract["agent_version"]["max_exclusive"]
        or compare_agent_versions(contract["agent_version"]["max_exclusive"], CODEX_APP_SERVER_STDIO_MIN_VERSION) > 0
    ]


def test_codex_fixture_is_at_or_above_the_setup_floor() -> None:
    assert compare_agent_versions(_fixture_version(), CODEX_APP_SERVER_STDIO_MIN_VERSION) >= 0


def test_windows_harnesses_know_every_codex_contract_setup_can_bind() -> None:
    selectable = _selectable_codex_contracts()
    assert "codex-hooks-v3-generic" in selectable
    for harness in (NATIVE_CI, RUN_WINDOWS):
        text = harness.read_text(encoding="utf-8")
        for contract_id in selectable:
            assert f"'{contract_id}' = @(" in text, (harness.name, contract_id)
    pattern = re.search(r"-notmatch '(\^codex-hooks-[^']+)'", RUN_WINDOWS.read_text(encoding="utf-8"))
    assert pattern is not None
    for contract_id in selectable:
        assert re.match(pattern.group(1), contract_id), contract_id
