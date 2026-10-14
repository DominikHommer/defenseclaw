# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""Setup hint for Cisco AI Defense rule selection."""

from defenseclaw.tui.panels.setup import _cisco_ai_defense_fields


def test_enabled_rules_hint_explains_blank_and_explicit_rules() -> None:
    field = next(field for field in _cisco_ai_defense_fields(None) if field.key == "cisco_ai_defense.enabled_rules")
    assert "Blank list uses the connection policy" in field.hint
    assert "entered names are sent each inspection" in field.hint
    assert "CSV" not in field.hint
    assert len(field.hint) <= 78
