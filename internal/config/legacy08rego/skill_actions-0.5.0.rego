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

package defenseclaw.skill_actions

import rego.v1

# Maps a severity level to runtime, file, and install actions.
# Supports per-scanner-type overrides via data.scanner_overrides.
#
# Input fields:
#   severity    - "CRITICAL", "HIGH", "MEDIUM", "LOW", or "INFO"
#   target_type - optional "skill", "mcp", or "plugin" for scanner-specific lookup
#
# Static data (data.json):
#   actions.<SEVERITY>.runtime              - "block" or "allow"
#   actions.<SEVERITY>.file                 - "quarantine" or "none"
#   actions.<SEVERITY>.install              - "block", "allow", or "none"
#   scanner_overrides.<TYPE>.<SEVERITY>.*   - per-scanner overrides

default runtime_action := "allow"

default file_action := "none"

default install_action := "none"

# Resolve effective action: scanner override > global
_effective := action if {
	input.target_type
	action := data.scanner_overrides[input.target_type][input.severity]
} else := action if {
	action := data.actions[input.severity]
}

runtime_action := action if {
	action := _effective.runtime
}

file_action := action if {
	action := _effective.file
}

install_action := action if {
	action := _effective.install
}

should_block if {
	runtime_action == "block"
}

should_quarantine if {
	file_action == "quarantine"
}

should_block_install if {
	install_action == "block"
}