#!/usr/bin/env bash
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
#
# Check the generated package postinstall without running a Mac installer.
# The signed LaunchAgent program copy and plist are checked by the package
# payload fixture in cli/tests/test_enterprise_sandbox_packaging.py.
BUILD_SH="${REPO_ROOT}/scripts/build-macos-enterprise-pkg.sh"

t_postinstall_runs_managed_ensure() {
  local d; d="$(mktest_tmp)"
  awk '/^cat >"\$SCRIPTS\/postinstall" <<'\''EOF'\''$/ { copying=1; next } copying && /^EOF$/ { exit } copying { print }' "${BUILD_SH}" >"${d}/postinstall"
  [[ -s "${d}/postinstall" ]] || { _fail "generated postinstall not found"; return 1; }
  bash -n "${d}/postinstall" || { _fail "generated postinstall has invalid shell syntax"; return 1; }
  grep -q 'enterprise macos ensure --from-package' "${d}/postinstall" || _fail "postinstall does not apply the managed deployment"
  grep -q 'last-package-result.json' "${d}/postinstall" || _fail "postinstall does not record the package result"
  if command -v shellcheck >/dev/null 2>&1; then
    local rc=0
    shellcheck "${d}/postinstall" >"${d}/shellcheck.out" 2>&1 || rc=$?
    assert_status "${rc}" 0 "shellcheck of the generated postinstall: $(head -5 "${d}/shellcheck.out")"
  fi
}

run_case "pkg postinstall applies and records the managed deployment" t_postinstall_runs_managed_ensure
