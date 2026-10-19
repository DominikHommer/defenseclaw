// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import "os"

const claudeVersionSuite = "claude-version"
const claudeVersionScope = "fixed_linux_native_claude_2_1_292_version_only_v1"
const claudeVersionReceiptSHA = "e24ee1736320e9df281e0ab7049b2df8cbacbf27d81d31fc46e21cef09b165b7"
const claudeLoaderSHA = "76b812138a1d4be51ae095e94920e1fd1c5d25f793651baf834d05a2c455c040"
const claudeLoaderSize = 853616
const claudeLoaderLeaf = "claude-runtime-loader"

// The exact 49c wrapper input passed three inert artifact reviews (run
// 39196467675/artifact12161534865, ZIP399a239a..., PROVc1b5e594...). This
// driver still needs its own build/image review before any fixed native run.
var versionAdmission = wrapperAdmission{Reviewed: true, VersionOnly: true,
	SHA: "63300aa074ad60c607b15fb7833a38dc3421a5616c73abdb54386a7045563912", Size: 3506302,
}

func admissionForArgs(args []string) wrapperAdmission {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "--suite" && args[i+1] == claudeVersionSuite {
			return versionAdmission
		}
	}
	return liveAdmission
}

func receiptForSuite(suite string) string {
	if suite == claudeVersionSuite {
		return claudeVersionReceiptSHA
	}
	return receiptSHA
}

func scopeForSuite(suite string) string {
	if suite == claudeVersionSuite {
		return claudeVersionScope
	}
	return "fixed_linux_native_peer_offline_contributor_v1"
}

// The existing first-bootstrap table has three private channels, self6 and
// wrapper7 before this fixture tail, yielding parent8/root9/loader10.
func versionFixtureInputs(parent, root, loader *os.File) []*os.File {
	files := []*os.File{parent, root}
	if loader != nil {
		files = append(files, loader)
	}
	return files
}
