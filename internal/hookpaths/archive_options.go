// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

type tarOptionSpec struct {
	name      string
	value     bool
	directory bool
	optional  bool
}

// tarOptionSpecs lists options that cannot run a child program or move an
// extracted member outside the selected destination.
var tarOptionSpecs = []tarOptionSpec{
	{name: "directory", value: true, directory: true},
	{name: "dir", value: true, directory: true},
	{name: "cd", value: true, directory: true},
	{name: "one-top-level", directory: true, optional: true},
	{name: "file", value: true},
	{name: "exclude", value: true},
	{name: "strip-components", value: true},
	{name: "extract"},
	{name: "get"},
	{name: "list"},
	{name: "overwrite"},
	{name: "keep-old-files"},
	{name: "skip-old-files"},
	{name: "no-same-owner"},
	{name: "no-same-permissions"},
	{name: "gzip"},
	{name: "bzip2"},
	{name: "xz"},
	{name: "zstd"},
	{name: "auto-compress"},
	{name: "verbose"},
	{name: "wildcards"},
}

func tarLongOption(name string) (tarOptionSpec, bool) {
	names := make([]string, len(tarOptionSpecs))
	for i, option := range tarOptionSpecs {
		names[i] = option.name
	}
	resolved, unique := longOption(name, names)
	if !unique || resolved == "" {
		return tarOptionSpec{}, false
	}
	for _, option := range tarOptionSpecs {
		if option.name == resolved {
			return option, true
		}
	}
	return tarOptionSpec{}, false
}
