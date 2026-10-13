// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path/filepath"
	"slices"
	"testing"
)

func TestShellTextWriteOperands(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "proj")
	for _, row := range []struct {
		command string
		path    string
	}{
		{`trap 'echo x >> disklink' EXIT; true`, "disklink"},
		{`bash <<< 'echo x >> disklink'`, "disklink"},
		{`bash <(echo 'echo x >> disklink')`, "disklink"},
		{`source <(echo 'echo x >> disklink')`, "disklink"},
		{`. /dev/stdin <<< 'echo x >> disklink'`, "disklink"},
		{`echo 'echo x >> disklink' > s.sh; bash s.sh`, "disklink"},
		{`echo 'echo x >> disklink' > s.sh; . ./s.sh`, "disklink"},
		{`printf 'cp payload disklink' > s.sh && sh s.sh`, "disklink"},
		{"cat > s.sh <<'EOF'\necho x >> disklink\nEOF\nchmod +x s.sh; ./s.sh", "disklink"},
		{"make -f - <<'EOF'\nall:\n\tcp payload disklink\nEOF", "disklink"},
		{`trap 'echo x >> out/log' EXIT; true`, "out/log"},
		{`bash <<< 'echo x >> out/log'`, "out/log"},
		{`echo 'echo x >> out/log' > s.sh; bash s.sh`, "out/log"},
	} {
		t.Run(row.command, func(t *testing.T) {
			paths, parsed, _ := ShellWriteOperands(row.command, cwd, home)
			for _, extra := range ShellExtraWriteOperands(row.command, cwd, home) {
				paths = append(paths, extra.Path)
			}
			if !parsed || !slices.Contains(paths, filepath.Join(cwd, row.path)) {
				t.Errorf("write operands = %v, parsed = %v", paths, parsed)
			}
		})
	}
}
