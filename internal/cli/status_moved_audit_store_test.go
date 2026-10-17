// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

// rel-1-0-2:GAP-0647 and GAP-0614: status pointed sqlite3 .recover at the
// archive itself and did not say which sidecars were archived with it.
func TestPrintMovedCorruptAuditStoresRecoversFromACopyAndNamesTheSidecars(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "audit.db")
	moved := db + ".corrupt-20261014T214026Z"
	for _, name := range []string{moved, moved + "-wal", moved + "-shm"} {
		if err := os.WriteFile(name, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	out := captureStdout(t, func() { printMovedCorruptAuditStores(&config.Config{AuditDB: db}, time.Time{}) })
	for _, want := range []string{
		"moved to " + moved + " together with its -wal and -shm files on ",
		audit.ArchiveRecoveryHint(moved),
		"Delete the moved file and its -wal, -shm and -journal files",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("status output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "sqlite3 "+moved+" .recover") {
		t.Fatalf("status points SQLite at the archive:\n%s", out)
	}
}
