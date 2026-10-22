// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package daemon

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// A gateway started by Daemon.Start records the credential configuration
// it applied; the record counts only for the process it names, with the
// kernel start identity that process has now. Outside a daemon child
// nothing is written.
func TestAppliedAuthNamesOnlyTheGatewayThatRecordedIt(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(EnvDataDir, dir)
	t.Setenv(EnvDaemon, "")
	if err := RecordAppliedAuth(AppliedAuth{Token: "inline"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(dir, AppliedAuthFileName)); !os.IsNotExist(err) {
		t.Fatalf("a process that is no daemon child wrote the record: %v", err)
	}
	t.Setenv(EnvDaemon, "1")
	want := AppliedAuth{TokenEnv: "R104_CUSTOM_TOKEN", Token: "inline"}
	if err := RecordAppliedAuth(want); err != nil {
		t.Fatal(err)
	}
	d := New(dir)
	pid := os.Getpid()
	if got, ok := d.AppliedAuth(pid); !ok || got != want {
		t.Fatalf("AppliedAuth(%d) = %+v, %v; want %+v", pid, got, ok, want)
	}
	if info, err := os.Stat(filepath.Join(dir, AppliedAuthFileName)); err != nil {
		t.Fatal(err)
	} else if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("the record is readable by others: %v", info.Mode())
	}
	for _, other := range []int{0, -1, pid + 1} {
		if _, ok := d.AppliedAuth(other); ok {
			t.Fatalf("the record answered for PID %d", other)
		}
	}
	// A record that names this PID with another start identity was left by
	// a process the OS gave the PID to before.
	stale, err := json.Marshal(appliedAuthRecord{PID: pid, StartIdentity: "1", AppliedAuth: want})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, AppliedAuthFileName), stale, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := d.AppliedAuth(pid); ok {
		t.Fatal("a record with another start identity answered")
	}
	if _, ok := New(t.TempDir()).AppliedAuth(pid); ok {
		t.Fatal("a data directory without a record answered")
	}
}
