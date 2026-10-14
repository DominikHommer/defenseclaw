//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func windowsManagedArtifactStampOfPath(t *testing.T, path string) (managedArtifactStamp, bool) {
	t.Helper()
	file, err := openWindowsManagedArtifactExclusive(path)
	if err != nil {
		t.Fatalf("open %s without writers: %v", path, err)
	}
	defer file.Close()
	return windowsManagedArtifactStamp(file)
}

// rewriteKeepingTimes changes one byte of path in place, keeps its size and
// puts every time stamp back, as a writer hiding a change would.
func rewriteKeepingTimes(t *testing.T, path string, fill byte) {
	t.Helper()
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	attributes, err := windows.CreateFile(name, windows.FILE_READ_ATTRIBUTES|windows.FILE_WRITE_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(attributes)
	var basic windowsManagedArtifactFileBasicInfo
	size := uint32(unsafe.Sizeof(basic))
	if err := windows.GetFileInformationByHandleEx(attributes, windows.FileBasicInfo, (*byte)(unsafe.Pointer(&basic)), size); err != nil {
		t.Fatal(err)
	}
	writer, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.WriteAt([]byte{fill}, 4096); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := windows.SetFileInformationByHandle(attributes, windows.FileBasicInfo, (*byte)(unsafe.Pointer(&basic)), size); err != nil {
		t.Fatal(err)
	}
}

// GAP-0438: the stamp follows the file version: a same-size write whose
// time stamps were put back still gets a new change-journal number.
func TestWindowsManagedArtifactStampFollowsTheFileVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "defenseclaw-hook.exe")
	writeManagedArtifactFixture(t, path, 1)
	first, ok := windowsManagedArtifactStampOfPath(t, path)
	if !ok {
		t.Skip("the test volume keeps no change journal; the memo is off there")
	}
	if again, _ := windowsManagedArtifactStampOfPath(t, path); again != first {
		t.Fatalf("the stamp of an unchanged file moved: %+v then %+v", first, again)
	}
	rewriteKeepingTimes(t, path, 9)
	later, ok := windowsManagedArtifactStampOfPath(t, path)
	if !ok {
		t.Fatal("no stamp after an in-place write")
	}
	if later.USN == first.USN || later == first {
		t.Fatalf("a same-size write with its times put back kept the stamp: %+v", later)
	}
	if later.Size != first.Size || later.ID != first.ID {
		t.Fatalf("the fixture did not keep size and file id: %+v then %+v", first, later)
	}
}

// The memo answers only for an unchanged file that no writer holds open.
func TestWindowsManagedArtifactDigestMemoAnswersOnlyForAnUnwrittenVersion(t *testing.T) {
	useManagedArtifactDigestSeams(t, windowsManagedArtifactStamp, openWindowsManagedArtifactExclusive)
	path := filepath.Join(t.TempDir(), "defenseclaw-hook.exe")
	first := writeManagedArtifactFixture(t, path, 1)
	if _, ok := windowsManagedArtifactStampOfPath(t, path); !ok {
		t.Skip("the test volume keeps no change journal; the memo is off there")
	}
	if got := managedArtifactDigestOf(t, path, true); got != first {
		t.Fatalf("digest %s, want %s", got, first)
	}
	const sentinel = "sha256:remembered"
	setRemembered := func() {
		t.Helper()
		managedArtifactDigests.Lock()
		defer managedArtifactDigests.Unlock()
		entry, ok := managedArtifactDigests.entries[managedArtifactDigestKey(path)]
		if !ok {
			t.Fatal("a full read of an unwritten version was not remembered")
		}
		entry.digest = sentinel
		managedArtifactDigests.entries[managedArtifactDigestKey(path)] = entry
	}
	setRemembered()
	if got := managedArtifactDigestOf(t, path, true); got != sentinel {
		t.Fatalf("an unchanged version was read again: %s", got)
	}

	// A writer that holds the file open could change it under one stamp:
	// the file is read in full and nothing is remembered.
	writer, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := managedArtifactDigestOf(t, path, true); got != first {
		t.Fatalf("with a writer open: digest %s, want the full read %s", got, first)
	}
	managedArtifactDigests.Lock()
	_, kept := managedArtifactDigests.entries[managedArtifactDigestKey(path)]
	managedArtifactDigests.Unlock()
	if kept {
		t.Fatal("a digest read while a writer held the file was remembered")
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	// An in-place write with every time stamp put back is read again.
	if got := managedArtifactDigestOf(t, path, true); got != first {
		t.Fatalf("digest %s, want %s", got, first)
	}
	setRemembered()
	rewriteKeepingTimes(t, path, 9)
	got := managedArtifactDigestOf(t, path, true)
	if got == sentinel || got == first {
		t.Fatalf("a rewritten file with its times put back kept the remembered digest: %s", got)
	}

	// A replacement by rename (another file id) is read again.
	setRemembered()
	replacement := path + ".new"
	want := writeManagedArtifactFixture(t, replacement, 5)
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
	if got := managedArtifactDigestOf(t, path, true); got != want {
		t.Fatalf("a replaced file kept the remembered digest: %s, want %s", got, want)
	}
}
