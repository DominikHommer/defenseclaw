// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package bridgeprocess

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"golang.org/x/sys/windows"
)

func TestWindowsAssetRoleMasksNeverPromoteOrForwardExtraRights(t *testing.T) {
	for _, write := range []bool{false, true} {
		required := uint32(0x120089)
		if write {
			required |= 0x116
		}
		if windowsAssetRequiredAccess(write) != required || !windowsAssetSourceAllows(required, write) || !windowsAssetCopyAllows(required, write) || !windowsAssetCopyAllows(required|0x20, write) {
			t.Fatal("mapped role mask differs from owned SDK floor")
		}
		for bit := uint32(1); bit != 0; bit <<= 1 {
			if required&bit != 0 && (windowsAssetSourceAllows(required & ^bit, write) || windowsAssetCopyAllows(required & ^bit, write)) {
				t.Fatal("missing role right admitted")
			}
		}
		for _, extra := range []uint32{windows.DELETE, windows.WRITE_DAC, windows.WRITE_OWNER, windows.ACCESS_SYSTEM_SECURITY} {
			if !windowsAssetSourceAllows(required|extra, write) || windowsAssetCopyAllows(required|extra, write) {
				t.Fatal("source rights were not reduced")
			}
		}
	}
	if windowsAssetSourceAllows(0x120089, true) || !windowsAssetSourceAllows(0x12019f, false) {
		t.Fatal("role reduction became promotion")
	}
	for _, invalid := range []windows.Handle{0, windows.InvalidHandle} {
		for _, cause := range []error{nil, errors.New("fixed refusal"), windows.NTStatus(0xc0000022)} {
			owned, err := windowsImageOpenResult(invalid, cause, nil)
			if owned != nil || !errors.Is(err, ErrAdmission) {
				t.Fatal("invalid handle gained cleanup authority")
			}
		}
	}
}

// Host filesystem only: fresh private directories and fixed public bytes.
// No child, token setter, sandbox, PE execution or external ACL mutation.
func windowsAssetFixture(t *testing.T) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "fixed-private-assets")
	if created, err := safefile.CreatePrivateDirectory(root); err != nil || !created {
		t.Fatal("fresh private asset root refused")
	}
	return root
}

func windowsAssetTestOpen(t *testing.T, path string, directory, write bool) *os.File {
	t.Helper()
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	access, flags := uint32(windows.GENERIC_READ), uint32(windows.FILE_FLAG_OPEN_REPARSE_POINT)
	if write {
		access |= windows.GENERIC_WRITE
	}
	if directory {
		flags |= windows.FILE_FLAG_BACKUP_SEMANTICS
	}
	// Delete sharing here is deliberate: only the returned capability pin may
	// explain the rename refusal below. The original handle does not block it.
	handle, err := windows.CreateFile(name, access, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, flags, 0)
	if err != nil {
		t.Fatal("open fixed asset")
	}
	file := os.NewFile(uintptr(handle), "fixed-public-native-asset")
	t.Cleanup(func() { _ = file.Close() })
	return file
}

func TestWindowsAssetDirectorySelfReopenRetainsIdentityAndRefusedCopyUntilClose(t *testing.T) {
	root := windowsAssetFixture(t)
	path, renamed := filepath.Join(root, "fixed-directory"), filepath.Join(root, "fixed-renamed")
	if created, err := safefile.CreatePrivateDirectory(path); err != nil || !created {
		t.Fatal("fresh directory refused")
	}
	source := windowsAssetTestOpen(t, path, true, false)
	if err := os.Rename(path, renamed); err != nil {
		t.Fatal("rename positive control with original handle")
	}
	if err := os.Rename(renamed, path); err != nil {
		t.Fatal("restore rename positive control")
	}
	copy, directory, id, err := windowsAsset(source, false)
	if copy != nil {
		defer func() {
			if copy != nil {
				_ = copy.Close()
			}
		}()
	}
	if err != nil || copy == nil || !directory {
		t.Fatal("held directory self reopen refused")
	}
	actual, err := windowsImageMetadata(source, true)
	granted, queryErr := windowsAssetGrantedAccess(windows.Handle(copy.Fd()))
	if err != nil || actual != id || queryErr != nil || granted != 0x120089 {
		t.Fatal("directory identity or reduced role differs")
	}
	// Real handles exercise both possible post-allocation refusal branches.
	// No child, image mapping or failed native call needs to be manufactured.
	for _, native := range []bool{false, true} {
		var duplicate windows.Handle
		if err := windows.DuplicateHandle(windows.CurrentProcess(), windows.Handle(copy.Fd()), windows.CurrentProcess(), &duplicate, 0, false, windows.DUPLICATE_SAME_ACCESS); err != nil {
			t.Fatal("duplicate fixed capability")
		}
		controlErr, nativeErr := error(errors.New("fixed control refusal")), error(nil)
		if native {
			controlErr, nativeErr = nil, windows.NTStatus(0xc0000022)
		}
		refused, err := windowsImageOpenResult(duplicate, controlErr, nativeErr)
		if refused == nil || !errors.Is(err, ErrAdmission) {
			if refused != nil {
				_ = refused.Close()
			}
			t.Fatal("allocated open refusal lost its handle")
		}
		actual, metadataErr := windowsImageMetadata(refused, true)
		closeErr := refused.Close()
		if metadataErr != nil || actual != id || closeErr != nil {
			t.Fatal("allocated refusal identity or cleanup differs")
		}
	}
	wrong := id
	wrong.File[0] ^= 1
	refused, _, _, err := windowsValidateAssetCopy(copy, true, wrong, false)
	if !errors.Is(err, ErrAdmission) || refused != copy {
		t.Fatal("allocated refusal lost its exact cleanup handle")
	}
	if err := os.Rename(path, renamed); err == nil {
		t.Fatal("held refused capability allowed directory replacement")
	}
	if err := refused.Close(); err != nil {
		t.Fatal("refused capability cleanup")
	}
	copy = nil
	if err := os.Rename(path, renamed); err != nil {
		t.Fatal("rename did not resume after exact capability close")
	}
}

func TestWindowsAssetReadOnlySourcesCannotBecomeWritableAndFullRolesWork(t *testing.T) {
	for _, directory := range []bool{false, true} {
		t.Run(map[bool]string{false: "file", true: "directory"}[directory], func(t *testing.T) {
			root := windowsAssetFixture(t)
			path := filepath.Join(root, "fixed-public-asset")
			if directory {
				if created, err := safefile.CreatePrivateDirectory(path); err != nil || !created {
					t.Fatal("fresh directory refused")
				}
			} else if err := os.WriteFile(path, []byte("fixed-public-bytes\n"), 0600); err != nil {
				t.Fatal(err)
			}
			read := windowsAssetTestOpen(t, path, directory, false)
			refused, _, _, err := windowsAsset(read, true)
			if refused != nil {
				defer refused.Close()
			}
			if !errors.Is(err, ErrAdmission) || refused != nil {
				t.Fatal("readonly handle promoted or allocated before rights refusal")
			}
			write := windowsAssetTestOpen(t, path, directory, true)
			owned, kind, _, err := windowsAsset(write, true)
			if owned != nil {
				defer owned.Close()
			}
			if err != nil || owned == nil || kind != directory {
				t.Fatal("full original writable role refused")
			}
			granted, err := windowsAssetGrantedAccess(windows.Handle(owned.Fd()))
			if err != nil || granted != 0x12019f {
				t.Fatal("writable copy role differs")
			}
			if directory {
				child, err := windowsImageOpen(owned, "fixed-child.txt", false, windows.FILE_CREATE, nil, windows.GENERIC_READ|windows.GENERIC_WRITE|windows.SYNCHRONIZE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE)
				if child != nil {
					defer child.Close()
				}
				if err != nil || child == nil {
					t.Fatalf("writable directory capability cannot create fixed child: %v", err)
				}
				if _, err := child.Write([]byte("fixed-public-child\n")); err != nil {
					t.Fatal("fixed child write refused")
				}
			} else if n, err := owned.WriteAt([]byte("F"), 0); err != nil || n != 1 {
				t.Fatal("writable file capability cannot write")
			}
		})
	}
}
