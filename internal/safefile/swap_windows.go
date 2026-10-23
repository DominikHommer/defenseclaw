// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package safefile

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"time"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

// ErrSwapRaced reports that a compare-and-swap found a different file than
// the one it expected: another writer changed it. The newer file is kept.
var ErrSwapRaced = errors.New("safefile: the file changed concurrently")

// swapLockTimeout bounds how long a compare-and-swap waits for another
// process to close a file it has open for writing.
const swapLockTimeout = 2 * time.Second

// SwapExpectation is the file a compare-and-swap may replace: absent, or
// present with exactly Data.
type SwapExpectation struct {
	Exists bool
	Data   []byte
}

// SwapResult reports what a compare-and-swap changed.
type SwapResult struct {
	// Swapped reports that the new file was published (or, for
	// RemoveFileIfUnchanged, that the file was removed).
	Swapped bool
	// Replaced reports that an existing file was replaced.
	Replaced bool
}

// CompareAndSwapFile moves source to destination only while destination
// holds expected. Writers that do not take the caller's lock, an
// administrator's editor or the agent itself, can save between a read and a
// write, so the comparison and the replacement happen under one handle: the
// current file is opened sharing only reads, so no other process can write,
// rename or delete it while the swap compares the bytes read through that
// handle, renames the file aside through the same handle and moves source in
// under its name. A file another process creates in the instant the name is
// free is newer: the swap keeps it and drops the older file.
//
// Any other file than expected returns ErrSwapRaced with destination
// untouched and source left for the caller to remove. inspect, when set, runs
// on the locked current file before the comparison, so a caller can read its
// metadata or refuse it.
func CompareAndSwapFile(
	source, destination string,
	expected SwapExpectation,
	limit int,
	inspect func(*os.File) error,
) (SwapResult, error) {
	current, err := lockFileForSwap(destination)
	if err != nil {
		return SwapResult{}, err
	}
	if current == nil {
		if expected.Exists {
			return SwapResult{}, swapRaced(destination)
		}
		if err := moveFileNoReplace(source, destination); err != nil {
			if swapNameTaken(err) {
				return SwapResult{}, swapRaced(destination)
			}
			return SwapResult{}, fmt.Errorf("safefile: publish %s: %w", destination, err)
		}
		return SwapResult{Swapped: true}, nil
	}
	defer current.Close()
	if err := matchLockedFile(current, expected, limit, inspect); err != nil {
		return SwapResult{}, err
	}
	aside := source + ".replaced"
	if err := renameLockedFile(current, aside); err != nil {
		return SwapResult{}, fmt.Errorf("safefile: move aside %s: %w", destination, err)
	}
	if err := moveFileNoReplace(source, destination); err != nil {
		if swapNameTaken(err) {
			// Another writer saved a new file under the free name: it is newer
			// than the file this swap holds.
			dropLockedFile(current, aside)
			return SwapResult{}, swapRaced(destination)
		}
		if restoreErr := renameLockedFile(current, destination); restoreErr != nil {
			return SwapResult{}, fmt.Errorf("safefile: publish %s: %w (the replaced file is kept at %s: %v)",
				destination, err, aside, restoreErr)
		}
		return SwapResult{}, fmt.Errorf("safefile: publish %s: %w", destination, err)
	}
	dropLockedFile(current, aside)
	return SwapResult{Swapped: true, Replaced: true}, nil
}

// RemoveFileIfUnchanged deletes path only while it holds expected: it reads
// and deletes the file through one handle no other process can write
// through. A different or missing file returns ErrSwapRaced; a different file
// is kept. inspect is as for CompareAndSwapFile.
func RemoveFileIfUnchanged(path string, expected []byte, limit int, inspect func(*os.File) error) (SwapResult, error) {
	current, err := lockFileForSwap(path)
	if err != nil {
		return SwapResult{}, err
	}
	if current == nil {
		return SwapResult{}, swapRaced(path)
	}
	defer current.Close()
	if err := matchLockedFile(current, SwapExpectation{Exists: true, Data: expected}, limit, inspect); err != nil {
		return SwapResult{}, err
	}
	if err := deleteLockedFile(current); err != nil {
		return SwapResult{}, fmt.Errorf("safefile: remove %s: %w", path, err)
	}
	return SwapResult{Swapped: true, Replaced: true}, nil
}

func swapRaced(path string) error {
	return fmt.Errorf("%w: %s", ErrSwapRaced, path)
}

// matchLockedFile reports ErrSwapRaced unless the locked file holds expected.
func matchLockedFile(file *os.File, expected SwapExpectation, limit int, inspect func(*os.File) error) error {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(file.Fd()), &info); err != nil {
		return err
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DEVICE) != 0 {
		return fmt.Errorf("safefile: refusing a file that is not regular: %s", file.Name())
	}
	if inspect != nil {
		if err := inspect(file); err != nil {
			return err
		}
	}
	if !expected.Exists {
		return swapRaced(file.Name())
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return err
	}
	data, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if err != nil {
		return err
	}
	if len(data) > limit || !bytes.Equal(data, expected.Data) {
		return swapRaced(file.Name())
	}
	return nil
}

// lockFileForSwap opens path for reading and deleting, sharing only reads:
// while the handle is open no other process can write, rename, replace or
// delete the file, and readers can still read it. It waits a short while for
// a writer that has the file open, and returns nil for a missing file.
func lockFileForSwap(path string) (*os.File, error) {
	name, err := winpath.UTF16Ptr(path)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(swapLockTimeout)
	for {
		handle, err := windows.CreateFile(
			name,
			windows.GENERIC_READ|windows.DELETE|windows.READ_CONTROL,
			windows.FILE_SHARE_READ,
			nil,
			windows.OPEN_EXISTING,
			windows.FILE_FLAG_OPEN_REPARSE_POINT,
			0,
		)
		if err == nil {
			return os.NewFile(uintptr(handle), path), nil
		}
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
			return nil, nil
		}
		if !errors.Is(err, windows.ERROR_SHARING_VIOLATION) || !time.Now().Before(deadline) {
			return nil, fmt.Errorf("safefile: open %s: %w", path, err)
		}
		time.Sleep(time.Millisecond)
	}
}

// renameLockedFile renames the file behind file to target, which must not
// exist.
func renameLockedFile(file *os.File, target string) error {
	name, err := windows.UTF16FromString(target)
	if err != nil {
		return err
	}
	type fileRenameInfo struct {
		ReplaceIfExists uint32
		RootDirectory   windows.Handle
		FileNameLength  uint32
		FileName        [1]uint16
	}
	size := unsafe.Offsetof(fileRenameInfo{}.FileName) + uintptr(len(name))*2
	buffer := make([]uint64, (size+7)/8)
	info := (*fileRenameInfo)(unsafe.Pointer(&buffer[0]))
	info.FileNameLength = uint32((len(name) - 1) * 2)
	copy(unsafe.Slice(&info.FileName[0], len(name)), name)
	return windows.SetFileInformationByHandle(
		windows.Handle(file.Fd()), windows.FileRenameInfo, (*byte)(unsafe.Pointer(&buffer[0])), uint32(size))
}

// deleteLockedFile deletes the file behind file when the handle closes.
func deleteLockedFile(file *os.File) error {
	deleteFile := byte(1) // FILE_DISPOSITION_INFO.DeleteFile
	return windows.SetFileInformationByHandle(windows.Handle(file.Fd()), windows.FileDispositionInfo, &deleteFile, 1)
}

// dropLockedFile deletes the replaced file moved aside to aside.
func dropLockedFile(file *os.File, aside string) {
	if deleteLockedFile(file) == nil {
		return
	}
	_ = file.Close()
	_ = os.Remove(aside)
}

// moveFileNoReplace moves source to destination, which must not exist.
func moveFileNoReplace(source, destination string) error {
	from, err := winpath.UTF16Ptr(source)
	if err != nil {
		return err
	}
	to, err := winpath.UTF16Ptr(destination)
	if err != nil {
		return err
	}
	return windows.MoveFileEx(from, to, windows.MOVEFILE_WRITE_THROUGH)
}

func swapNameTaken(err error) bool {
	return errors.Is(err, windows.ERROR_ALREADY_EXISTS) || errors.Is(err, windows.ERROR_FILE_EXISTS)
}
