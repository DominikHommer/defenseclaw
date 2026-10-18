// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"bytes"
	"crypto/rand"
	"debug/elf"
	"encoding/hex"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// All paths below this helper are fixed artifact members or newly generated
// synthetic fixture names. Relative opens walk every component without links.
func openRelative(parent *os.File, name string, flags int) (*os.File, error) {
	if parent == nil || name == "" || len(name) > 4096 || !filepath.IsLocal(name) || strings.ContainsRune(name, 0) {
		return nil, errors.New("fixed relative object refused")
	}
	parts := strings.Split(name, "/")
	if len(parts) > 16 {
		return nil, errors.New("fixed object depth refused")
	}
	fd, err := unix.FcntlInt(parent.Fd(), unix.F_DUPFD_CLOEXEC, 3)
	if err != nil {
		return nil, err
	}
	for i, part := range parts {
		if part == "" || part == "." || part == ".." {
			_ = unix.Close(fd)
			return nil, errors.New("fixed object component refused")
		}
		access := unix.O_RDONLY | unix.O_DIRECTORY
		if i == len(parts)-1 {
			access = flags | unix.O_NONBLOCK
		}
		next, err := unix.Openat(fd, part, access|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		_ = unix.Close(fd)
		if err != nil {
			return nil, err
		}
		fd = next
	}
	return os.NewFile(uintptr(fd), "fixed-held-object"), nil
}

func openDirectory(path string) (*os.File, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return nil, errors.New("exact absolute directory refused")
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	root := os.NewFile(uintptr(fd), "filesystem-root")
	defer root.Close()
	return openRelative(root, strings.TrimPrefix(path, "/"), unix.O_RDONLY|unix.O_DIRECTORY)
}

func privateDirectory(file *os.File) error {
	var stat unix.Stat_t
	if unix.Fstat(int(file.Fd()), &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != uint32(os.Geteuid()) || stat.Mode&0777 != 0700 {
		return errors.New("fixed owned private directory refused")
	}
	return nil
}

func boundedFile(parent *os.File, path string, maximum int64, expected string) (*os.File, []byte, error) {
	file, err := openRelative(parent, path, unix.O_RDONLY)
	if err != nil {
		return nil, nil, errors.New("reviewed fixed artifact open refused")
	}
	accepted := false
	defer func() {
		if !accepted {
			_ = file.Close()
		}
	}()
	var stat unix.Stat_t
	if unix.Fstat(int(file.Fd()), &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&06000 != 0 || stat.Nlink != 1 || stat.Size < 1 || stat.Size > maximum {
		return nil, nil, errors.New("reviewed fixed artifact type/size/link refused")
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(data)) != stat.Size || digestBytes(data) != expected {
		return nil, nil, errors.New("reviewed fixed artifact bytes differ")
	}
	accepted = true
	return file, data, nil
}

func validateStaticELF(data []byte) error {
	file, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return errors.New("fixed static ELF header refused")
	}
	defer file.Close()
	if file.Class != elf.ELFCLASS64 || file.Data != elf.ELFDATA2LSB || file.Machine != elf.EM_X86_64 || file.Type != elf.ET_EXEC || len(file.Progs) == 0 || len(file.Progs) > 128 {
		return errors.New("fixed static Linux image required")
	}
	entry := false
	for _, p := range file.Progs {
		if p.Type == elf.PT_INTERP || p.Type == elf.PT_DYNAMIC || p.Filesz > p.Memsz || p.Off > uint64(len(data)) || p.Filesz > uint64(len(data))-p.Off || p.Vaddr > ^uint64(0)-p.Memsz {
			return errors.New("dynamic or malformed static image")
		}
		entry = entry || p.Type == elf.PT_LOAD && p.Flags&elf.PF_X != 0 && file.Entry >= p.Vaddr && file.Entry-p.Vaddr < p.Filesz
	}
	if !entry {
		return errors.New("static entry outside executable file-backed segment")
	}
	return nil
}

func sealBytes(data []byte, expected string) (_ *os.File, resultErr error) {
	if len(data) < 64 || len(data) > 32<<20 || digestBytes(data) != expected || validateStaticELF(data) != nil {
		return nil, errors.New("reviewed fixed image bytes refused")
	}
	fd, err := unix.MemfdCreate("fixed-reviewed-outer-wrapper", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "fixed-reviewed-sealed-wrapper")
	accepted := false
	defer func() {
		if !accepted {
			resultErr = errors.Join(resultErr, file.Close())
		}
	}()
	if _, err := file.Write(data); err != nil {
		return nil, err
	}
	if err := file.Chmod(0500); err != nil {
		return nil, err
	}
	if _, err := unix.FcntlInt(file.Fd(), unix.F_ADD_SEALS, unix.F_SEAL_SEAL|unix.F_SEAL_GROW|unix.F_SEAL_SHRINK|unix.F_SEAL_WRITE); err != nil {
		return nil, err
	}
	accepted = true
	return file, nil
}

// fixtureCapabilities are created by the trusted host driver before any USER
// namespace clone. The parent owner check is never inferred from overflow UID.
type fixtureCapabilities struct {
	parent, root *os.File
	path         string
}

func (f *fixtureCapabilities) close() error {
	if f == nil {
		return nil
	}
	var errs []error
	if f.root != nil {
		errs = append(errs, f.root.Close())
	}
	if f.parent != nil {
		errs = append(errs, f.parent.Close())
	}
	return errors.Join(errs...)
}
func trustedTemporaryParent(st unix.Stat_t) bool {
	return st.Mode&unix.S_IFMT == unix.S_IFDIR && st.Uid == 0 && st.Mode&unix.S_ISVTX != 0
}
func newHostFixture() (*fixtureCapabilities, error) {
	parent, err := openDirectory("/tmp")
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	var st unix.Stat_t
	if unix.Fstat(int(parent.Fd()), &st) != nil || !trustedTemporaryParent(st) {
		return nil, errors.New("fixed host temporary parent refused")
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, err
	}
	return createHostFixtureUnder(parent, "/tmp", hex.EncodeToString(random[:]))
}
func createHostFixtureUnder(parent *os.File, displayParent, nonce string) (_ *fixtureCapabilities, resultErr error) {
	if parent == nil || len(nonce) != 32 || strings.Trim(nonce, "0123456789abcdef") != "" {
		return nil, errors.New("fixed fixture identity refused")
	}
	name := "dc-axis-native-peer-" + nonce
	if err := unix.Mkdirat(int(parent.Fd()), name, 0700); err != nil {
		return nil, err
	}
	f := &fixtureCapabilities{path: filepath.Join(displayParent, name)}
	// A partial creation is returned for exact evidence and handle cleanup; the
	// fresh task-created directory is retained on every outcome.
	fd, err := unix.FcntlInt(parent.Fd(), unix.F_DUPFD_CLOEXEC, 3)
	if err != nil {
		return f, err
	}
	f.parent = os.NewFile(uintptr(fd), "fixed-held-host-tmp-parent")
	f.root, err = openRelative(parent, name, unix.O_RDONLY|unix.O_DIRECTORY)
	if err != nil {
		return f, err
	}
	return f, privateDirectory(f.root)
}
func checkInheritedFixture(parent, root *os.File) error {
	if parent == nil || root == nil || privateDirectory(root) != nil {
		return errors.New("fixed held fixture root refused")
	}
	var st unix.Stat_t
	if unix.Fstat(int(parent.Fd()), &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Mode&unix.S_ISVTX == 0 {
		return errors.New("fixed held fixture parent refused")
	}
	// Display strings correlate retained objects only; never reopen through them.
	var value [512]byte
	n, err := unix.Readlink("/proc/self/fd/"+fmt.Sprint(root.Fd()), value[:])
	if err != nil || n <= 0 || n >= len(value) {
		return errors.New("fixed fixture display refused")
	}
	display := string(value[:n])
	name := filepath.Base(display)
	nonce := strings.TrimPrefix(name, "dc-axis-native-peer-")
	if filepath.Dir(display) != "/tmp" || len(nonce) != 32 || strings.Trim(nonce, "0123456789abcdef") != "" || name != "dc-axis-native-peer-"+nonce {
		return errors.New("fixed fixture display refused")
	}
	observed, err := openRelative(parent, name, unix.O_RDONLY|unix.O_DIRECTORY)
	if err != nil {
		return err
	}
	defer observed.Close()
	a, err := observed.Stat()
	if err != nil {
		return err
	}
	b, err := root.Stat()
	if err != nil {
		return err
	}
	if !os.SameFile(a, b) {
		return errors.New("fixed fixture held identity differs")
	}
	return nil
}
