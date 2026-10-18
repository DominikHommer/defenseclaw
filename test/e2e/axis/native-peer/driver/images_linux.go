// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"bytes"
	"debug/elf"
	"errors"
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
