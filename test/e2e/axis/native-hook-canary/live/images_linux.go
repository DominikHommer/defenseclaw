// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"bytes"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"errors"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

func digestBytes(data []byte) string {
	value := sha256.Sum256(data)
	return hex.EncodeToString(value[:])
}

func validateStaticELF(data []byte) error {
	file, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return errors.New("fixed static ELF header refused")
	}
	defer file.Close()
	if file.Class != elf.ELFCLASS64 || file.Data != elf.ELFDATA2LSB || file.Machine != elf.EM_X86_64 || file.Type != elf.ET_EXEC || len(file.Progs) == 0 || len(file.Progs) > 128 {
		return errors.New("fixed static Linux amd64 image required")
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

// The independently reviewed peer is a fixed glibc-linked ET_DYN image.
// Its exact digest and interpreter are pinned; only the Go testdriver,
// synthetic payload, Bubblewrap and outer custodian are static ET_EXEC.
func validateReviewedPeerELF(data []byte) error {
	file, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return errors.New("fixed reviewed peer ELF header refused")
	}
	defer file.Close()
	if file.Class != elf.ELFCLASS64 || file.Data != elf.ELFDATA2LSB || file.Machine != elf.EM_X86_64 || file.Type != elf.ET_DYN || len(file.Progs) != 12 {
		return errors.New("fixed reviewed peer Linux amd64 shape differs")
	}
	entry, interpreter, dynamic := false, false, false
	for _, p := range file.Progs {
		if p.Filesz > p.Memsz || p.Off > uint64(len(data)) || p.Filesz > uint64(len(data))-p.Off || p.Vaddr > ^uint64(0)-p.Memsz {
			return errors.New("fixed reviewed peer segment differs")
		}
		entry = entry || p.Type == elf.PT_LOAD && p.Flags&elf.PF_X != 0 && file.Entry >= p.Vaddr && file.Entry-p.Vaddr < p.Filesz
		if p.Type == elf.PT_INTERP {
			raw, err := io.ReadAll(io.LimitReader(p.Open(), 64))
			if err != nil || string(raw) != "/lib64/ld-linux-x86-64.so.2\x00" {
				return errors.New("fixed reviewed peer loader differs")
			}
			interpreter = true
		}
		dynamic = dynamic || p.Type == elf.PT_DYNAMIC
	}
	if !entry || !interpreter || !dynamic {
		return errors.New("fixed reviewed peer entry/loader differs")
	}
	return nil
}

func privateDirectory(parent *os.File, leaf string) (*os.File, error) {
	base := unix.AT_FDCWD
	if parent != nil {
		base = int(parent.Fd())
	}
	fd, err := unix.Openat(base, leaf, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "fixed-private-directory")
	var info unix.Stat_t
	if unix.Fstat(fd, &info) != nil || info.Mode&unix.S_IFMT != unix.S_IFDIR || info.Mode&07777 != 0700 || info.Uid != uint32(os.Geteuid()) {
		// The caller must retain a nonnil partial owner even on refusal.
		return file, errors.New("fixed private input directory differs")
	}
	return file, nil
}

// Source files are private, literal leaves. The digest and size come only from
// source constants; callers cannot promote an artifact or choose another path.
func admittedImage(parent *os.File, leaf string, pin imagePin, owner *cleanupOwner) (_ *os.File, resultErr error) {
	if parent == nil || !pin.valid() {
		return nil, errors.New("fixed image admission is closed")
	}
	fd, err := unix.Openat(int(parent.Fd()), leaf, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	source := os.NewFile(uintptr(fd), "fixed-admitted-source")
	defer func() { resultErr = errors.Join(resultErr, owner.releaseResource(source.Close)) }()
	var info unix.Stat_t
	if unix.Fstat(fd, &info) != nil || info.Mode&unix.S_IFMT != unix.S_IFREG || info.Mode&07777 != pin.mode || info.Uid != uint32(os.Geteuid()) || info.Nlink != 1 || info.Size != pin.size {
		return nil, errors.New("fixed source type, owner, mode or size differs")
	}
	raw, err := io.ReadAll(io.LimitReader(source, pin.size+1))
	if err != nil || int64(len(raw)) != pin.size || digestBytes(raw) != pin.sha {
		return nil, errors.New("fixed source bytes differ")
	}
	imageErr := validateStaticELF(raw)
	if leaf == "peer" && pin.sha == peerSHA {
		imageErr = validateReviewedPeerELF(raw)
	}
	if imageErr != nil {
		return nil, errors.New("fixed source ELF profile differs")
	}
	sealed, err := sealImage(raw, owner)
	if err != nil {
		return nil, err
	}
	return sealed, nil
}

func sealImage(raw []byte, owner *cleanupOwner) (_ *os.File, resultErr error) {
	fd, err := unix.MemfdCreate("fixed-contained-hook-image", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "fixed-sealed-hook-image")
	accepted := false
	defer func() {
		if !accepted {
			resultErr = errors.Join(resultErr, owner.releaseResource(file.Close))
		}
	}()
	if n, err := file.Write(raw); err != nil || n != len(raw) {
		return nil, errors.New("fixed image copy failed")
	}
	if err := file.Chmod(0500); err != nil {
		return nil, err
	}
	seals := unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL
	if _, err := unix.FcntlInt(file.Fd(), unix.F_ADD_SEALS, seals); err != nil {
		return nil, err
	}
	accepted = true
	return file, nil
}
