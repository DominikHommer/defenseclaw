// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package namespaceinit

import (
	"crypto/sha256"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func TestPrivateRootPinnedImageRefusesMutationAndPartialSeal(t *testing.T) {
	data := make([]byte, 128)
	for i := range data {
		data[i] = byte(i)
	}
	fd, err := unix.MemfdCreate("fixed-private-root-test", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		t.Fatal(err)
	}
	file := os.NewFile(uintptr(fd), "fixed-test-image")
	defer file.Close()
	if n, err := file.Write(data); err != nil || n != len(data) {
		t.Fatal("test image write refused")
	}
	if _, err := unix.FcntlInt(file.Fd(), unix.F_ADD_SEALS, seals); err != nil {
		t.Fatal(err)
	}
	image := PinnedSealedFile{File: file, Size: int64(len(data)), SHA256: sha256.Sum256(data)}
	if err := validatePinnedSealedImage(&image); err != nil {
		t.Fatal(err)
	}
	if err := hashPinnedImage(&image, file.Fd()); err != nil {
		t.Fatal(err)
	}
	if hashPinnedImage(&image, file.Fd()+1) == nil {
		t.Fatal("wrong fixed image descriptor accepted")
	}
	wrongHash := image
	wrongHash.SHA256[0] ^= 1
	if validatePinnedSealedImage(&wrongHash) == nil {
		t.Fatal("wrong pinned digest accepted")
	}
	wrongSize := image
	wrongSize.Size++
	if validatePinnedSealedImage(&wrongSize) == nil {
		t.Fatal("wrong pinned size accepted")
	}
	overBudget := image
	overBudget.Size = privateRootImageBudget + 1
	if validatePinnedSealedImage(&overBudget) == nil {
		t.Fatal("oversized input accepted")
	}
	absent := image
	absent.File = nil
	if validatePinnedSealedImage(&absent) == nil {
		t.Fatal("missing owned file accepted")
	}
	partialFD, err := unix.MemfdCreate("fixed-unsealed-image", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		t.Fatal(err)
	}
	partial := os.NewFile(uintptr(partialFD), "fixed-unsealed-test")
	defer partial.Close()
	if n, err := partial.Write(data); err != nil || n != len(data) {
		t.Fatal("partial image write refused")
	}
	unsealed := PinnedSealedFile{File: partial, Size: int64(len(data)), SHA256: sha256.Sum256(data)}
	if validatePinnedSealedImage(&unsealed) == nil {
		t.Fatal("unsealed image accepted")
	}
}

func TestPrivateRootControlPipeTypeAndDirection(t *testing.T) {
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer read.Close()
	defer write.Close()
	if err := validPrivatePipe(read, read.Fd(), unix.O_RDONLY); err != nil {
		t.Fatal(err)
	}
	if err := validPrivatePipe(write, write.Fd(), unix.O_WRONLY); err != nil {
		t.Fatal(err)
	}
	if validPrivatePipe(read, read.Fd(), unix.O_WRONLY) == nil {
		t.Fatal("wrong pipe direction accepted")
	}
	if validPrivatePipe(read, read.Fd()+1, unix.O_RDONLY) == nil {
		t.Fatal("wrong pipe descriptor accepted")
	}
}
