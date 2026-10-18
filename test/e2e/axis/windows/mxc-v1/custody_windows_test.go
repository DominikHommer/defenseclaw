// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build ignore

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func syntheticReceipt(t *testing.T) (string, receipt) {
	t.Helper()
	root := t.TempDir()
	artifact := filepath.Join(root, "artifact")
	binary := filepath.Join(artifact, filepath.FromSlash(binaryName))
	if err := os.MkdirAll(filepath.Dir(binary), 0700); err != nil {
		t.Fatal(err)
	}
	content := []byte("synthetic bytes; never executed")
	if err := os.WriteFile(binary, content, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(artifact, filepath.FromSlash(loaderName)), content, 0600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(content)
	no := false
	value := receipt{Verified: true, ExecutionPerformed: &no, ProductionCertification: &no,
		Scope: diagnosticScope, Variant: diagnosticVariant, Axis: "fb5fd5f0f9377c2ccb30d7e027a36373de0d037c",
		MXC: "fda29ac63bc306b7f97f3b86b4b63d44f7f40cf2", BuildCommit: strings.Repeat("a", 40),
		BuildRun: 123, ArtifactID: 456, Archive: strings.Repeat("b", 64), Provenance: strings.Repeat("c", 64),
		Lock: combinedLock, Artifact: artifact, Binary: binaryName, BinarySHA: hex.EncodeToString(digest[:]), BinarySize: int64(len(content))}
	value.Binaries = []component{{Path: binaryName, SHA256: value.BinarySHA, Size: value.BinarySize}, {Path: loaderName, SHA256: value.BinarySHA, Size: value.BinarySize}}
	return filepath.Join(root, "receipt.json"), value
}

func writeReceipt(t *testing.T, path string, value receipt, extra []byte) string {
	t.Helper()
	content, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	content = append(content, extra...)
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:])
}

func TestReceiptMustBeIndependentlyPinned(t *testing.T) {
	path, value := syntheticReceipt(t)
	writeReceipt(t, path, value, nil)
	if _, image, err := checkedReceipt(path, strings.Repeat("0", 64)); err == nil {
		image.Close()
		t.Fatal("changed receipt accepted")
	}
}

func TestMissingExplicitNonExecutionEvidenceRefused(t *testing.T) {
	path, value := syntheticReceipt(t)
	value.ExecutionPerformed = nil
	pin := writeReceipt(t, path, value, nil)
	if _, image, err := checkedReceipt(path, pin); err == nil {
		image.Close()
		t.Fatal("missing false execution evidence accepted")
	}
}

func TestDifferentCombinedLockRefused(t *testing.T) {
	path, value := syntheticReceipt(t)
	value.Lock = strings.Repeat("d", 64)
	pin := writeReceipt(t, path, value, nil)
	if _, image, err := checkedReceipt(path, pin); err == nil {
		image.Close()
		t.Fatal("unreviewed lock accepted")
	}
}

func TestTrailingJSONRefused(t *testing.T) {
	path, value := syntheticReceipt(t)
	pin := writeReceipt(t, path, value, []byte("\n{}"))
	if _, image, err := checkedReceipt(path, pin); err == nil {
		image.Close()
		t.Fatal("trailing JSON accepted")
	}
}

func TestChangedBinaryRefused(t *testing.T) {
	path, value := syntheticReceipt(t)
	pin := writeReceipt(t, path, value, nil)
	if err := os.WriteFile(filepath.Join(value.Artifact, filepath.FromSlash(binaryName)), []byte("tampered"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, image, err := checkedReceipt(path, pin); err == nil {
		image.Close()
		t.Fatal("changed binary accepted")
	}
}

func TestBothDiagnosticImagesAreRequired(t *testing.T) {
	path, value := syntheticReceipt(t)
	value.Binaries = value.Binaries[:1]
	pin := writeReceipt(t, path, value, nil)
	if _, images, err := checkedReceipt(path, pin); err == nil {
		images.Close()
		t.Fatal("missing loader image accepted")
	}
}

func TestHeadlessReceiptCannotBecomeLoaderDiagnostic(t *testing.T) {
	path, value := syntheticReceipt(t)
	value.Scope = "fixed_windows_native_psec_only_headless"
	value.Variant = ""
	pin := writeReceipt(t, path, value, nil)
	if _, images, err := checkedReceipt(path, pin); err == nil {
		images.Close()
		t.Fatal("historical headless variant accepted as loader diagnostic")
	}
}

func TestVerifiedImageRemainsPinnedAgainstWrites(t *testing.T) {
	path, value := syntheticReceipt(t)
	pin := writeReceipt(t, path, value, nil)
	_, image, err := checkedReceipt(path, pin)
	if err != nil {
		t.Fatal(err)
	}
	defer image.Close()
	binary := filepath.Join(value.Artifact, filepath.FromSlash(binaryName))
	if err := os.WriteFile(binary, []byte("must not replace reviewed image"), 0600); err == nil {
		t.Fatal("verified image allowed writes while pinned")
	}
}
