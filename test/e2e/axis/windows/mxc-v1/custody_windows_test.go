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
	"regexp"
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

func syntheticBoundaryReceipt(t *testing.T) (string, receipt) {
	t.Helper()
	path, value := syntheticReceipt(t)
	content, err := os.ReadFile(filepath.Join(value.Artifact, filepath.FromSlash(binaryName)))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(value.Artifact, filepath.FromSlash(boundaryName)), content, 0600); err != nil {
		t.Fatal(err)
	}
	value.Scope, value.Variant = boundaryScope, boundaryVariant
	value.Binaries = append(value.Binaries, component{Path: boundaryName, SHA256: value.BinarySHA, Size: value.BinarySize})
	return path, value
}

func TestNativeIdentityReceiptMatchesVerifierAuthority(t *testing.T) {
	// Read the actual peer-language constants, rather than deriving the fixture
	// from Go's constants alone: that missed the native-identity scope change.
	source, err := os.ReadFile("verify_live_artifact.py")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"BOUNDARY_VARIANT": "standalone_std_boundary_native_identity_environment",
		"BOUNDARY_SCOPE":   "fixed_windows_native_psec_boundary_native_identity_environment",
	}
	for name, expected := range want {
		matches := regexp.MustCompile(`(?m)^`+name+` = "([^"\r\n]+)"\r?$`).FindAllSubmatch(source, -1)
		if len(matches) != 1 || string(matches[0][1]) != expected {
			t.Fatalf("verifier %s differs from the exact native-identity contract", name)
		}
	}
	if boundaryVariant != want["BOUNDARY_VARIANT"] || boundaryScope != want["BOUNDARY_SCOPE"] {
		t.Fatal("custody and verifier native-identity authority differ")
	}
	path, value := syntheticBoundaryReceipt(t)
	// Use the independent exact values above in the serialized receipt.
	value.Variant, value.Scope = want["BOUNDARY_VARIANT"], want["BOUNDARY_SCOPE"]
	pin := writeReceipt(t, path, value, nil)
	_, images, err := checkedReceipt(path, pin, "standalone-boundary")
	if err != nil {
		t.Fatal(err)
	}
	if len(images) != 3 {
		images.Close()
		t.Fatal("native-identity receipt did not pin all three synthetic images")
	}
	if err := images.Close(); err != nil {
		t.Fatal(err)
	}
	for _, legacy := range [][2]string{
		{"standalone_std_boundary_literal_argv", value.Scope},
		{value.Variant, "fixed_windows_native_psec_boundary_literal_argv"},
		{"standalone_std_boundary_literal_argv", "fixed_windows_native_psec_boundary_literal_argv"},
	} {
		changed := value
		changed.Variant, changed.Scope = legacy[0], legacy[1]
		pin = writeReceipt(t, path, changed, nil)
		if _, images, err := checkedReceipt(path, pin, "standalone-boundary"); err == nil {
			images.Close()
			t.Fatal("a historical literal-only receipt selected native-identity custody")
		}
	}
}

func TestModesRequireExactlyOneExplicitChoice(t *testing.T) {
	for _, choice := range [][2]bool{{false, false}, {true, true}} {
		if _, err := selectedMode(choice[0], choice[1]); err == nil {
			t.Fatal("ambiguous fixed mode accepted")
		}
	}
	for _, choice := range []struct {
		loader, boundary bool
		mode             string
	}{{true, false, "loader-only"}, {false, true, "standalone-boundary"}} {
		if mode, err := selectedMode(choice.loader, choice.boundary); err != nil || mode != choice.mode {
			t.Fatal("explicit mode differs")
		}
	}
}

func TestBoundaryReceiptRequiresItsOwnModeAndAllThreeImages(t *testing.T) {
	path, value := syntheticBoundaryReceipt(t)
	pin := writeReceipt(t, path, value, nil)
	if _, images, err := checkedReceipt(path, pin, "loader-only"); err == nil {
		images.Close()
		t.Fatal("boundary accepted as loader")
	}
	_, images, err := checkedReceipt(path, pin, "standalone-boundary")
	if err != nil {
		t.Fatal(err)
	}
	defer images.Close()
	if len(images) != 3 {
		t.Fatal("complete boundary bundle is not held")
	}
	if file, err := os.OpenFile(filepath.Join(value.Artifact, filepath.FromSlash(boundaryName)), os.O_WRONLY, 0); err == nil {
		file.Close()
		t.Fatal("third image can be overwritten while pinned")
	}
}

func TestBoundaryRejectsMissingOrTamperedThirdImage(t *testing.T) {
	path, value := syntheticBoundaryReceipt(t)
	pin := writeReceipt(t, path, value, nil)
	if err := os.WriteFile(filepath.Join(value.Artifact, filepath.FromSlash(boundaryName)), []byte("tampered"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, images, err := checkedReceipt(path, pin, "standalone-boundary"); err == nil {
		images.Close()
		t.Fatal("changed third image accepted")
	}
	value.Binaries = value.Binaries[:2]
	pin = writeReceipt(t, path, value, nil)
	if _, images, err := checkedReceipt(path, pin, "standalone-boundary"); err == nil {
		images.Close()
		t.Fatal("missing third image accepted")
	}
}

func TestReceiptMustBeIndependentlyPinned(t *testing.T) {
	path, value := syntheticReceipt(t)
	writeReceipt(t, path, value, nil)
	if _, image, err := checkedReceipt(path, strings.Repeat("0", 64), "loader-only"); err == nil {
		image.Close()
		t.Fatal("changed receipt accepted")
	}
}

func TestMissingExplicitNonExecutionEvidenceRefused(t *testing.T) {
	path, value := syntheticReceipt(t)
	value.ExecutionPerformed = nil
	pin := writeReceipt(t, path, value, nil)
	if _, image, err := checkedReceipt(path, pin, "loader-only"); err == nil {
		image.Close()
		t.Fatal("missing false execution evidence accepted")
	}
}

func TestDifferentCombinedLockRefused(t *testing.T) {
	path, value := syntheticReceipt(t)
	value.Lock = strings.Repeat("d", 64)
	pin := writeReceipt(t, path, value, nil)
	if _, image, err := checkedReceipt(path, pin, "loader-only"); err == nil {
		image.Close()
		t.Fatal("unreviewed lock accepted")
	}
}

func TestTrailingJSONRefused(t *testing.T) {
	path, value := syntheticReceipt(t)
	pin := writeReceipt(t, path, value, []byte("\n{}"))
	if _, image, err := checkedReceipt(path, pin, "loader-only"); err == nil {
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
	if _, image, err := checkedReceipt(path, pin, "loader-only"); err == nil {
		image.Close()
		t.Fatal("changed binary accepted")
	}
}

func TestBothDiagnosticImagesAreRequired(t *testing.T) {
	path, value := syntheticReceipt(t)
	value.Binaries = value.Binaries[:1]
	pin := writeReceipt(t, path, value, nil)
	if _, images, err := checkedReceipt(path, pin, "loader-only"); err == nil {
		images.Close()
		t.Fatal("missing loader image accepted")
	}
}

func TestHeadlessReceiptCannotBecomeLoaderDiagnostic(t *testing.T) {
	path, value := syntheticReceipt(t)
	value.Scope = "fixed_windows_native_psec_only_headless"
	value.Variant = ""
	pin := writeReceipt(t, path, value, nil)
	if _, images, err := checkedReceipt(path, pin, "loader-only"); err == nil {
		images.Close()
		t.Fatal("historical headless variant accepted as loader diagnostic")
	}
}

func TestVerifiedImageRemainsPinnedAgainstWrites(t *testing.T) {
	path, value := syntheticReceipt(t)
	pin := writeReceipt(t, path, value, nil)
	_, image, err := checkedReceipt(path, pin, "loader-only")
	if err != nil {
		t.Fatal(err)
	}
	defer image.Close()
	binary := filepath.Join(value.Artifact, filepath.FromSlash(binaryName))
	if err := os.WriteFile(binary, []byte("must not replace reviewed image"), 0600); err == nil {
		t.Fatal("verified image allowed writes while pinned")
	}
}
