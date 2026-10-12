// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

// Package enterprisebundle reads and validates signed policy bundles for the
// standalone enterprise profile: the manifest and its strict decoder, the
// archive and directory readers with their limits, the files[] integrity
// check, secret references and the inline-secret scan, group reachability
// warnings, and the effective policy digest of a bundle per platform.
//
// Everything here is a pure function of its inputs: nothing is written,
// installed or published, and no bundle content ever appears in an error.
// Signatures, trust anchors and the version floor are checked by the callers
// (bundle verify and apply).
package enterprisebundle

import (
	"errors"
	"fmt"
	"strconv"
)

// Code is the stable error code of a refused bundle (spec section 7). The
// receipt, the CLI JSON and the MDM result carry it unchanged.
type Code string

const (
	CodeArchiveInvalid   Code = "archive_invalid"
	CodeManifestInvalid  Code = "manifest_invalid"
	CodeFileMissing      Code = "file_missing"
	CodeFileExtra        Code = "file_extra"
	CodeFileHashMismatch Code = "file_hash_mismatch"
	CodeInlineSecret     Code = "inline_secret"
	CodeConfigInvalid    Code = "config_invalid"
)

// Limits of the readers and the manifest decoder. A bundle over any of them
// is refused before anything else is looked at.
const (
	MaxCompressedBytes = 4 << 20   // a .dcbundle file
	MaxExpandedBytes   = 16 << 20  // the sum of all file sizes
	MaxEntries         = 512       // files and directories
	MaxManifestBytes   = 256 << 10 // manifest.json
	MaxSignatureBytes  = 16 << 10  // manifest.sig
	MaxPathBytes       = 255
	MaxPathDepth       = 16
	MaxChangeSummary   = 512 // runes
	MaxSecretRefs      = 64
	MaxWarnings        = 256
)

// Error is a refused bundle. Path names the bundle file or manifest field at
// fault; Detail says what is wrong without quoting any content.
type Error struct {
	Code   Code
	Path   string
	Detail string
}

func (e *Error) Error() string {
	if e.Path == "" {
		return fmt.Sprintf("bundle %s: %s", e.Code, e.Detail)
	}
	return fmt.Sprintf("bundle %s: %s: %s", e.Code, safePath(e.Path), e.Detail)
}

// CodeOf returns the bundle error code of err, or "" when err is not a
// bundle refusal.
func CodeOf(err error) Code {
	var bundleErr *Error
	if errors.As(err, &bundleErr) {
		return bundleErr.Code
	}
	return ""
}

func refuse(code Code, path, format string, args ...any) *Error {
	return &Error{Code: code, Path: path, Detail: fmt.Sprintf(format, args...)}
}

// safePath quotes a path taken from untrusted input when it holds anything
// other than the characters a valid bundle path may hold, and bounds it.
func safePath(path string) string {
	if len(path) > 128 {
		path = path[:128] + "..."
	}
	for i := 0; i < len(path); i++ {
		if !pathByte(path[i]) && path[i] != '[' && path[i] != ']' {
			return strconv.QuoteToASCII(path)
		}
	}
	return path
}
