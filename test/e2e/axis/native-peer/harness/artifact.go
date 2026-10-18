// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"regexp"
	"unicode/utf8"
)

const harnessScope = "fixed_linux_native_peer_offline_contributor_v1"

var errUnreviewed = errors.New("native peer contributor artifact registry has no independently reviewed live entry")

type buildIdentity struct {
	Role          string `json:"role"`
	Commit        string `json:"commit"`
	Run           uint64 `json:"run"`
	Artifact      uint64 `json:"artifact"`
	ArchiveSHA    string `json:"archive_sha256"`
	ProvenanceSHA string `json:"provenance_sha256"`
}

type imageIdentity struct {
	Role string `json:"role"`
	Path string `json:"path"`
	SHA  string `json:"sha256"`
	Size int64  `json:"size"`
}

// artifactReceipt is a restricted external review result, not runtime or
// policy authority. A caller cannot select its expected digest or contents.
type artifactReceipt struct {
	Version                 uint16          `json:"version"`
	Scope                   string          `json:"scope"`
	Verified                bool            `json:"verified"`
	ExecutionPerformed      *bool           `json:"execution_performed"`
	ProductionCertification *bool           `json:"production_certification"`
	Axis                    string          `json:"axis_commit"`
	MXC                     string          `json:"mxc_commit"`
	Bubblewrap              string          `json:"bubblewrap_commit"`
	StaticClosureSHA        string          `json:"static_closure_sha256"`
	PayloadSourceSHA        string          `json:"payload_source_sha256"`
	Builds                  []buildIdentity `json:"builds"`
	Images                  []imageIdentity `json:"images"`
}

type reviewedRegistry struct {
	Reviewed   bool
	ReceiptSHA string
	Receipt    artifactReceipt
}

// Intentionally closed until the new peer/static-musl/payload artifact set has
// independent source, lock, static closure and GitHub artifact review. Filling
// this entry is a separate reviewed source change, never a CLI/env override.
var liveRegistry = reviewedRegistry{Reviewed: false}

var hexDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)
var gitCommit = regexp.MustCompile(`^[0-9a-f]{40}$`)

func digestBytes(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func (r reviewedRegistry) validate() error {
	v := r.Receipt
	if !r.Reviewed || !hexDigest.MatchString(r.ReceiptSHA) || v.Version != 1 || v.Scope != harnessScope ||
		!v.Verified || v.ExecutionPerformed == nil || *v.ExecutionPerformed || v.ProductionCertification == nil || *v.ProductionCertification ||
		v.Axis != "fb5fd5f0f9377c2ccb30d7e027a36373de0d037c" || v.MXC != "fda29ac63bc306b7f97f3b86b4b63d44f7f40cf2" ||
		v.Bubblewrap != "8e51677abd7e3338e4952370bf7d902e37d8cbb6" ||
		!hexDigest.MatchString(v.StaticClosureSHA) || !hexDigest.MatchString(v.PayloadSourceSHA) || len(v.Builds) != 2 || len(v.Images) != 3 {
		return errUnreviewed
	}
	for i, role := range []string{"peer_and_static_bwrap", "fixed_payload"} {
		b := v.Builds[i]
		if b.Role != role || !gitCommit.MatchString(b.Commit) || b.Run == 0 || b.Artifact == 0 || !hexDigest.MatchString(b.ArchiveSHA) || !hexDigest.MatchString(b.ProvenanceSHA) {
			return errUnreviewed
		}
	}
	for i, role := range []string{"peer", "static_musl_bwrap", "fixed_payload"} {
		image := v.Images[i]
		if image.Role != role || image.Path != []string{"images/peer", "images/bwrap-static-musl", "images/fixed-payload"}[i] ||
			!hexDigest.MatchString(image.SHA) || image.Size < 64 || image.Size > 64<<20 {
			return errUnreviewed
		}
	}
	return nil
}

func admitReceipt(data []byte, registry reviewedRegistry) (artifactReceipt, error) {
	var value artifactReceipt
	if registry.validate() != nil {
		return value, errUnreviewed
	}
	if len(data) == 0 || len(data) > 64<<10 || !utf8.Valid(data) || bytes.IndexByte(data, 0) >= 0 || digestBytes(data) != registry.ReceiptSHA {
		return value, errors.New("reviewed contributor receipt digest or encoding differs")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&value) != nil {
		return value, errors.New("reviewed contributor receipt shape differs")
	}
	if decoder.Decode(new(any)) != io.EOF || !reflect.DeepEqual(value, registry.Receipt) {
		return value, errors.New("reviewed contributor receipt metadata differs")
	}
	return value, nil
}
