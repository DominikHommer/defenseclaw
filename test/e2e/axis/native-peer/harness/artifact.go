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

// This entry admits only the four fixed contributor cases and these exact
// independently reviewed artifacts. It grants no production/provider authority.
// No CLI, environment, discovery or caller digest may replace these pins.
const fixedContributorReceiptSHA = "6af34ded1837e54d4909f782235613acd56232eafe0c60e2ebc61af5e7fd6ec6"

var liveRegistry = fixedContributorRegistry()

func fixedContributorRegistry() reviewedRegistry {
	no := false
	return reviewedRegistry{
		Reviewed:   true,
		ReceiptSHA: fixedContributorReceiptSHA,
		Receipt: artifactReceipt{
			Version:                 1,
			Scope:                   "fixed_linux_native_peer_offline_contributor_v1",
			Verified:                true,
			ExecutionPerformed:      &no,
			ProductionCertification: &no,
			Axis:                    "fb5fd5f0f9377c2ccb30d7e027a36373de0d037c",
			MXC:                     "fda29ac63bc306b7f97f3b86b4b63d44f7f40cf2",
			Bubblewrap:              "8e51677abd7e3338e4952370bf7d902e37d8cbb6",
			StaticClosureSHA:        "e6ce4df2d0118cfa0b1a26f554e4dcbd039d1fa3b77ad0d7628d5a3d1ba9665b",
			PayloadSourceSHA:        "40e6e1bccb635385cdab82e0969de893cb9e5c9d1aeb1499a2446623a9cca986",
			Builds: []buildIdentity{
				{Role: "peer_and_static_bwrap", Commit: "c914cb9a66d3e05a11d5eac4dcf4da7a8c0de139", Run: 39158759518, Artifact: 12148605722, ArchiveSHA: "68e5d232ed286cfbbbbcb212170cc6bf0aff4536cfbc98fb7129da1315a99085", ProvenanceSHA: "7d6fd05f40006e334921fa4efec58a033b3c2bbaf707d7be03b6322bc81ac59c"},
				{Role: "fixed_payload", Commit: "d07485c4cc8ecf8ab7db1a0121ac61a6a8b636f3", Run: 39134453264, Artifact: 12138953410, ArchiveSHA: "251779fc9462ca8f49014dceb6c86b633c86712b488d009a4a61e9095df9c401", ProvenanceSHA: "ae7d3700b3a8f20236cbef90e249f2c529103747e79d8c3473042b9fd5259a98"},
			},
			Images: []imageIdentity{
				{Role: "peer", Path: "images/peer", SHA: "274717415360304d4ff14096faa13cc98fcf7eaba5409dcd1c800350d4048665", Size: 2722752},
				{Role: "static_musl_bwrap", Path: "images/bwrap-static-musl", SHA: "b4d1a59426c6a52e9f9a0d57d03d620e4dfc1beef976201a3afc0c1b492ee37d", Size: 198584},
				{Role: "fixed_payload", Path: "images/fixed-payload", SHA: "d2d2ac02859541bbc03eaae305a8b1f833338a7783f8b31e57046e5dd4e4533c", Size: 1929342},
			},
		},
	}
}

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
