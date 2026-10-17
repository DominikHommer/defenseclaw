// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package setuppayload

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// payloadBindingDomain separates this digest from every other SHA-256 the
// build computes, and versions its layout.
const payloadBindingDomain = "defenseclaw-setup-payload-binding/v1"

// PayloadBinding returns the hex SHA-256 that binds a standalone Setup image
// to the payload it was built with: the distribution flavor and the SHA-256
// of every payload file, in byte order of the file names.
//
// packaging/windows/standalone/build-setup.sh computes it from the payload
// directory (windows-repro-manifest payload-binding) and links it into the
// outer Setup image. At run time the Setup computes it again from the
// manifest of the trailer it read and refuses a payload that does not
// match, so the payload it stages is the one its own image was built for,
// whatever file it read the trailer from.
//
// files maps a payload file name to its hex SHA-256 (either case).
func PayloadBinding(flavor string, files map[string]string) string {
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	digest := sha256.New()
	fmt.Fprintf(digest, "%s\nflavor=%s\n", payloadBindingDomain, flavor)
	for _, name := range names {
		fmt.Fprintf(digest, "%s %s\n", strings.ToLower(files[name]), name)
	}
	return hex.EncodeToString(digest.Sum(nil))
}
