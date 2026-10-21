// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package openshell

import (
	"fmt"
	"strconv"
	"strings"

	v1 "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1"
)

// Supported OpenShell releases. 0.1.0 broke every 0.0.x peer, and the
// project promises Stable-interface compatibility only within a minor line,
// so the window is one minor release wide and bumped deliberately.
const (
	// SupportedMin is the oldest OpenShell release DefenseClaw drives. It
	// stays at 0.1.1 while hosts that DefenseClaw 1.0.0 to 1.0.3 set up on
	// 0.1.1 or 0.1.2 can still be running sandboxes: raising it would cut
	// their daemon off from the gateway until OpenShell is upgraded.
	SupportedMin = "0.1.1"
	// SupportedBelow is the first release outside the window.
	SupportedBelow = "0.2.0"

	// InstallerVersion is the release the setup flow installs, and the one
	// it offers an older supported release an in-place upgrade to
	// (Installer.Upgrade, DoctorReport.OpenShellUpgradeAvailable).
	InstallerVersion = "0.1.5"
	// InstallerTag is InstallerVersion's upstream release tag.
	InstallerTag = "v" + InstallerVersion
	// InstallerURL is the tag-pinned upstream installer. Fetching it from a
	// tag rather than main keeps the bytes stable enough to pin a digest.
	InstallerURL = "https://raw.githubusercontent.com/NVIDIA/OpenShell/" + InstallerTag + "/install.sh"
	// InstallerSHA256 is the digest of InstallerURL. Setup refuses to run a
	// script that does not match it.
	InstallerSHA256 = "7bf6706741b8b59c1b61e0c47030f0a34fefba6cee3c74cd52638cbf7cdc3655"

	// installerUpgradeReason says why a host on an older supported release
	// is offered InstallerVersion (the doctor's CLI check). Review it with
	// InstallerVersion.
	installerUpgradeReason = "fixes a supervisor bug that can stall a sandbox's first connection (0.1.2), cuts the CPU an idle sandbox uses (0.1.2), " +
		"ships the MicroVM driver already signed for Apple's Hypervisor (0.1.3), flushes a MicroVM's disk before it stops (0.1.5) " +
		"and lets a sandbox in OpenShell's error state be stopped and started again (0.1.5)"

	// ErrorStopRelease is the first release whose gateway stops a sandbox
	// in its error state, so that it can be started again without deleting
	// it (NVIDIA/OpenShell#4231). Earlier ones refuse both.
	ErrorStopRelease = "0.1.5"

	// DefaultBaseImage is the digest-pinned NVIDIA community sandbox image
	// the DefenseClaw overlay is built on (multi-arch; ships node, uv, git
	// and gh, among others).
	DefaultBaseImage = "ghcr.io/nvidia/openshell-community/sandboxes/base@sha256:aeef1c63f00e2913ea002ccb3aaf925f338b5c5d70e63576f0d95c16a138044e"
	// NSSMyhostnameVersion is the libnss-myhostname release in
	// NSSMyhostnameDebs.
	NSSMyhostnameVersion = "255.4-1ubuntu8.17"

	// DefaultWorkspace is the OpenShell workspace (tenant) sandboxes are
	// created in when the operator does not choose one. Since 0.1.0 the
	// gateway no longer selects it implicitly.
	DefaultWorkspace = "default"
	// DefaultGatewayName is the registration the package-managed local
	// gateway installs.
	DefaultGatewayName = "openshell"
)

// PinnedDeb is one architecture's file of a pinned Debian package.
type PinnedDeb struct {
	// URLs serve the same file and are tried in order.
	URLs []string
	// SHA256 is the file's digest, as the Packages index of its release
	// publishes it; a build refuses any other file.
	SHA256 string
}

// NSSMyhostnameDebs are the libnss-myhostname NSSMyhostnameVersion packages
// of Ubuntu 24.04 (universe; the noble-security and noble-updates release
// when pinned), the release of DefaultBaseImage, by `dpkg
// --print-architecture`. The images built for OpenShell's MicroVM driver
// install the one of their architecture so that localhost resolves in a
// MicroVM (image.BuildSpec.MicroVM); the images for the docker driver do
// not. Each is fetched from Ubuntu's snapshot archive, which keeps every
// file it published, else from Launchpad's librarian, which keeps Ubuntu's
// builds: the archive's own pool drops a version once a newer one
// supersedes it. The package depends only on libc6 (>= 2.38) and libcap2
// (>= 1:2.10), which DefaultBaseImage carries on both architectures
// (2.39-0ubuntu8.7 and 1:2.66-5ubuntu2.4), so it installs with `dpkg -i`
// and no package index. Review it with DefaultBaseImage.
var NSSMyhostnameDebs = map[string]PinnedDeb{
	"amd64": {
		URLs: []string{
			"https://snapshot.ubuntu.com/ubuntu/20260929T000000Z/pool/universe/s/systemd/libnss-myhostname_255.4-1ubuntu8.17_amd64.deb",
			"https://launchpadlibrarian.net/871327436/libnss-myhostname_255.4-1ubuntu8.17_amd64.deb",
		},
		SHA256: "5014f50bd8a717629a626e799d2c453316e3985893625ec41d12ac1a82bfcd54",
	},
	"arm64": {
		URLs: []string{
			"https://snapshot.ubuntu.com/ubuntu/20260929T000000Z/pool/universe/s/systemd/libnss-myhostname_255.4-1ubuntu8.17_arm64.deb",
			"https://launchpadlibrarian.net/871327181/libnss-myhostname_255.4-1ubuntu8.17_arm64.deb",
		},
		SHA256: "5f39fb3175f068aad4ab0b39479fb0ad1265343982fdc19983f8dfa659e74465",
	},
}

// TarballBaseURL is where NVIDIA publishes the release tarballs and their
// checksum files: TarballBaseURL + "v<version>/<asset>".
const TarballBaseURL = "https://github.com/NVIDIA/OpenShell/releases/download/"

// TarballPins are the SHA-256 digests of NVIDIA's release tarballs, by
// release, that the managed-enterprise "setup" install mode installs
// (TarballInstaller). A tarball is installed only when its digest is
// listed in NVIDIA's own checksum file for the release and equals the
// digest pinned here, so the digests of a release are compiled in only
// after they were checked against the published ones. The macOS
// openshell-driver-vm of every pinned release ships signed with Apple's
// com.apple.security.hypervisor entitlement (since 0.1.3), so it is
// installed as shipped. Add a release with
// InstallerVersion; a release without an entry cannot be installed. 0.1.3
// stays listed for the managed hosts DefenseClaw 1.0.3 set up with
// enterprise.openshell.version: "0.1.3"; drop it once that release leaves
// the supported window (SupportedMin).
var TarballPins = map[string]map[string]string{
	"0.1.3": {
		"openshell-x86_64-unknown-linux-musl.tar.gz":           "ed08ea7874c47f22d6e5dcc4b27d9ef1ef5d2060f83035b35ff725d5160830a3",
		"openshell-aarch64-unknown-linux-musl.tar.gz":          "07687dacefc52bc73b01943f5b58f7a5082c1ceaa228461b9a2a78023b8057c0",
		"openshell-aarch64-apple-darwin.tar.gz":                "2eda3676aa85ff60551b403847090942e119c89f37c84d1635ac166c6b879826",
		"openshell-gateway-x86_64-unknown-linux-gnu.tar.gz":    "da8dce943fe01cce90243b2bf2587c71a243e4d641a4b616528829b681ced198",
		"openshell-gateway-aarch64-unknown-linux-gnu.tar.gz":   "801214322227f64f2d3faa6989daaa5e6cd9ef1ab768b5860496deeb1158c27b",
		"openshell-gateway-aarch64-apple-darwin.tar.gz":        "a0cff0699f4a608a644805dbbf898c42caa59856274ff3cc2cdd6b3af4bacabe",
		"openshell-driver-vm-x86_64-unknown-linux-gnu.tar.gz":  "22593640c6179eb87413ab099832fbd133d3a6a4979904d27679e7da6d80a0cb",
		"openshell-driver-vm-aarch64-unknown-linux-gnu.tar.gz": "4426ee0992989060eb5987ad7072feb3eb6aecf5a628ad0284c3d7ad5f39974b",
		"openshell-driver-vm-aarch64-apple-darwin.tar.gz":      "56e321f990741ca5585f5229e37c178f541b0c38029351fe59b72a36c1c750d4",
	},
	"0.1.5": {
		"openshell-x86_64-unknown-linux-musl.tar.gz":           "ca1ad6e6fbb4a6cd407e95763391b8ecff02912e7d9c467e7ca22696fe80af69",
		"openshell-aarch64-unknown-linux-musl.tar.gz":          "30c949b4ac07a9c8245c1248eb82e4eb241615134fcabf3c9bf30dec7d00addf",
		"openshell-aarch64-apple-darwin.tar.gz":                "48d6f4b4a222dc0a120ee4d6a677cb931bcc57f9ac54aefb101588f99c9c7642",
		"openshell-gateway-x86_64-unknown-linux-gnu.tar.gz":    "6ed6a6aff420c65250082cc1db48dc6271a6f5eec0e0068133566ffae4aa788b",
		"openshell-gateway-aarch64-unknown-linux-gnu.tar.gz":   "125f9f43b8d06da8280c78089904a6da2faa7c4cb03f82db3b31fc980cf6c62d",
		"openshell-gateway-aarch64-apple-darwin.tar.gz":        "8e6fd1b05999709a9042ec83fcd902e062507af3e817f28bcda181fb93b42e7a",
		"openshell-driver-vm-x86_64-unknown-linux-gnu.tar.gz":  "6465e39666276215a9fa05d27991e67c9c88267284b59aca95cb7dbb9d69cd41",
		"openshell-driver-vm-aarch64-unknown-linux-gnu.tar.gz": "fc49a0bebfda3075a996123c0fd252200e2987856da63fbd8e7f021f327e1e68",
		"openshell-driver-vm-aarch64-apple-darwin.tar.gz":      "125692d5e9b0183ceeadbc78b71de6007a3318dcc7ec9823e784b072ece2c4ac",
	},
}

// SandboxPolicy is the typed OpenShell sandbox policy the renderer produces
// and the client submits.
type SandboxPolicy = v1.SandboxPolicy

// Version is a parsed OpenShell release number. Pre-release and build
// suffixes are kept for display but do not take part in comparisons, so a
// 0.1.2-pre.3 build is treated as 0.1.2.
type Version struct {
	Major, Minor, Patch int
	Raw                 string
}

// ParseVersion accepts "0.1.1", "v0.1.1", "openshell 0.1.1" and
// "0.1.1-1" (the Debian revision the package reports).
func ParseVersion(s string) (Version, error) {
	raw := strings.TrimSpace(s)
	fields := strings.Fields(raw)
	if len(fields) == 0 {
		return Version{}, fmt.Errorf("openshell: empty version")
	}
	token := strings.TrimPrefix(fields[len(fields)-1], "v")
	if i := strings.IndexAny(token, "-+"); i >= 0 {
		token = token[:i]
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Version{}, fmt.Errorf("openshell: unrecognized version %q", raw)
	}
	var nums [3]int
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return Version{}, fmt.Errorf("openshell: unrecognized version %q", raw)
		}
		nums[i] = n
	}
	return Version{Major: nums[0], Minor: nums[1], Patch: nums[2], Raw: raw}, nil
}

// Compare returns -1, 0 or 1.
func (v Version) Compare(o Version) int {
	for _, d := range [3]int{v.Major - o.Major, v.Minor - o.Minor, v.Patch - o.Patch} {
		if d < 0 {
			return -1
		}
		if d > 0 {
			return 1
		}
	}
	return 0
}

func (v Version) String() string {
	return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
}

// breakingReleaseFloor is the upstream installer's BREAKING_RELEASE_VERSION:
// gateway state from earlier releases is incompatible, so the installer
// refuses to upgrade them without OPENSHELL_ACK_BREAKING_UPGRADE=1, while
// 0.0.37 and later upgrade in place.
const breakingReleaseFloor = "0.0.37"

// ErrUnsupportedVersion reports an OpenShell release outside the window.
// Its advice follows the upstream installer, as Installer does: releases
// before 0.0.37 need their runtime cleaned up first, later ones upgrade
// in place.
type ErrUnsupportedVersion struct {
	Found Version
}

func (e *ErrUnsupportedVersion) Error() string {
	switch {
	case e.Found.Compare(mustParse(breakingReleaseFloor)) < 0:
		return fmt.Sprintf("OpenShell %s predates %s, and %s cannot use its gateway state or sandboxes: back up what you need, "+
			"clean up with the old CLI (openshell sandbox delete --all && openshell gateway destroy), then install %s",
			e.Found, breakingReleaseFloor, InstallerVersion, InstallerVersion)
	case e.Found.Compare(mustParse(SupportedMin)) < 0:
		return fmt.Sprintf("OpenShell %s is older than %s; upgrade it in place to %s", e.Found, SupportedMin, InstallerVersion)
	}
	return fmt.Sprintf("OpenShell %s is not supported; DefenseClaw drives >=%s <%s", e.Found, SupportedMin, SupportedBelow)
}

// CheckSupported returns an *ErrUnsupportedVersion when v is outside the
// supported window.
func CheckSupported(v Version) error {
	if v.Compare(mustParse(SupportedMin)) < 0 || v.Compare(mustParse(SupportedBelow)) >= 0 {
		return &ErrUnsupportedVersion{Found: v}
	}
	return nil
}

func mustParse(s string) Version {
	v, err := ParseVersion(s)
	if err != nil {
		panic(err)
	}
	return v
}
