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
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// Trusted CAs for sandboxes (openshell.trusted_ca_bundle).
//
// Behind a TLS-inspecting proxy (a corporate secure web gateway) every
// provider certificate is re-signed by the organization's CA. The host
// trusts that CA; a sandbox does not: OpenShell builds the bundle its
// workload verifies with (SSL_CERT_FILE, REQUESTS_CA_BUNDLE, CURL_CA_BUNDLE,
// GIT_SSL_CAINFO) from the image's system store plus its own CA, and its
// upstream TLS from the same store. DefenseClaw never imports the host's
// store on its own: an operator names the CA file, and the overlay image
// build adds exactly those certificates to the image's system store
// (image.BuildSpec.TrustedCAs), so OpenShell's bundle holds them.
const (
	// MaxTrustedCABytes caps the trusted CA file.
	MaxTrustedCABytes = 1 << 20
	// MaxTrustedCAs caps the certificates in it.
	MaxTrustedCAs = 64
	// TrustedCAKey is the configuration key that names the file.
	TrustedCAKey = "openshell.trusted_ca_bundle"
	// SandboxTrustedCADir is where an overlay image keeps the trusted CAs,
	// one file per certificate, for update-ca-certificates. It exists only
	// in an image built with trusted CAs.
	SandboxTrustedCADir = "/usr/local/share/ca-certificates/defenseclaw"
	// SandboxSystemCABundle is the Debian and Ubuntu system bundle
	// update-ca-certificates writes, the first one OpenShell reads.
	SandboxSystemCABundle = "/etc/ssl/certs/ca-certificates.crt"
)

// TrustedCAs is a parsed trusted CA file: PEM is the normalized bundle
// (each certificate re-encoded once, in file order, duplicates dropped),
// which is what an image carries and its content hash covers.
type TrustedCAs struct {
	PEM   []byte
	Certs []*x509.Certificate
}

// Empty reports no trusted CAs.
func (t TrustedCAs) Empty() bool { return len(t.Certs) == 0 }

// Digest is "sha256:<hex>" of PEM ("" when empty).
func (t TrustedCAs) Digest() string {
	if t.Empty() {
		return ""
	}
	sum := sha256.Sum256(t.PEM)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Subjects names the certificates (their subject common names, else the
// whole subject).
func (t TrustedCAs) Subjects() []string {
	out := make([]string, 0, len(t.Certs))
	for _, c := range t.Certs {
		out = append(out, CertName(c))
	}
	return out
}

// Expired lists the certificates that are not valid at now.
func (t TrustedCAs) Expired(now time.Time) []string {
	var out []string
	for _, c := range t.Certs {
		if now.After(c.NotAfter) || now.Before(c.NotBefore) {
			out = append(out, CertName(c))
		}
	}
	return out
}

// Files splits PEM into one PEM file per certificate, the form the
// image's system store (update-ca-certificates) takes.
func (t TrustedCAs) Files() [][]byte {
	out := make([][]byte, 0, len(t.Certs))
	for _, c := range t.Certs {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
	}
	return out
}

// CertName is a certificate's subject common name, else its whole subject.
func CertName(c *x509.Certificate) string {
	if c == nil {
		return ""
	}
	if cn := strings.TrimSpace(c.Subject.CommonName); cn != "" {
		return cn
	}
	return c.Subject.String()
}

// ParseTrustedCAs parses a trusted CA bundle: PEM CERTIFICATE blocks, each
// a CA certificate (basic constraints CA:TRUE), at most MaxTrustedCAs. Text
// around the blocks (comments, `openssl x509 -text` output) is ignored. Any
// other block (a private key above all) or a certificate that does not
// parse refuses the whole file: a bundle that only half loads would leave
// sandboxes failing TLS with no word why.
func ParseTrustedCAs(data []byte) (TrustedCAs, error) {
	if len(data) > MaxTrustedCABytes {
		return TrustedCAs{}, fmt.Errorf("it is larger than %d bytes", MaxTrustedCABytes)
	}
	var out TrustedCAs
	seen := map[[32]byte]bool{}
	rest := data
	for n := 1; ; n++ {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return TrustedCAs{}, fmt.Errorf("block %d is a %q, not a CERTIFICATE (the file must hold CA certificates only)", n, block.Type)
		}
		if len(block.Headers) != 0 {
			return TrustedCAs{}, fmt.Errorf("certificate %d has PEM headers", n)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return TrustedCAs{}, fmt.Errorf("certificate %d does not parse: %v", n, err)
		}
		if !cert.BasicConstraintsValid || !cert.IsCA {
			return TrustedCAs{}, fmt.Errorf("certificate %d (%s) is not a CA certificate", n, CertName(cert))
		}
		sum := sha256.Sum256(cert.Raw)
		if seen[sum] {
			continue
		}
		seen[sum] = true
		if len(out.Certs) == MaxTrustedCAs {
			return TrustedCAs{}, fmt.Errorf("it holds more than %d certificates", MaxTrustedCAs)
		}
		out.Certs = append(out.Certs, cert)
		out.PEM = append(out.PEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})...)
	}
	if out.Empty() {
		return TrustedCAs{}, errors.New("it holds no PEM certificate (convert a DER file with `openssl x509 -inform der -in FILE -out FILE.pem`)")
	}
	return out, nil
}

// TrustedCAFileCheck is the managed trust check of an administrator's CA
// file (owner, modes and every ancestor); tests replace it.
var TrustedCAFileCheck = managed.ValidateTrustedFilePath

// LoadTrustedCAs reads and parses the file openshell.trusted_ca_bundle
// names. path is absolute or starts with "~/" (the caller's home). admin
// marks an administrator's configuration (managed_enterprise): the path
// must be absolute and the file administrator-owned, so no user can put a
// CA of their own into the organization's sandboxes. An empty path is no
// trusted CAs.
func LoadTrustedCAs(path string, admin bool) (TrustedCAs, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return TrustedCAs{}, nil
	}
	fail := func(err error) (TrustedCAs, error) {
		return TrustedCAs{}, &TrustedCAError{Path: path, Err: err}
	}
	if strings.HasPrefix(path, "~/") {
		if admin {
			return fail(errors.New("an administrator's configuration needs an absolute path"))
		}
		home, err := os.UserHomeDir()
		if err != nil || home == "" {
			return fail(errors.New("cannot resolve the home directory"))
		}
		path = filepath.Join(home, path[2:])
	}
	if !filepath.IsAbs(path) {
		return fail(errors.New("the path must be absolute or start with ~/"))
	}
	path = filepath.Clean(path)
	info, err := os.Stat(path)
	if err != nil {
		return fail(err)
	}
	if !info.Mode().IsRegular() {
		return fail(errors.New("it is not a regular file"))
	}
	if admin {
		if err := TrustedCAFileCheck(path, TrustedCAKey); err != nil {
			return fail(err)
		}
	}
	f, err := os.Open(path)
	if err != nil {
		return fail(err)
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, MaxTrustedCABytes+1))
	if err != nil {
		return fail(err)
	}
	cas, err := ParseTrustedCAs(data)
	if err != nil {
		return fail(err)
	}
	return cas, nil
}

// publicRootSources are where a host keeps the public roots of its
// distribution, without the CAs an administrator added: what a sandbox
// image's system store holds before openshell.trusted_ca_bundle. Debian
// and Ubuntu keep Mozilla's set as files, RHEL and Fedora as a p11-kit
// source (its PEM blocks), macOS as /etc/ssl/cert.pem (the keychain's
// added roots are not in it).
var publicRootSources = map[string][]string{
	"linux":  {"/usr/share/ca-certificates/mozilla", "/usr/share/pki/ca-trust-source/ca-bundle.trust.p11-kit"},
	"darwin": {"/etc/ssl/cert.pem"},
}

// PublicRoots reads the public roots of goos's distribution
// (publicRootSources) and names where they came from. A host without any
// is an error: the check that compares them with the host's trust cannot
// run there.
func PublicRoots(goos string) (*x509.CertPool, string, error) {
	for _, src := range publicRootSources[goos] {
		pool := x509.NewCertPool()
		info, err := os.Stat(src)
		if err != nil {
			continue
		}
		if info.IsDir() {
			matches, _ := filepath.Glob(filepath.Join(src, "*.crt"))
			for _, m := range matches {
				if data, err := os.ReadFile(m); err == nil {
					pool.AppendCertsFromPEM(data)
				}
			}
		} else if data, err := os.ReadFile(src); err == nil {
			pool.AppendCertsFromPEM(data)
		}
		if !pool.Equal(x509.NewCertPool()) {
			return pool, src, nil
		}
	}
	return nil, "", fmt.Errorf("no public root store of the distribution found on this %s computer", goos)
}

// TrustedCAError is a trusted CA file that cannot be used. Sandboxes fail
// closed on it: no image is built without the CAs the operator named.
type TrustedCAError struct {
	Path string
	Err  error
}

func (e *TrustedCAError) Error() string {
	return TrustedCAKey + " " + e.Path + ": " + e.Err.Error()
}

func (e *TrustedCAError) Unwrap() error { return e.Err }
