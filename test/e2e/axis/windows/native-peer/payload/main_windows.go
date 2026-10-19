// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

// Fixed public contributor canary. No executable/script/path option exists.
package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"
)

const sentinel = "fixed-public-windows-peer-sentinel\n"
const input = "fixed-private-stdin\x00\xff\n"
const marker = "FIXED_WINDOWS_PEER_CANARY_PASS\n"
const diagnostic = "FIXED_WINDOWS_PEER_STDERR\n"

var literal = []string{"--fixed-canary-v1", "", "a b", `a"b`, `tail\`, "λ-雪;$()`&|<>*?"}

type frame struct {
	work, system string
	tcp, udp     uint16
}

func decode(raw []byte) (frame, error) {
	var value frame
	const magic = "DCAXIS-WINCAN1\x00\x00"
	if len(raw) < 24 || len(raw) > 16384 || string(raw[:16]) != magic {
		return value, errors.New("frame")
	}
	a, b := int(binary.BigEndian.Uint16(raw[16:18])), int(binary.BigEndian.Uint16(raw[18:20]))
	if a < 4 || b < 4 || a > 4096 || b > 4096 || len(raw) != 24+a+b+len(input) || string(raw[24+a+b:]) != input {
		return value, errors.New("frame")
	}
	value = frame{string(raw[24 : 24+a]), string(raw[24+a : 24+a+b]), binary.BigEndian.Uint16(raw[20:22]), binary.BigEndian.Uint16(raw[22:24])}
	for _, path := range []string{value.work, value.system} {
		if !utf8.ValidString(path) || !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) < 4 ||
			!((path[0] >= 'A' && path[0] <= 'Z') || (path[0] >= 'a' && path[0] <= 'z')) || path[1:3] != `:\` ||
			strings.ContainsAny(path, "\x00\r\n") || strings.ContainsRune(path[2:], ':') {
			return frame{}, errors.New("frame")
		}
	}
	if filepath.Base(value.work) != "work" || filepath.Base(filepath.Dir(value.work)) != "fixture" || value.tcp == 0 || value.udp == 0 {
		return frame{}, errors.New("frame")
	}
	return value, nil
}

func denied(err error) bool {
	return errors.Is(err, os.ErrPermission) || errors.Is(err, syscall.Errno(10013))
}

func check(value frame) string {
	wantArgs := append([]string{filepath.Join(value.work, "fixed-canary.exe")}, literal...)
	if !slices.Equal(os.Args, wantArgs) {
		return "argv"
	}
	cwd, err := os.Getwd()
	if err != nil || cwd != value.work {
		return "cwd"
	}
	stable := map[string]string{"HOME": filepath.Join(value.work, "home"), "USERPROFILE": filepath.Join(value.work, "home"), "APPDATA": filepath.Join(value.work, "home", "AppData", "Roaming"), "SYSTEMROOT": value.system, "DC_AXIS_FIXED_PAYLOAD": "fixed-windows-peer-v1"}
	allowed := map[string]bool{"HOME": true, "USERPROFILE": true, "APPDATA": true, "SYSTEMROOT": true, "DC_AXIS_FIXED_PAYLOAD": true, "TEMP": true, "TMP": true, "LOCALAPPDATA": true}
	seen := map[string]bool{}
	for _, entry := range os.Environ() {
		name, _, ok := strings.Cut(entry, "=")
		name = strings.ToUpper(name)
		if !ok || !allowed[name] || seen[name] {
			return "environment_inventory"
		}
		seen[name] = true
	}
	if len(seen) != 8 {
		return "environment_inventory"
	}
	for name, expected := range stable {
		if os.Getenv(name) != expected {
			return "stable_environment"
		}
	}
	// This is a limited observation, never a native-profile authority or exact
	// requested/realized equality claim. No redirected value is opened or logged.
	local, temp := os.Getenv("LOCALAPPDATA"), os.Getenv("TEMP")
	home := filepath.Join(value.work, "home") + `\`
	if !strings.HasPrefix(local, home) || !filepath.IsAbs(local) || filepath.Clean(local) != local ||
		!strings.HasPrefix(temp, home) || !filepath.IsAbs(temp) || filepath.Clean(temp) != temp || os.Getenv("TMP") != temp {
		return "redirected_environment_observation"
	}
	public, err := os.ReadFile(filepath.Join(value.work, "readonly.txt"))
	if err != nil || string(public) != sentinel {
		return "readonly_read"
	}
	if err := os.WriteFile(filepath.Join(value.work, "readonly.txt"), []byte("unexpected"), 0600); !denied(err) {
		return "readonly_write_denial"
	}
	if err := os.WriteFile(filepath.Join(value.work, "workspace", "positive.txt"), []byte(sentinel), 0600); err != nil {
		return "workspace_write"
	}
	outside := filepath.Join(filepath.Dir(value.work), "outside.txt")
	if _, err := os.ReadFile(outside); !denied(err) {
		return "outside_read_denial"
	}
	if err := os.WriteFile(outside, []byte("unexpected"), 0600); !denied(err) {
		return "outside_write_denial"
	}
	connection, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(value.tcp))), 500*time.Millisecond)
	if connection != nil {
		_ = connection.Close()
	}
	if !denied(err) {
		return "tcp_denial"
	}
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err == nil {
		_, writeErr := udp.WriteToUDP([]byte("FIXED_WINDOWS_PEER_UDP"), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(value.udp)})
		closeErr := udp.Close()
		if closeErr != nil || writeErr != nil && !denied(writeErr) {
			return "udp_denial"
		}
	} else if !denied(err) {
		return "udp_denial"
	}
	// Successful UDP send alone is not a denial proof. The host must observe
	// no arrival at its live, positively controlled endpoint before accepting.
	return ""
}

func run() int {
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, 16385))
	if err != nil || len(raw) > 16384 {
		_, _ = fmt.Fprint(os.Stderr, "FIXED_WINDOWS_PEER_FAILURE input\n")
		return 1
	}
	value, err := decode(raw)
	if err != nil {
		_, _ = fmt.Fprint(os.Stderr, "FIXED_WINDOWS_PEER_FAILURE frame\n")
		return 1
	}
	if code := check(value); code != "" {
		_, _ = fmt.Fprint(os.Stderr, "FIXED_WINDOWS_PEER_FAILURE "+code+"\n")
		return 1
	}
	_, a := io.Copy(os.Stdout, bytes.NewBufferString(marker))
	_, b := io.Copy(os.Stderr, bytes.NewBufferString(diagnostic))
	if a != nil || b != nil {
		return 1
	}
	return 23
}

func main() { os.Exit(run()) }
