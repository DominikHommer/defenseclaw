// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/axis/bridgeowner"
	"github.com/defenseclaw/defenseclaw/internal/axis/bridgeprocess"
	"golang.org/x/sys/windows"
)

func (o *owner) networkControls(r *result) error {
	var err error
	o.tcp, err = net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return errors.New("network_control")
	}
	if o.tcp.SetDeadline(time.Now().Add(500*time.Millisecond)) != nil {
		return errors.New("network_control")
	}
	client, err := net.DialTimeout("tcp4", o.tcp.Addr().String(), 500*time.Millisecond)
	if err != nil || client == nil {
		if client != nil && client.Close() != nil {
			o.uncertain = true
		}
		return errors.New("network_control")
	}
	server, acceptErr := o.tcp.AcceptTCP()
	clientErr := client.Close()
	var serverErr error
	if server != nil {
		serverErr = server.Close()
	}
	if clientErr != nil || serverErr != nil {
		o.uncertain = true
	}
	if acceptErr != nil || server == nil || clientErr != nil || serverErr != nil {
		return errors.New("network_control")
	}
	r.TCPPositive = true
	o.udp, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return errors.New("network_control")
	}
	udp, err := net.DialUDP("udp4", nil, o.udp.LocalAddr().(*net.UDPAddr))
	if err != nil || udp == nil {
		if udp != nil && udp.Close() != nil {
			o.uncertain = true
		}
		return errors.New("network_control")
	}
	_, writeErr := udp.Write([]byte("FIXED_HOST_UDP_POSITIVE"))
	closeErr := udp.Close()
	if closeErr != nil {
		o.uncertain = true
	}
	if writeErr != nil || closeErr != nil || o.udp.SetReadDeadline(time.Now().Add(500*time.Millisecond)) != nil {
		return errors.New("network_control")
	}
	var raw [64]byte
	n, _, err := o.udp.ReadFromUDP(raw[:])
	if err != nil || string(raw[:n]) != "FIXED_HOST_UDP_POSITIVE" {
		return errors.New("network_control")
	}
	r.UDPPositive = true
	return nil
}

func (o *owner) networkAfter(r *result) error {
	if o.tcp.SetDeadline(time.Now().Add(100*time.Millisecond)) != nil {
		return errors.New("network_after")
	}
	connection, err := o.tcp.AcceptTCP()
	if connection != nil {
		if connection.Close() != nil {
			o.uncertain = true
		}
		return errors.New("network_after")
	}
	var timeout net.Error
	if !errors.As(err, &timeout) || !timeout.Timeout() {
		return errors.New("network_after")
	}
	r.TCPNoArrival = true
	if o.udp.SetReadDeadline(time.Now().Add(100*time.Millisecond)) != nil {
		return errors.New("network_after")
	}
	var raw [64]byte
	_, _, err = o.udp.ReadFromUDP(raw[:])
	if !errors.As(err, &timeout) || !timeout.Timeout() {
		return errors.New("network_after")
	}
	r.UDPNoArrival = true
	return nil
}

func run() (record result) {
	record.Stage = "closed_registry"
	if len(os.Args) != 2 || os.Args[1] != "--run-fixed" || !reviewed.valid() {
		return record
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel() // registered first: runs AFTER independent Session cleanup
	o := &owner{}
	liveOwner = o
	defer func() {
		o.close(&record)
		record.FixtureRetained = o.createdFixture
		record.Passed = record.Stage == "complete" && record.NativeCleanup && !record.FirstCleanupFailed && record.ImagesClosed && record.HandlesClosed
	}()
	record.Stage = "fixed_root"
	executable, err := os.Executable()
	if err != nil || filepath.Base(executable) != "windows-native-peer-harness.exe" {
		return record
	}
	base := filepath.Dir(executable)
	if filepath.Base(base) != "windows-native-peer-canary-06" {
		return record
	}
	if o.parents(executable) != nil {
		return record
	}
	basePin, err := o.open(base, true, false)
	if err != nil {
		return record
	}
	record.Stage = "receipt"
	receipt, err := o.open(filepath.Join(base, "REVIEWED-ARTIFACTS.json"), false, false)
	if err != nil {
		return record
	}
	raw, err := bytesAt(receipt, 64<<10)
	if err != nil || digest(raw) != reviewed.Receipt {
		return record
	}
	// Receipt bytes are exact source pins, reviewed independently; they never
	// supply executable paths, digests, arguments or environment at runtime.
	record.Stage = "artifact_images"
	peer, err := o.open(filepath.Join(base, "peer.exe"), false, false)
	if err != nil {
		return record
	}
	payload, err := o.open(filepath.Join(base, "payload.exe"), false, false)
	if err != nil {
		return record
	}
	for _, item := range []struct {
		file *os.File
		size int64
		hash string
	}{{peer, reviewed.PeerSize, reviewed.Peer}, {payload, reviewed.PayloadSize, reviewed.Payload}} {
		raw, err := bytesAt(item.file, 64<<20)
		if err != nil || int64(len(raw)) != item.size || digest(raw) != item.hash {
			return record
		}
	}
	record.Stage = "fresh_fixture"
	fixture := filepath.Join(base, "fixture")
	fixturePin, err := o.directory(fixture)
	if err != nil {
		return record
	}
	record.FixtureRetained = true
	// No recursive cleanup runs in this diagnostic harness. Public fixtures
	// stay for identity-checked review. Image.Close removes only its owned copy.
	work := filepath.Join(fixture, "work")
	cwd, err := o.directory(work)
	if err != nil {
		return record
	}
	for _, name := range []string{"workspace", "home", "tmp", `home\AppData`, `home\AppData\Roaming`, `home\AppData\Local`} {
		if _, err := o.directory(filepath.Join(work, name)); err != nil {
			return record
		}
	}
	root, err := os.OpenRoot(fixture)
	if root != nil {
		defer func() {
			if root.Close() != nil {
				o.uncertain = true
			}
		}()
	}
	if err != nil || root == nil {
		return record
	}
	check, err := o.keep(root.Open("."))
	if err != nil || !sameID(check, fixturePin) {
		return record
	}
	var sentinels []*os.File
	for _, name := range []string{`work\readonly.txt`, "outside.txt"} {
		file, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
		file, err = o.keep(file, err)
		if err != nil {
			return record
		}
		if _, err = file.Write([]byte(fixedSentinel)); err != nil {
			return record
		}
		if file.Sync() != nil {
			return record
		}
		// Both remain writable to this same user; no read-only file attribute
		// or deny-write sharing can masquerade as PSEC policy enforcement.
		if _, err = file.WriteAt([]byte(fixedSentinel), 0); err != nil {
			return record
		}
		sentinels = append(sentinels, file)
	}
	record.Stage = "owned_image_copies"
	for _, source := range []struct {
		file *os.File
		hash string
	}{{peer, reviewed.Peer}, {payload, reviewed.Payload}} {
		image, err := bridgeprocess.SealImageIn(ctx, source.file, "sha256:"+source.hash, fixturePin)
		if image != nil {
			o.images = append(o.images, image)
		}
		if err != nil {
			return record
		}
	}
	if len(o.images) != 2 {
		return record
	}
	var writable []*os.File
	for _, name := range []string{"workspace", "home", "tmp"} {
		file, err := o.open(filepath.Join(work, name), true, true)
		if err != nil {
			return record
		}
		writable = append(writable, file)
	}
	// Parents above CWD and sealed image directories remain held through native
	// cleanup. Image owns its own private subtree lease; basePin anchors the
	// entire fixed staging root even after independent source receipt checks.
	_ = basePin
	record.Stage = "network_positive_controls"
	if o.networkControls(&record) != nil {
		return record
	}
	system, err := windows.GetSystemWindowsDirectory()
	if err != nil {
		return record
	}
	plan := fixedPlan(work, system)
	if plan.Validate() != nil {
		return record
	}
	binding, err := bindingFor(plan)
	if err != nil {
		return record
	}
	record.Stage = "start"
	o.session, err = bridgeprocess.Start(ctx, binding, plan, bridgeprocess.Inputs{Peer: o.images[0], Payload: o.images[1], CWD: cwd, Read: []*os.File{cwd}, Write: writable}, bridgeowner.Limits{WriteTimeout: 500 * time.Millisecond, CleanupTimeout: 2 * time.Second})
	if err != nil || o.session == nil || o.session.Protocol == nil {
		writeFixedDiagnostic(os.Stderr, "start", err)
		return record
	}
	tcp := uint16(o.tcp.Addr().(*net.TCPAddr).Port)
	udp := uint16(o.udp.LocalAddr().(*net.UDPAddr).Port)
	record.Stage = "protocol"
	if err := exercise(ctx, o.session.Protocol, binding, plan, inputFrame(work, system, tcp, udp), &record); err != nil {
		writeFixedDiagnostic(os.Stderr, "protocol", err)
		return record
	}
	record.Stage = "host_observations"
	if o.networkAfter(&record) != nil {
		return record
	}
	for index, name := range []string{`work\readonly.txt`, "outside.txt"} {
		file, err := o.open(filepath.Join(fixture, name), false, true)
		if err != nil || !sameID(file, sentinels[index]) {
			return record
		}
		raw, err := bytesAt(file, 128)
		if err != nil || string(raw) != fixedSentinel {
			return record
		}
	}
	record.SentinelsUnchanged = true
	positive, err := o.open(filepath.Join(work, "workspace", "positive.txt"), false, true)
	if err != nil {
		return record
	}
	raw, err = bytesAt(positive, 128)
	if err != nil || string(raw) != fixedSentinel {
		return record
	}
	record.WorkspaceWrite = true
	record.Stage = "complete"
	return record
}
