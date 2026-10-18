// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/axis/namespaceinit"
	"golang.org/x/sys/unix"
)

func runDriver(ctx context.Context, opts options, admission wrapperAdmission, record map[string]any, retained *cleanupOwner) (resultErr error) {
	if err := admission.validate(); err != nil {
		return err
	}
	if retained == nil || runtime.GOARCH != "amd64" || os.Geteuid() == 0 || os.Getuid() != os.Geteuid() || os.Getgid() != os.Getegid() || filepath.Base(opts.receipt) != "REVIEWED-ARTIFACTS.json" {
		return errors.New("fixed unprivileged native Linux driver required")
	}
	root, err := openDirectory(filepath.Dir(opts.receipt))
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, root.Close()) }()
	if err := privateDirectory(root); err != nil {
		return err
	}
	receipt, _, err := boundedFile(root, "REVIEWED-ARTIFACTS.json", 64<<10, receiptSHA)
	if err != nil {
		return err
	}
	if err := receipt.Close(); err != nil {
		return err
	}
	source, data, err := boundedFile(root, "images/reviewed-wrapper", admission.Size, admission.SHA)
	if err != nil {
		return err
	}
	if err := source.Close(); err != nil {
		return err
	}
	if int64(len(data)) != admission.Size {
		return errors.New("fixed wrapper size differs")
	}
	wrapper, err := sealBytes(data, admission.SHA)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, wrapper.Close()) }()
	self, selfHash, err := sealedRunningImage()
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, self.Close()) }()
	record["driver_self_image_sha256"], record["reviewed_wrapper_sha256"] = selfHash, admission.SHA
	record["driver_stage"] = "host_fixture"
	fixture, err := newHostFixture()
	if fixture != nil {
		record["synthetic_fixture"], record["fixture_retained"] = fixture.path, true
		defer func() { resultErr = errors.Join(resultErr, fixture.close()) }()
	}
	if err != nil {
		return err
	}
	record["host_fixture_source_no_idmap_verified_before_clone"] = true
	record["host_fixture_parent_verified_before_clone"] = true
	grantRead, grantWrite, err := os.Pipe()
	if err != nil {
		return err
	}
	defer grantWrite.Close()
	readyRead, readyWrite, err := os.Pipe()
	if err != nil {
		_ = grantRead.Close()
		return err
	}
	defer readyRead.Close()
	var childFiles []*os.File
	for _, image := range []*os.File{self, wrapper, fixture.parent, fixture.root} {
		fd, err := unix.FcntlInt(image.Fd(), unix.F_DUPFD_CLOEXEC, 3)
		if err != nil {
			_ = grantRead.Close()
			_ = readyWrite.Close()
			for _, copy := range childFiles {
				_ = copy.Close()
			}
			return err
		}
		childFiles = append(childFiles, os.NewFile(uintptr(fd), "fixed-child-owned-image"))
	}
	proof, err := namespaceinit.Capture()
	if err != nil {
		_ = grantRead.Close()
		_ = readyWrite.Close()
		for _, file := range childFiles {
			_ = file.Close()
		}
		return err
	}
	childFiles = append([]*os.File{proof, grantRead, readyWrite}, childFiles...)
	stdout, stderr := &boundedCapture{}, &boundedCapture{}
	pidfd := -1
	command := &exec.Cmd{Path: "/proc/self/fd/6", Args: []string{"fixed-native-peer-outer-driver", "--owned-wrapper-bootstrap", "--receipt", opts.receipt, "--evidence", opts.evidence}, Env: []string{}, Dir: "/", ExtraFiles: childFiles, Stdout: stdout, Stderr: stderr,
		SysProcAttr: &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS | syscall.CLONE_NEWPID | syscall.CLONE_NEWNET | syscall.CLONE_NEWIPC | syscall.CLONE_NEWUTS,
			AmbientCaps: []uintptr{unix.CAP_SYS_ADMIN},
			UidMappings: []syscall.SysProcIDMap{{ContainerID: os.Getuid(), HostID: os.Getuid(), Size: 1}}, GidMappings: []syscall.SysProcIDMap{{ContainerID: os.Getgid(), HostID: os.Getgid(), Size: 1}}, GidMappingsEnableSetgroups: false, PidFD: &pidfd}}
	owner := &outerCustodian{pidfd: -1, done: make(chan struct{}), exit: -1}
	defer func() {
		cleanupErr := retained.close(owner)
		record["whole_wrapper_namespace_cleanup_observed"] = cleanupErr == nil
		record["pending_driver_cleanup"] = len(retained.pending)
		// Capture on failures too, after bounded native cleanup has been tried.
		// The capture locks protect readers that remain owned on a failed wait.
		output, stdoutOverflow := stdout.snapshot()
		diagnostics, stderrOverflow := stderr.snapshot()
		record["wrapper_stdout"], record["wrapper_stderr"] = string(output), string(diagnostics)
		record["stdout_truncated"], record["stderr_truncated"] = stdoutOverflow, stderrOverflow
		resultErr = errors.Join(resultErr, cleanupErr)
	}()
	record["driver_stage"] = "wrapper_namespace_start"
	record["wrapper_namespace_start_attempted"] = true
	if err := owner.start(ctx, command, &pidfd, childFiles); err != nil {
		return err
	}
	deadline := time.Now().Add(10 * time.Second)
	if outer, ok := ctx.Deadline(); ok && outer.Before(deadline) {
		deadline = outer
	}
	if readyRead.SetReadDeadline(deadline) != nil || grantWrite.SetWriteDeadline(deadline) != nil {
		return errors.New("fixed outer handshake deadline refused")
	}
	ready := make([]byte, len(workerReady))
	if _, err := io.ReadFull(readyRead, ready); err != nil || string(ready) != workerReady {
		return errors.New("fixed outer bootstrap readiness refused")
	}
	record["bootstrap_ready_observed"] = true
	if _, err := io.WriteString(grantWrite, workerGrant); err != nil {
		return err
	}
	if err := grantWrite.Close(); err != nil {
		return err
	}
	record["wrapper_exec_authorized"], record["execution_performed"] = true, nil
	select {
	case <-owner.done:
	case <-ctx.Done():
		return ctx.Err()
	}
	output, overflow := stdout.snapshot()
	diagnostics, stderrOverflow := stderr.snapshot()
	record["wrapper_exit_code"] = owner.exit
	var child map[string]any
	decoder := json.NewDecoder(bytes.NewReader(output))
	if overflow || stderrOverflow || len(diagnostics) != 0 || owner.waitErr != nil || owner.exit != 0 || decoder.Decode(&child) != nil || decoder.Decode(new(any)) != io.EOF {
		return errors.New("fixed wrapper output, exit or pipe bound failed")
	}
	record["wrapper_record"] = child
	if err := validateWrapperResult(child); err != nil {
		return err
	}
	record["wrapper_result_observed"], record["execution_performed"], record["passed"] = true, true, true
	return nil
}

func validateWrapperResult(child map[string]any) error {
	if child["scope"] != "fixed_linux_native_peer_offline_contributor_v1" || child["passed"] != true || child["execution_performed"] != true || child["production_certification"] != false || child["common_launch_gate_qualified"] != false || child["artifact_receipt_sha256"] != receiptSHA || child["outer_namespace_cleanup_observed"] != true || child["pending_outer_cleanup"] != float64(0) || child["pending_native_cleanup"] != float64(0) {
		return errors.New("fixed wrapper result or native cleanup differs")
	}
	for _, key := range []string{"outer_worker_ready_observed", "outer_worker_grant_sent", "owned_worker_result_observed", "host_outside_read_and_write_positive_controls", "original_canary_identities_and_bytes_preserved"} {
		if child[key] != true {
			return errors.New("fixed wrapper control or canary evidence missing")
		}
	}
	cases, ok := child["cases"].([]any)
	if !ok || len(cases) != 4 {
		return errors.New("fixed wrapper case inventory differs")
	}
	for index, mode := range []string{"argv", "stdio", "exit23", "boundaries"} {
		result, ok := cases[index].(map[string]any)
		if !ok || result["mode"] != mode || result["passed"] != true || result["prepared"] != true || result["started"] != true || result["fixed_payload_marker_observed"] != true || result["destroyed"] != true || result["native_cleanup_observed"] != true || result["exit_code"] != float64(23) || result["error"] != nil {
			return errors.New("fixed wrapper case assertion differs")
		}
	}
	return nil
}

func bootstrap(args []string, admission wrapperAdmission) (map[string]any, *cleanupOwner, error) {
	record := map[string]any{"scope": scope, "passed": false, "execution_performed": false, "production_certification": false}
	owner := &cleanupOwner{}
	if err := admission.validate(); err != nil {
		return record, owner, err
	}
	if os.Getpid() != 1 || os.Getppid() != 0 || os.Geteuid() == 0 || runtime.GOARCH != "amd64" || len(args) != 4 || args[0] != "--receipt" || args[2] != "--evidence" || len(args[1]) == 0 || len(args[1]) > 4096 || len(args[3]) == 0 || len(args[3]) > 4096 {
		return record, owner, errors.New("fixed owned bootstrap required")
	}
	// Setup installs PDEATHSIG, verifies owned fresh USER/MNT/PID namespaces,
	// mounts matching procfs and drops capabilities on every Go OS thread.
	// No READY or GRANT is processed before successful completion.
	if err := namespaceinit.Setup(); err != nil {
		return record, owner, err
	}
	grant, ready, self, wrapper := os.NewFile(4, "fixed-outer-grant"), os.NewFile(5, "fixed-outer-ready"), os.NewFile(6, "fixed-outer-self"), os.NewFile(7, "fixed-outer-wrapper")
	fixtureParent, fixtureRoot := os.NewFile(8, "fixed-host-fixture-parent"), os.NewFile(9, "fixed-host-fixture-root")
	defer fixtureParent.Close()
	defer fixtureRoot.Close()
	if err := checkInheritedFixture(fixtureParent, fixtureRoot); err != nil {
		return record, owner, err
	}
	defer grant.Close()
	defer ready.Close()
	defer self.Close()
	defer wrapper.Close()
	for index, file := range []*os.File{grant, ready} {
		var st unix.Stat_t
		flags, err := unix.FcntlInt(file.Fd(), unix.F_GETFL, 0)
		want := unix.O_RDONLY
		if index == 1 {
			want = unix.O_WRONLY
		}
		if err != nil || unix.Fstat(int(file.Fd()), &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFIFO || flags&unix.O_ACCMODE != want {
			return record, owner, errors.New("fixed private outer channel refused")
		}
	}
	for _, file := range []*os.File{self, wrapper} {
		seals, err := unix.FcntlInt(file.Fd(), unix.F_GET_SEALS, 0)
		if err != nil || seals != unix.F_SEAL_SEAL|unix.F_SEAL_GROW|unix.F_SEAL_SHRINK|unix.F_SEAL_WRITE {
			return record, owner, errors.New("fixed sealed outer image refused")
		}
	}
	current, err := os.Open("/proc/self/exe")
	if err != nil {
		return record, owner, err
	}
	var currentStat, selfStat unix.Stat_t
	identityErr := errors.Join(unix.Fstat(int(current.Fd()), &currentStat), unix.Fstat(int(self.Fd()), &selfStat), current.Close())
	if identityErr != nil || currentStat.Dev != selfStat.Dev || currentStat.Ino != selfStat.Ino {
		return record, owner, errors.New("fixed bootstrap self identity differs")
	}
	info, err := wrapper.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != admission.Size {
		return record, owner, errors.New("fixed wrapper size differs")
	}
	data := make([]byte, admission.Size)
	if _, err := wrapper.ReadAt(data, 0); err != nil || digestBytes(data) != admission.SHA || validateStaticELF(data) != nil {
		return record, owner, errors.New("fixed wrapper image differs")
	}
	if err := readyThenGrant(ready, grant); err != nil {
		return record, owner, err
	}
	if err := errors.Join(grant.Close(), ready.Close(), self.Close()); err != nil {
		return record, owner, err
	}
	if _, err := unix.FcntlInt(wrapper.Fd(), unix.F_SETFD, unix.FD_CLOEXEC); err != nil {
		return record, owner, err
	}
	// Literal proc-self FD names the still-held sealed executable; no host image
	// pathname is reopened. Exec has no PATH lookup or command-string parsing.
	err = syscall.Exec("/proc/self/fd/7", []string{"reviewed-native-peer-wrapper", "--run-fixed", "--receipt", args[1], "--evidence", args[3]}, []string{})
	runtime.KeepAlive(wrapper)
	return record, owner, err
}
