// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

// Fixed contributor-only outer custody for the compiled synthetic hook test.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/axis/namespaceinit"
	"github.com/defenseclaw/defenseclaw/test/e2e/axis/native-hook-canary/fixture"
	"golang.org/x/sys/unix"
)

const outputLimit = 4 << 20
const scope = "fixed_linux_contained_hook_outer_custody_v1"
const claudeTest = "TestContainedNativeHookClaudeUsesActualSharedEvaluator"
const allTest = "TestContainedNativeHookAllTwelveUseActualSharedEvaluator"
const peerSHA = "e2afdf64b0456817f469eb3a7acf3eceb43bc204187a194f3c5e8d54a68c3e3c"
const bwrapSHA = "b4d1a59426c6a52e9f9a0d57d03d620e4dfc1beef976201a3afc0c1b492ee37d"

// Fixed expected image bytes for the build-only wrapper. Hosted preparation
// remains closed until complete canary and wrapper artifacts are reviewed.
// These are source literals, never environment, CLI or receipt values.
const payloadSHA = "d1a812ce303b8eec3ba1dd9330ea5e338e1a413b41c2924ae060f68fc1144046"
const payloadSize int64 = 11247742
const testDriverSHA = "4b6f03634d6db339302a7c5b5aaddfc471419141a5b4c16c22b538e83a296808"
const testDriverSize int64 = 141533310

type imagePin struct {
	sha  string
	size int64
	mode uint32
}

func (p imagePin) valid() bool {
	return len(p.sha) == 64 && strings.Trim(p.sha, "0123456789abcdef") == "" && p.size >= 64 && p.size <= 256<<20 && (p.mode == 0400 || p.mode == 0500)
}

var peerPin = imagePin{peerSHA, 2760048, 0400}
var bwrapPin = imagePin{bwrapSHA, 198584, 0400}
var payloadPin = imagePin{payloadSHA, payloadSize, 0400}
var driverPin = imagePin{testDriverSHA, testDriverSize, 0500}
var retainedRoots []*cleanupOwner // exact failed owner stays reachable through final reporting
var cases = []string{"amp", "antigravity", "claudecode", "codex", "copilot", "cursor", "devin", "hermes", "kiro", "omnigent", "opencode", "openhands"}

func expectedCases(suite string) []string {
	if suite == "claude" {
		return []string{"claudecode"}
	}
	if suite == "all12" {
		return cases
	}
	return nil
}
func testName(suite string) string {
	if suite == "claude" {
		return claudeTest
	}
	if suite == "all12" {
		return allTest
	}
	return ""
}
func admitted() bool {
	return peerPin.valid() && bwrapPin.valid() && payloadPin.valid() && driverPin.valid()
}

func inspectResult(raw []byte, suite string) (map[string]any, error) {
	root := testName(suite)
	expected := expectedCases(suite)
	if root == "" || len(raw) == 0 || len(raw) > outputLimit {
		return nil, errors.New("fixed test output refused")
	}
	want := map[string]bool{root: true}
	if suite == "all12" {
		for _, name := range expected {
			want[root+"/"+name] = true
		}
	}
	runs, passes := map[string]bool{}, map[string]bool{}
	result, cleanup := map[string]map[string]any{}, map[string]bool{}
	packagePass := 0
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 4096), 512<<10)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "=== RUN   ") {
			name := strings.TrimPrefix(line, "=== RUN   ")
			if !want[name] || runs[name] {
				return nil, errors.New("unexpected or repeated fixed test")
			}
			runs[name] = true
		}
		if strings.HasPrefix(line, "--- PASS: ") {
			name, _, ok := strings.Cut(strings.TrimPrefix(line, "--- PASS: "), " ")
			if !ok || !want[name] || passes[name] {
				return nil, errors.New("unexpected or repeated fixed pass")
			}
			passes[name] = true
		}
		if line == "PASS" {
			packagePass++
		}
		if strings.Contains(line, "--- FAIL:") || strings.Contains(line, "--- SKIP:") || strings.HasPrefix(line, "FAIL") || strings.Contains(line, "panic:") {
			return nil, errors.New("fixed test failed, skipped or panicked")
		}
		if at := strings.Index(line, "CONTAINED_HOOK_RESULT "); at >= 0 {
			item, err := strictObject([]byte(line[at+len("CONTAINED_HOOK_RESULT "):]))
			if err != nil {
				return nil, errors.New("fixed case record malformed")
			}
			connector, ok := item["connector"].(string)
			if !ok || result[connector] != nil {
				return nil, errors.New("fixed case result inventory differs")
			}
			result[connector] = item
		}
		if at := strings.Index(line, "CONTAINED_HOOK_CLEANUP_RESULT connector="); at >= 0 {
			fields := strings.Fields(line[at:])
			if len(fields) != 4 || fields[0] != "CONTAINED_HOOK_CLEANUP_RESULT" || !strings.HasPrefix(fields[1], "connector=") || fields[2] != "resources_released=true" || fields[3] != "incomplete=false" {
				return nil, errors.New("fixed cleanup incomplete")
			}
			name := strings.TrimPrefix(fields[1], "connector=")
			if cleanup[name] {
				return nil, errors.New("fixed cleanup repeated")
			}
			cleanup[name] = true
		}
	}
	if scanner.Err() != nil || packagePass != 1 || len(runs) != len(want) || len(passes) != len(want) || len(result) != len(expected) || len(cleanup) != len(expected) {
		return nil, errors.New("fixed test pass, record or cleanup inventory differs")
	}
	for name := range want {
		if !runs[name] || !passes[name] {
			return nil, errors.New("fixed test missing")
		}
	}
	for _, name := range expected {
		if !cleanup[name] || verifyCase(result[name], name) != nil {
			return nil, errors.New("fixed case result or cleanup differs")
		}
	}
	return map[string]any{"selector": root, "connectors": expected, "case_results": result, "cleanup_observed": true, "test_passes": len(passes)}, nil
}

// The case record is emitted by a fixed Go test, but malformed or duplicate
// fields must not let a last-wins JSON decoder promote failure to success.
func strictObject(raw []byte) (map[string]any, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := uniqueJSONValue(decoder, 0); err != nil {
		return nil, err
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return nil, errors.New("fixed JSON trailing value refused")
	}
	var value map[string]any
	if err := json.Unmarshal(raw, &value); err != nil || value == nil {
		return nil, errors.New("fixed JSON object refused")
	}
	return value, nil
}

func uniqueJSONValue(decoder *json.Decoder, depth int) error {
	if depth > 32 {
		return errors.New("fixed JSON depth exceeded")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	switch token {
	case json.Delim('{'):
		seen := map[string]bool{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			key, ok := keyToken.(string)
			if err != nil || !ok || seen[key] {
				return errors.New("fixed JSON duplicate or invalid key")
			}
			seen[key] = true
			if err := uniqueJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("fixed JSON object end refused")
		}
	case json.Delim('['):
		for decoder.More() {
			if err := uniqueJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("fixed JSON array end refused")
		}
	case json.Delim('}'), json.Delim(']'):
		return errors.New("fixed JSON unexpected end")
	}
	return nil
}

func verifyCase(item map[string]any, name string) error {
	value, err := fixture.Lookup(name)
	if err != nil || item == nil || item["scope"] != "fixed synthetic contained hook exchange" || item["connector"] != name ||
		item["declared_schema_version"] != value.Version || item["native_surface"] != value.NativeSurface ||
		item["prepared"] != true || item["started"] != true || item["exited"] != true || item["destroyed"] != true ||
		item["native_and_endpoint_cleanup"] != true || item["binding_mint_attempted"] != true ||
		item["binding_issued"] != true || item["binding_revoked"] != true ||
		item["vendor_runtime_qualification"] != false || item["production_qualification"] != false ||
		item["actual_synthetic_payload"] != "sha256:"+payloadSHA {
		return errors.New("fixed case lifecycle differs")
	}
	binding, ok := item["binding_id"].(string)
	if !ok || binding == "" || len(binding) > 256 {
		return errors.New("fixed binding identity absent")
	}
	rows, ok := item["rows"].([]any)
	if !ok || len(rows) != 4 {
		return errors.New("fixed row inventory differs")
	}
	for i, phase := range []byte{'A', 'B', 'S', 'L'} {
		object, ok := rows[i].(map[string]any)
		if !ok || len(object) != 4 {
			return errors.New("fixed row schema differs")
		}
		for _, key := range []string{"phase", "hook_code", "hook_stdout", "hook_stderr"} {
			if _, present := object[key]; !present {
				return errors.New("fixed row field missing")
			}
		}
		raw, err := json.Marshal(object)
		if err != nil {
			return errors.New("fixed row encoding differs")
		}
		var row fixture.Row
		if json.Unmarshal(raw, &row) != nil || row.Phase != string(phase) ||
			len(row.Stdout) > 16384 || len(row.Stderr) > 16384 {
			return errors.New("fixed row phase or output differs")
		}
		if phase == 'S' && (row.Code != 0 || row.Stdout != "" || row.Stderr != "") {
			return errors.New("fixed silence phase differs")
		}
		if name == "claudecode" && phase != 'S' && fixture.ValidateClaudeRow(phase, row) != nil {
			return errors.New("fixed Claude strict response differs")
		}
	}
	decisions, ok := item["decisions"].([]any)
	if !ok || len(decisions) != 2 {
		return errors.New("fixed evaluator decision inventory differs")
	}
	for i, action := range []string{"allow", "block"} {
		decision, ok := decisions[i].(map[string]any)
		if !ok || decision["BindingID"] != binding || decision["SandboxName"] != "fixed-contained-hook-"+name ||
			decision["Connector"] != name || decision["Action"] != action || decision["WouldBlock"] != false {
			return errors.New("fixed actual evaluator decision differs")
		}
	}
	return nil
}

func execute(suite string) (record map[string]any, resultErr error) {
	record = map[string]any{"scope": scope, "suite": suite, "passed": false, "execution_performed": false, "production_qualification": false, "vendor_runtime_qualification": false}
	// Admit before every filesystem/image/native operation.
	if testName(suite) == "" || !admitted() || runtime.GOARCH != "amd64" || os.Geteuid() == 0 || os.Getuid() != os.Geteuid() || os.Getgid() != os.Getegid() {
		return record, errors.New("fixed live image/selector admission is closed")
	}
	// Register every nonnil partial owner before testing its error. A failed
	// source/failed memfd close must remain reachable through final reporting.
	retained := &cleanupOwner{}
	retainedRoots = append(retainedRoots, retained)
	defer func() {
		resultErr = errors.Join(resultErr, retained.retry())
		record["pending_outer_cleanup"] = len(retained.pending)
		record["pending_outer_resources"] = len(retained.heldResources)
		if resultErr != nil || len(retained.pending) != 0 || len(retained.heldResources) != 0 {
			record["passed"] = false
		}
	}()
	root, err := privateDirectory(nil, "live-inputs")
	if root != nil {
		defer func() { resultErr = errors.Join(resultErr, retained.releaseResource(root.Close)) }()
	}
	if err != nil {
		return record, err
	}
	inputs, err := privateDirectory(root, "native-hook-canary-inputs")
	if inputs != nil {
		defer func() { resultErr = errors.Join(resultErr, retained.releaseResource(inputs.Close)) }()
	}
	if err != nil {
		return record, err
	}
	peer, err := admittedImage(inputs, "peer", peerPin, retained)
	if peer != nil {
		defer func() { resultErr = errors.Join(resultErr, retained.releaseResource(peer.Close)) }()
	}
	if err != nil {
		return record, err
	}
	bwrap, err := admittedImage(inputs, "bubblewrap", bwrapPin, retained)
	if bwrap != nil {
		defer func() { resultErr = errors.Join(resultErr, retained.releaseResource(bwrap.Close)) }()
	}
	if err != nil {
		return record, err
	}
	payload, err := admittedImage(inputs, "payload", payloadPin, retained)
	if payload != nil {
		defer func() { resultErr = errors.Join(resultErr, retained.releaseResource(payload.Close)) }()
	}
	if err != nil {
		return record, err
	}
	driver, err := admittedImage(root, "fixed-contained-hook-driver.test", driverPin, retained)
	if driver != nil {
		defer func() { resultErr = errors.Join(resultErr, retained.releaseResource(driver.Close)) }()
	}
	if err != nil {
		return record, err
	}
	self, selfHash, err := sealedRunningImage(retained)
	if self != nil {
		defer func() { resultErr = errors.Join(resultErr, retained.releaseResource(self.Close)) }()
	}
	if err != nil {
		return record, err
	}
	record["self_sha256"] = selfHash
	record["driver_sha256"] = testDriverSHA
	record["payload_sha256"] = payloadSHA
	record["peer_sha256"] = peerSHA
	record["bubblewrap_sha256"] = bwrapSHA

	proof, err := namespaceinit.Capture()
	if proof != nil {
		defer func() { resultErr = errors.Join(resultErr, retained.releaseResource(proof.Close)) }()
	}
	if err != nil {
		return record, err
	}
	grantRead, grantWrite, err := os.Pipe()
	if grantRead != nil {
		defer func() {
			if grantRead != nil {
				resultErr = errors.Join(resultErr, retained.releaseResource(grantRead.Close))
			}
		}()
	}
	if grantWrite != nil {
		defer func() {
			if grantWrite != nil {
				resultErr = errors.Join(resultErr, retained.releaseResource(grantWrite.Close))
			}
		}()
	}
	if err != nil {
		return record, err
	}
	readyRead, readyWrite, err := os.Pipe()
	if readyRead != nil {
		defer func() { resultErr = errors.Join(resultErr, retained.releaseResource(readyRead.Close)) }()
	}
	if readyWrite != nil {
		defer func() {
			if readyWrite != nil {
				resultErr = errors.Join(resultErr, retained.releaseResource(readyWrite.Close))
			}
		}()
	}
	if err != nil {
		return record, err
	}
	originals := []*os.File{proof, grantRead, readyWrite, self, driver, root}
	children := make([]*os.File, 0, len(originals))
	for _, original := range originals {
		fd, e := unix.FcntlInt(original.Fd(), unix.F_DUPFD_CLOEXEC, 3)
		if e != nil {
			var closeErr error
			for _, child := range children {
				closeErr = errors.Join(closeErr, retained.releaseResource(child.Close))
			}
			return record, errors.Join(e, closeErr)
		}
		children = append(children, os.NewFile(uintptr(fd), "fixed-child-fd"))
	}
	stdout, stderr := &boundedCapture{}, &boundedCapture{}
	pidfd := -1
	command := &exec.Cmd{Path: "/proc/self/fd/6", Args: []string{"fixed-contained-hook-outer", "--owned-worker", suite}, Env: []string{}, Dir: "/", ExtraFiles: children, Stdout: stdout, Stderr: stderr,
		SysProcAttr: &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS | syscall.CLONE_NEWPID | syscall.CLONE_NEWNET | syscall.CLONE_NEWIPC | syscall.CLONE_NEWUTS,
			AmbientCaps: []uintptr{unix.CAP_SYS_ADMIN}, UidMappings: []syscall.SysProcIDMap{{ContainerID: os.Getuid(), HostID: os.Getuid(), Size: 1}}, GidMappings: []syscall.SysProcIDMap{{ContainerID: os.Getgid(), HostID: os.Getgid(), Size: 1}}, GidMappingsEnableSetgroups: false, PidFD: &pidfd}}
	owner := &outerCustodian{pidfd: -1, done: make(chan struct{}), exit: -1}
	defer func() {
		cleanupErr := retained.close(owner)
		record["whole_test_namespace_cleanup_observed"] = cleanupErr == nil
		record["pending_outer_cleanup"] = len(retained.pending)
		record["worker_exit_code"] = owner.exit
		output, tooLarge := stdout.snapshot()
		diagnostics, stderrTooLarge := stderr.snapshot()
		record["test_stdout"] = string(output)
		record["worker_stderr"] = string(diagnostics)
		record["stdout_exceeded_bound"] = tooLarge
		record["stderr_exceeded_bound"] = stderrTooLarge
		resultErr = errors.Join(resultErr, cleanupErr)
		if resultErr != nil {
			record["passed"] = false
		}
	}()
	lifetime := 3 * time.Minute
	if suite == "all12" {
		lifetime = 13 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), lifetime)
	defer cancel()
	record["stage"] = "namespace_start"
	if err := owner.start(ctx, command, &pidfd, children); err != nil {
		return record, err
	}
	grantReadCloseErr := retained.releaseResource(grantRead.Close)
	grantRead = nil
	readyWriteCloseErr := retained.releaseResource(readyWrite.Close)
	readyWrite = nil
	if err := errors.Join(grantReadCloseErr, readyWriteCloseErr); err != nil {
		return record, err
	}
	deadline := time.Now().Add(10 * time.Second)
	if err := readyRead.SetReadDeadline(deadline); err != nil {
		return record, err
	}
	if err := grantWrite.SetWriteDeadline(deadline); err != nil {
		return record, err
	}
	ready := make([]byte, len(workerReady))
	if _, err := io.ReadFull(readyRead, ready); err != nil || string(ready) != workerReady {
		return record, errors.New("fixed worker READY refused")
	}
	record["worker_ready_observed"] = true
	if _, err := io.WriteString(grantWrite, workerGrant); err != nil {
		return record, err
	}
	grantWriteCloseErr := retained.releaseResource(grantWrite.Close)
	grantWrite = nil
	if grantWriteCloseErr != nil {
		return record, grantWriteCloseErr
	}
	record["worker_grant_sent"] = true
	record["execution_performed"] = true
	select {
	case <-owner.done:
	case <-ctx.Done():
		return record, ctx.Err()
	}
	output, overflow := stdout.snapshot()
	diagnostics, stderrOverflow := stderr.snapshot()
	if overflow || stderrOverflow || len(diagnostics) != 0 || owner.waitErr != nil || owner.exit != 0 {
		return record, errors.New("fixed worker exit or output bound refused")
	}
	parsed, err := inspectResult(output, suite)
	if err != nil {
		return record, err
	}
	record["observed"] = parsed
	record["passed"] = true
	return record, nil
}

func bootstrap(suite string) error {
	if testName(suite) == "" || !admitted() || os.Getpid() != 1 || os.Getppid() != 0 || os.Geteuid() == 0 || runtime.GOARCH != "amd64" {
		return errors.New("fixed namespace worker refused")
	}
	if err := namespaceinit.Setup(); err != nil {
		return err
	}
	grant, ready, self, driver, root := os.NewFile(4, "fixed-grant"), os.NewFile(5, "fixed-ready"), os.NewFile(6, "fixed-self"), os.NewFile(7, "fixed-driver"), os.NewFile(8, "fixed-input-root")
	defer grant.Close()
	defer ready.Close()
	defer self.Close()
	defer driver.Close()
	defer root.Close()
	for index, file := range []*os.File{grant, ready} {
		var st unix.Stat_t
		flags, err := unix.FcntlInt(file.Fd(), unix.F_GETFL, 0)
		wanted := unix.O_RDONLY
		if index == 1 {
			wanted = unix.O_WRONLY
		}
		if err != nil || unix.Fstat(int(file.Fd()), &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFIFO || flags&unix.O_ACCMODE != wanted {
			return errors.New("fixed private handshake channel refused")
		}
	}
	for _, file := range []*os.File{self, driver} {
		seals, err := unix.FcntlInt(file.Fd(), unix.F_GET_SEALS, 0)
		if err != nil || seals != unix.F_SEAL_WRITE|unix.F_SEAL_GROW|unix.F_SEAL_SHRINK|unix.F_SEAL_SEAL {
			return errors.New("fixed sealed executable refused")
		}
	}
	current, err := os.Open("/proc/self/exe")
	if err != nil {
		return err
	}
	var running, held unix.Stat_t
	identityErr := errors.Join(unix.Fstat(int(current.Fd()), &running), unix.Fstat(int(self.Fd()), &held), current.Close())
	if identityErr != nil || running.Dev != held.Dev || running.Ino != held.Ino {
		return errors.New("fixed worker executable identity differs")
	}
	var st unix.Stat_t
	if unix.Fstat(int(root.Fd()), &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Mode&07777 != 0700 || st.Uid != uint32(os.Geteuid()) {
		return errors.New("fixed input root identity refused")
	}
	if err := unix.Fchdir(int(root.Fd())); err != nil {
		return err
	}
	if err := readyThenGrant(ready, grant); err != nil {
		return err
	}
	if err := errors.Join(grant.Close(), ready.Close(), self.Close(), root.Close()); err != nil {
		return err
	}
	if _, err := unix.FcntlInt(driver.Fd(), unix.F_SETFD, unix.FD_CLOEXEC); err != nil {
		return err
	}
	testTimeout := "2m"
	if suite == "all12" {
		testTimeout = "12m"
	}
	argv := []string{"fixed-contained-hook-test", "-test.v=true", "-test.count=1", "-test.timeout=" + testTimeout, "-test.run=^" + testName(suite) + "$"}
	// The exact sealed FD is executable only after READY/GRANT. The test's
	// own nested peer/bwrap custody remains below this PID namespace init.
	return syscall.Exec("/proc/self/fd/7", argv, []string{})
}

func main() {
	var record map[string]any
	var err error
	if len(os.Args) == 3 && os.Args[1] == "--owned-worker" {
		err = bootstrap(os.Args[2])
		if err != nil {
			os.Exit(1)
		}
		return
	}
	if len(os.Args) != 4 || os.Args[1] != "--run-fixed" || os.Args[2] != "--suite" || testName(os.Args[3]) == "" {
		record = map[string]any{"scope": scope, "passed": false, "execution_performed": false, "production_qualification": false}
		err = errors.New("fixed selector refused")
	} else {
		record, err = execute(os.Args[3])
	}
	if err != nil {
		record["error"] = "fixed_outer_admission_execution_or_cleanup_failed"
		record["passed"] = false
	}
	writeErr := json.NewEncoder(os.Stdout).Encode(record)
	runtime.KeepAlive(retainedRoots)
	if err != nil || writeErr != nil {
		os.Exit(1)
	}
}
