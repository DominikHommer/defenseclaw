// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

// Fixed contributor harness. It has no production admission or launcher API.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/axis/bridgeowner"
	"github.com/defenseclaw/defenseclaw/internal/axis/bridgeprocess"
	"github.com/defenseclaw/defenseclaw/internal/axis/bridgeproto"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

const fixedInput = "fixed-private-stdin\x00\xff\n"
const fixedSentinel = "fixed-public-windows-peer-sentinel\n"
const fixedStdout = "FIXED_WINDOWS_PEER_CANARY_PASS\n"
const fixedStderr = "FIXED_WINDOWS_PEER_STDERR\n"
const outputBound = 64 << 10

// Remains closed until the exact peer artifact and local payload source/build
// have separate ROOT/Max reviews. Runtime callers cannot provide these pins.
var reviewed = artifactRegistry{}

type artifactRegistry struct {
	Enabled                bool
	Receipt, Peer, Payload string
	PeerSize, PayloadSize  int64
}

func (r artifactRegistry) valid() bool {
	if !r.Enabled || r.PeerSize < 64 || r.PeerSize > 64<<20 || r.PayloadSize < 64 || r.PayloadSize > 64<<20 {
		return false
	}
	for _, value := range []string{r.Receipt, r.Peer, r.Payload} {
		raw, err := hex.DecodeString(value)
		if err != nil || len(raw) != 32 || strings.ToLower(value) != value {
			return false
		}
	}
	return true
}

type result struct {
	Passed              bool   `json:"passed"`
	Stage               string `json:"stage"`
	Prepared            bool   `json:"prepared"`
	PeerStartedReply    bool   `json:"peer_started_reply_observed"`
	CanaryMarker        bool   `json:"fixed_canary_marker_observed"`
	Exit23              bool   `json:"exit23_observed"`
	Destroyed           bool   `json:"destroyed"`
	NativeCleanup       bool   `json:"native_cleanup_observed"`
	FirstCleanupFailed  bool   `json:"initial_cleanup_failed"`
	ImagesClosed        bool   `json:"image_views_and_copies_closed"`
	HandlesClosed       bool   `json:"harness_handles_closed"`
	TCPPositive         bool   `json:"host_tcp_positive_control"`
	UDPPositive         bool   `json:"host_udp_positive_control"`
	TCPNoArrival        bool   `json:"host_tcp_no_arrival_observed"`
	UDPNoArrival        bool   `json:"host_udp_no_arrival_observed"`
	SentinelsUnchanged  bool   `json:"sentinels_unchanged"`
	WorkspaceWrite      bool   `json:"workspace_write_observed"`
	FixtureRetained     bool   `json:"fresh_fixture_retained"`
	ProductionQualified bool   `json:"production_qualification"`
	CanaryFailure       string `json:"fixed_canary_failure,omitempty"`
}

type owner struct {
	files          []*os.File
	images         []*bridgeprocess.Image
	session        *bridgeprocess.Session
	tcp            *net.TCPListener
	udp            *net.UDPConn
	uncertain      bool
	createdFixture bool
}

// Reachable until this exact harness exits. The separately reviewed outer Job
// remains the final cleanup owner if retained Session cleanup cannot complete.
var liveOwner *owner

func (o *owner) keep(file *os.File, err error) (*os.File, error) {
	if file != nil {
		o.files = append(o.files, file)
	}
	return file, err
}

func (o *owner) close(record *result) {
	if o.session != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		err := o.session.Close(ctx)
		cancel()
		if err != nil {
			writeFixedDiagnostic(os.Stderr, "session_close", err)
			record.FirstCleanupFailed = true
			// Retry retained exact custody with a fresh bound; preserve failure.
			ctx, cancel = context.WithTimeout(context.Background(), 2*time.Second)
			err = o.session.StopAndWait(ctx)
			cancel()
			if err != nil {
				writeFixedDiagnostic(os.Stderr, "session_stop_and_wait", err)
			}
		}
		record.NativeCleanup = err == nil
		if err != nil {
			return
		} // keep all leases and reachable cleanup owner
	}
	for _, image := range slices.Backward(o.images) {
		if image.Close() != nil {
			o.uncertain = true
		}
	}
	record.ImagesClosed = !o.uncertain
	if o.tcp != nil && o.tcp.Close() != nil {
		o.uncertain = true
	}
	if o.udp != nil && o.udp.Close() != nil {
		o.uncertain = true
	}
	for index := len(o.files) - 1; index >= 0; index-- {
		file := o.files[index]
		o.files[index] = nil // no blind retry of an uncertain native close
		if file != nil && file.Close() != nil {
			o.uncertain = true
		}
	}
	record.HandlesClosed = !o.uncertain
}

// Diagnostic output is closed vocabulary and numeric Win32 codes only. Never
// format an error: even a trusted error may wrap an os.PathError or peer text.
func writeFixedDiagnostic(writer io.Writer, stage string, err error) {
	switch stage {
	case "start", "protocol", "session_close", "session_stop_and_wait":
	default:
		stage = "diagnostic_refused"
	}
	classes := []string{}
	for _, item := range []struct {
		name string
		err  error
	}{
		{"process_admission", bridgeprocess.ErrAdmission},
		{"process_unavailable", bridgeprocess.ErrUnavailable},
		{"owner_closed", bridgeowner.ErrClosed},
		{"owner_cleanup", bridgeowner.ErrCleanup},
		{"owner_backpressure", bridgeowner.ErrBackpressure},
		{"owner_peer_failure", bridgeowner.ErrPeer},
		{"protocol", bridgeproto.ErrProtocol},
		{"context_canceled", context.Canceled},
		{"context_deadline", context.DeadlineExceeded},
		{"file_closed", os.ErrClosed},
		{"file_deadline", os.ErrDeadlineExceeded},
	} {
		if errors.Is(err, item.err) {
			classes = append(classes, item.name)
		}
	}
	nativeStage := ""
	var staged interface{ NativeStartStage() string }
	if errors.As(err, &staged) {
		nativeStage = staged.NativeStartStage()
		switch nativeStage {
		case "allocated", "peer_duplicate", "peer_application", "payload_duplicate", "payload_metadata", "asset_cwd", "asset_read", "asset_write", "cwd_coverage", "private_pipe", "inheritable_capabilities", "bootstrap", "inheritable_stdio", "job_create", "job_limits", "protocol", "begin", "unclassified":
		default:
			nativeStage = "unclassified"
		}
	}
	operation, peerKind, peerFailure, preparationStage := "", "", "", ""
	var protocolFailure *fixedProtocolError
	if errors.As(err, &protocolFailure) {
		operation = closedProtocolOperation(protocolFailure.operation)
		peerKind = closedPeerKind(protocolFailure.kind)
		peerFailure = closedPeerFailure(protocolFailure.failure)
		if bridgeproto.ValidNativePreparationStage(protocolFailure.preparationStage) {
			preparationStage = protocolFailure.preparationStage
		}
	}
	cleanupStage := ""
	var cleanup interface{ NativeCleanupStage() string }
	if errors.As(err, &cleanup) {
		cleanupStage = cleanup.NativeCleanupStage()
		switch cleanupStage {
		case "entry", "completion", "startup_wait", "cleanup_slot", "root_wait", "job_query", "native_signal", "native_wait", "native_handles_close", "asset_close", "startup_copies_close", "preowner_pipes_close", "pipe_setup_close", "sticky_uncertainty", "unclassified":
		default:
			cleanupStage = "unclassified"
		}
	}
	var native syscall.Errno
	hasNative := errors.As(err, &native)
	raw, _ := json.Marshal(struct {
		Stage            string   `json:"fixed_diagnostic_stage"`
		NativeStage      string   `json:"native_start_stage,omitempty"`
		Operation        string   `json:"protocol_operation,omitempty"`
		PeerKind         string   `json:"peer_frame_kind,omitempty"`
		PeerFailure      string   `json:"peer_failure_code,omitempty"`
		PreparationStage string   `json:"native_preparation_stage,omitempty"`
		CleanupStage     string   `json:"native_cleanup_stage,omitempty"`
		Present          bool     `json:"error_present"`
		Classes          []string `json:"error_classes"`
		Win32            uint32   `json:"win32_error"`
		Unclassified     bool     `json:"unclassified_error"`
	}{stage, nativeStage, operation, peerKind, peerFailure, preparationStage, cleanupStage, err != nil, classes, uint32(native), err != nil && len(classes) == 0 && !hasNative})
	raw = append(raw, '\n')
	_, _ = writer.Write(raw) // already a failed measurement; outer stderr refuses.
}

func digest(raw []byte) string { sum := sha256.Sum256(raw); return hex.EncodeToString(sum[:]) }

func (o *owner) open(path string, directory, write bool) (*os.File, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, errors.New("fixed_open")
	}
	access, share, flags := uint32(windows.GENERIC_READ), uint32(windows.FILE_SHARE_READ), uint32(windows.FILE_FLAG_OPEN_REPARSE_POINT)
	if write {
		access |= windows.GENERIC_WRITE
		share |= windows.FILE_SHARE_WRITE
	}
	if directory {
		share |= windows.FILE_SHARE_WRITE
		flags |= windows.FILE_FLAG_BACKUP_SEMANTICS
	}
	handle, err := windows.CreateFile(name, access, share, nil, windows.OPEN_EXISTING, flags, 0)
	if handle == windows.InvalidHandle || handle == 0 {
		return nil, errors.New("fixed_open")
	}
	file := os.NewFile(uintptr(handle), "fixed-owned-object")
	o.files = append(o.files, file)
	var info windows.ByHandleFileInformation
	if err != nil || windows.GetFileInformationByHandle(handle, &info) != nil || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 ||
		(info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0) != directory || !directory && info.NumberOfLinks != 1 {
		return file, errors.New("fixed_metadata")
	}
	if directory && safefile.ValidatePrivateHandle(handle) != nil {
		// Nonprivate ancestors are pinned by parents(), not admitted as roots.
		return file, errors.New("fixed_private_directory")
	}
	return file, nil
}

func (o *owner) parents(path string) error {
	if _, err := winpath.ValidateFixedNTFSMountedPath(path); err != nil {
		return errors.New("fixed_volume")
	}
	var paths []string
	for parent := filepath.Dir(path); ; parent = filepath.Dir(parent) {
		paths = append(paths, parent)
		if filepath.Dir(parent) == parent {
			break
		}
	}
	slices.Reverse(paths)
	for _, path := range paths {
		name, err := windows.UTF16PtrFromString(path)
		if err != nil {
			return errors.New("ancestor")
		}
		h, err := windows.CreateFile(name, windows.FILE_LIST_DIRECTORY|windows.FILE_READ_ATTRIBUTES|windows.READ_CONTROL|windows.SYNCHRONIZE,
			windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
		if h == 0 || h == windows.InvalidHandle {
			return errors.New("ancestor")
		}
		file := os.NewFile(uintptr(h), "fixed-held-ancestor")
		o.files = append(o.files, file)
		var info windows.ByHandleFileInformation
		if err != nil || windows.GetFileInformationByHandle(h, &info) != nil || info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 || info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY == 0 {
			return errors.New("ancestor")
		}
	}
	return nil
}

func (o *owner) directory(path string) (*os.File, error) {
	created, err := safefile.CreatePrivateDirectory(path)
	if created && filepath.Base(path) == "fixture" {
		o.createdFixture = true
	}
	if err != nil || !created {
		return nil, errors.New("fresh_directory")
	}
	return o.open(path, true, false)
}

func bytesAt(file *os.File, maximum int64) ([]byte, error) {
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > maximum {
		return nil, errors.New("fixed_read")
	}
	raw := make([]byte, info.Size()+1)
	n, err := file.ReadAt(raw, 0)
	if err != io.EOF || int64(n) != info.Size() {
		return nil, errors.New("fixed_read")
	}
	return raw[:n], nil
}

func sameID(a, b *os.File) bool {
	type id struct {
		Volume uint64
		File   [16]byte
	}
	var x, y id
	return windows.GetFileInformationByHandleEx(windows.Handle(a.Fd()), windows.FileIdInfo, (*byte)(unsafe.Pointer(&x)), uint32(unsafe.Sizeof(x))) == nil &&
		windows.GetFileInformationByHandleEx(windows.Handle(b.Fd()), windows.FileIdInfo, (*byte)(unsafe.Pointer(&y)), uint32(unsafe.Sizeof(y))) == nil && x == y
}

func inputFrame(work, system string, tcp, udp uint16) []byte {
	raw := []byte("DCAXIS-WINCAN1\x00\x00")
	raw = binary.BigEndian.AppendUint16(raw, uint16(len(work)))
	raw = binary.BigEndian.AppendUint16(raw, uint16(len(system)))
	raw = binary.BigEndian.AppendUint16(raw, tcp)
	raw = binary.BigEndian.AppendUint16(raw, udp)
	raw = append(raw, work...)
	raw = append(raw, system...)
	return append(raw, fixedInput...)
}

func fixedPlan(work, system string) bridgeproto.Preparation {
	return bridgeproto.Preparation{Backend: "windows_psec", Argv: []string{filepath.Join(work, "fixed-canary.exe"), "--fixed-canary-v1", "", "a b", `a"b`, `tail\`, "λ-雪;$()`&|<>*?"},
		Environment: []bridgeproto.Variable{{Name: "HOME", Value: filepath.Join(work, "home")}, {Name: "USERPROFILE", Value: filepath.Join(work, "home")}, {Name: "APPDATA", Value: filepath.Join(work, "home", "AppData", "Roaming")}, {Name: "SYSTEMROOT", Value: system}, {Name: "LOCALAPPDATA", Value: filepath.Join(work, "home", "AppData", "Local")}, {Name: "TEMP", Value: filepath.Join(work, "tmp")}, {Name: "TMP", Value: filepath.Join(work, "tmp")}, {Name: "DC_AXIS_FIXED_PAYLOAD", Value: "fixed-windows-peer-v1"}},
		Workdir:     work, Filesystem: bridgeproto.Filesystem{Read: []string{work}, Write: []string{filepath.Join(work, "workspace"), filepath.Join(work, "home"), filepath.Join(work, "tmp")}, Deny: []string{}}, Offline: true, TimeoutMS: 5000, OutputLimit: outputBound}
}

func bindingFor(plan bridgeproto.Preparation) (bridgeproto.Binding, error) {
	preparation, err := bridgeproto.PreparationDigest(plan)
	if err != nil {
		return bridgeproto.Binding{}, err
	}
	h := "sha256:" + digest([]byte("fixed-windows-contributor-only\x00"+preparation+reviewed.Receipt))
	b := bridgeproto.Binding{SessionID: "fixed-windows-peer-canary-v1", SessionDigest: h, PolicyDigest: h, RuntimeDigest: "sha256:" + reviewed.Receipt, HarnessDigest: "sha256:" + reviewed.Payload, PreparationHash: preparation}
	return b, b.Validate()
}

type protocol interface {
	Send(context.Context, bridgeowner.Command) (uint64, error)
	Receive(context.Context) (bridgeproto.Frame, error)
}

// This private wrapper carries only source-fixed operation labels and already
// validated correlated peer enums. Its cause remains available to errors.Is/As;
// neither Error nor the diagnostic serializer formats private cause text.
type fixedProtocolError struct {
	operation        string
	cause            error
	kind             bridgeproto.Kind
	failure          string
	preparationStage string
}

func (err *fixedProtocolError) Error() string { return "fixed contributor protocol refused" }
func (err *fixedProtocolError) Unwrap() error { return err.cause }

func closedProtocolOperation(value string) string {
	switch value {
	case "prepare_send", "prepare_receive", "launch_send", "launch_receive", "input_send", "input_eof_send", "wait_send", "execution_receive", "execution_frame", "execution_kind", "destroy_send", "destroy_receive":
		return value
	default:
		return "unclassified"
	}
}

func closedPeerKind(value bridgeproto.Kind) string {
	switch value {
	case bridgeproto.Prepared, bridgeproto.Started, bridgeproto.Output, bridgeproto.Exited, bridgeproto.Destroyed, bridgeproto.Failed:
		return string(value)
	case "":
		return ""
	default:
		return "unclassified"
	}
}

func closedPeerFailure(value string) string {
	switch value {
	case "", "invalid_request", "unsupported", "preparation_failed", "launch_failed", "io_failed", "cleanup_failed":
		return value
	default:
		return "unclassified"
	}
}

func correlatedProtocolFailure(operation string, frame bridgeproto.Frame) error {
	failure, preparationStage := "", ""
	if frame.Kind == bridgeproto.Failed && frame.Failure != nil {
		failure = frame.Failure.Code
		if frame.Failure.NativeStage != nil {
			preparationStage = string(*frame.Failure.NativeStage)
		}
	}
	return &fixedProtocolError{operation: operation, cause: bridgeproto.ErrProtocol, kind: frame.Kind, failure: failure, preparationStage: preparationStage}
}

func reply(ctx context.Context, p protocol, b bridgeproto.Binding, request uint64, kind bridgeproto.Kind, operation string) error {
	f, err := p.Receive(ctx)
	if err != nil {
		return &fixedProtocolError{operation: operation, cause: err}
	}
	if f.Validate() != nil || f.Binding != b || f.Request != request {
		return &fixedProtocolError{operation: operation, cause: bridgeproto.ErrProtocol}
	}
	if f.Kind != kind {
		return correlatedProtocolFailure(operation, f)
	}
	return nil
}

func exercise(ctx context.Context, p protocol, b bridgeproto.Binding, plan bridgeproto.Preparation, input []byte, r *result) error {
	var stdout, stderr bytes.Buffer
	defer func() {
		for _, code := range []string{"input", "frame", "argv", "cwd", "environment_inventory", "stable_environment", "redirected_environment_observation", "readonly_read", "readonly_write_denial", "workspace_write", "outside_read_denial", "outside_write_denial", "tcp_denial", "udp_denial"} {
			if stderr.String() == "FIXED_WINDOWS_PEER_FAILURE "+code+"\n" {
				r.CanaryFailure = code
				break
			}
		}
	}()
	id, err := p.Send(ctx, bridgeowner.Command{Kind: bridgeproto.Prepare, Plan: &plan})
	if err != nil {
		return &fixedProtocolError{operation: "prepare_send", cause: err}
	}
	if err := reply(ctx, p, b, id, bridgeproto.Prepared, "prepare_receive"); err != nil {
		return err
	}
	r.Prepared = true
	id, err = p.Send(ctx, bridgeowner.Command{Kind: bridgeproto.Launch})
	if err != nil {
		return &fixedProtocolError{operation: "launch_send", cause: err}
	}
	if err := reply(ctx, p, b, id, bridgeproto.Started, "launch_receive"); err != nil {
		return err
	}
	r.PeerStartedReply = true
	if _, err = p.Send(ctx, bridgeowner.Command{Kind: bridgeproto.Input, Data: &bridgeproto.Data{Stream: "stdin", Bytes: input}}); err != nil {
		return &fixedProtocolError{operation: "input_send", cause: err}
	}
	if _, err = p.Send(ctx, bridgeowner.Command{Kind: bridgeproto.InputEOF}); err != nil {
		return &fixedProtocolError{operation: "input_eof_send", cause: err}
	}
	if _, err = p.Send(ctx, bridgeowner.Command{Kind: bridgeproto.Wait}); err != nil {
		return &fixedProtocolError{operation: "wait_send", cause: err}
	}
	exited := false
	for count := 0; count < 256; count++ {
		f, err := p.Receive(ctx)
		if err != nil {
			return &fixedProtocolError{operation: "execution_receive", cause: err}
		}
		if f.Validate() != nil || f.Binding != b || f.Request != id {
			return &fixedProtocolError{operation: "execution_frame", cause: bridgeproto.ErrProtocol}
		}
		switch f.Kind {
		case bridgeproto.Output:
			if stdout.Len()+stderr.Len()+len(f.Data.Bytes) > outputBound {
				return errors.New("output_bound")
			}
			if f.Data.Stream == "stdout" {
				stdout.Write(f.Data.Bytes)
			} else {
				stderr.Write(f.Data.Bytes)
			}
		case bridgeproto.Exited:
			if f.Result.ExitCode != 23 || f.Result.TimedOut || f.Result.Truncated {
				return errors.New("exit")
			}
			exited = true
			r.Exit23 = true
		default:
			return correlatedProtocolFailure("execution_kind", f)
		}
		if exited {
			break
		}
	}
	if !exited || stdout.String() != fixedStdout || stderr.String() != fixedStderr {
		return errors.New("fixed_streams")
	}
	r.CanaryMarker = true
	id, err = p.Send(ctx, bridgeowner.Command{Kind: bridgeproto.Destroy})
	if err != nil {
		return &fixedProtocolError{operation: "destroy_send", cause: err}
	}
	if err := reply(ctx, p, b, id, bridgeproto.Destroyed, "destroy_receive"); err != nil {
		return err
	}
	r.Destroyed = true
	return nil
}

func main() {
	r := run()
	// Only typed booleans and a source-fixed stage leave the private harness.
	raw, _ := json.Marshal(r)
	raw = append(raw, '\n')
	n, err := os.Stdout.Write(raw)
	if err != nil || n != len(raw) {
		os.Exit(1)
	}
	if !r.Passed {
		os.Exit(1)
	}
}
