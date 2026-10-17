// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package mcpasuser

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func testEntry() config.MCPServerEntry {
	return config.MCPServerEntry{
		Name: "notes", Command: "npx", Args: []string{"-y", ".", "--config", `.\srv.json`},
		Env: map[string]string{"NOTES_TOKEN": "x"}, Connector: "claudecode",
		Project: `C:\Users\dcw-std1\proj`, Home: `C:\Users\dcw-std1`,
	}
}

func testRequest(t *testing.T) Request {
	t.Helper()
	request, err := NewRequest("DefenseClawGateway", "s-1-5-21-1-2-3-1001", testEntry())
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func TestRequestArgRoundTripAndValidation(t *testing.T) {
	request := testRequest(t)
	if request.SID != "S-1-5-21-1-2-3-1001" {
		t.Fatalf("SID not normalized: %q", request.SID)
	}
	arg, err := EncodeRequestArg(request)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeRequestArg(arg)
	if err != nil || decoded != request {
		t.Fatalf("round trip: %+v, %v", decoded, err)
	}
	bad := []func(*Request){
		func(r *Request) { r.Version = 2 },
		func(r *Request) { r.GatewayService = `x\y` },
		func(r *Request) { r.SID = "S-1-5-18-x" },
		func(r *Request) { r.Connector = "codex" },
		func(r *Request) { r.Name = "" },
		func(r *Request) { r.Name = "a\nb" },
		func(r *Request) { r.Project = "C:\\p\x00" },
		func(r *Request) { r.Digest = "abc" },
	}
	for i, mutate := range bad {
		changed := request
		mutate(&changed)
		if _, err := EncodeRequestArg(changed); !errors.Is(err, ErrProtocol) {
			t.Fatalf("case %d: encoded an invalid request: %v", i, err)
		}
	}
	for _, arg := range []string{"", "!!", strings.Repeat("A", maxRequestArgBytes+1)} {
		if _, err := DecodeRequestArg(arg); !errors.Is(err, ErrProtocol) {
			t.Fatalf("decoded %q: %v", arg, err)
		}
	}
	// A request never carries a command: an extra field is refused.
	if _, err := decodeRequest([]byte(`{"version":1,"gateway_service":"G","sid":"S-1-5-21-1-2-3","connector":"kiro","name":"n","digest":"` +
		strings.Repeat("a", 64) + `","command":"cmd.exe"}`)); !errors.Is(err, ErrProtocol) {
		t.Fatalf("accepted a request with a command: %v", err)
	}
}

func TestDigestFollowsTheLaunchDefinition(t *testing.T) {
	base := testEntry()
	digest := Digest(base)
	same := base
	same.Home, same.Connector, same.Args, same.Env = `D:\elsewhere`, "kiro", append([]string(nil), base.Args...), map[string]string{"NOTES_TOKEN": "x"}
	if Digest(same) != digest {
		t.Fatal("digest depends on fields the launch does not use")
	}
	empty := base
	empty.Args, empty.Env = []string{}, map[string]string{}
	none := base
	none.Args, none.Env = nil, nil
	if Digest(empty) != Digest(none) {
		t.Fatal("empty and absent args or env digest differently")
	}
	for name, change := range map[string]func(*config.MCPServerEntry){
		"command": func(e *config.MCPServerEntry) { e.Command = "uvx" },
		"args":    func(e *config.MCPServerEntry) { e.Args = []string{"-y", "evil"} },
		"env":     func(e *config.MCPServerEntry) { e.Env = map[string]string{"NOTES_TOKEN": "y"} },
		"cwd":     func(e *config.MCPServerEntry) { e.CWD = "sub" },
		"project": func(e *config.MCPServerEntry) { e.Project = `C:\Users\dcw-std2\proj` },
		"name":    func(e *config.MCPServerEntry) { e.Name = "other" },
	} {
		changed := base
		change(&changed)
		if Digest(changed) == digest {
			t.Fatalf("a changed %s keeps the digest", name)
		}
	}
}

func TestFramesRejectOversizedPayloads(t *testing.T) {
	var buffer bytes.Buffer
	if err := WriteFrame(&buffer, FrameStdout, make([]byte, MaxFramePayload+1)); !errors.Is(err, ErrProtocol) {
		t.Fatalf("wrote an oversized frame: %v", err)
	}
	header := []byte{FrameStdout, 0xff, 0xff, 0xff, 0xff}
	if _, _, err := ReadFrame(bytes.NewReader(header)); !errors.Is(err, ErrProtocol) {
		t.Fatalf("read an oversized frame: %v", err)
	}
	if _, _, err := ReadFrame(bytes.NewReader([]byte{FrameStdout, 0, 0, 0, 4, 'a'})); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("short frame: %v", err)
	}
	if name, err := PipeName("DefenseClawGateway"); err != nil || name != `\\.\pipe\DefenseClaw-DefenseClawGateway-mcp-as-user` {
		t.Fatalf("pipe name %q, %v", name, err)
	}
	if _, err := PipeName(`..\x`); err == nil {
		t.Fatal("pipe name accepted a path")
	}
}

// echoSession is a server that answers each stdin line on stdout, writes a
// stderr line and exits with code once stdin closes.
type echoSession struct {
	stdinR, stdoutR, stderrR *io.PipeReader
	stdinW, stdoutW, stderrW *io.PipeWriter
	code                     int
	done                     chan struct{}
	killOnce                 sync.Once
	killed                   chan struct{}
}

func newEchoSession(code int, hang bool) *echoSession {
	s := &echoSession{code: code, done: make(chan struct{}), killed: make(chan struct{})}
	s.stdinR, s.stdinW = io.Pipe()
	s.stdoutR, s.stdoutW = io.Pipe()
	s.stderrR, s.stderrW = io.Pipe()
	go func() {
		defer close(s.done)
		_, _ = s.stderrW.Write([]byte("server starting\n"))
		scanner := bufio.NewScanner(s.stdinR)
		for scanner.Scan() {
			_, _ = s.stdoutW.Write([]byte("echo:" + scanner.Text() + "\n"))
		}
		if hang {
			<-s.killed
		}
		_ = s.stdoutW.Close()
		_ = s.stderrW.Close()
	}()
	return s
}

func (s *echoSession) Stdin() io.WriteCloser { return s.stdinW }
func (s *echoSession) Stdout() io.Reader     { return s.stdoutR }
func (s *echoSession) Stderr() io.Reader     { return s.stderrR }
func (s *echoSession) Wait() (int, error) {
	<-s.done
	select {
	case <-s.killed:
		return 1, nil
	default:
		return s.code, nil
	}
}
func (s *echoSession) Kill() {
	s.killOnce.Do(func() {
		close(s.killed)
		_ = s.stdinR.CloseWithError(io.ErrClosedPipe)
	})
}
func (s *echoSession) Close() { s.Kill() }

func TestRelayAndServeCarryStdioAndExitCode(t *testing.T) {
	relayConn, serverConn := net.Pipe()
	request := testRequest(t)
	var started Request
	served := make(chan error, 1)
	go func() {
		got, err := ServeConn(context.Background(), serverConn, func(_ context.Context, r Request) (Session, error) {
			started = r
			return newEchoSession(7, false), nil
		}, time.Minute)
		_ = serverConn.Close()
		if got != request {
			err = errors.Join(err, errors.New("served another request"))
		}
		served <- err
	}()
	var stdout, stderr bytes.Buffer
	code, err := RunRelay(relayConn, request, strings.NewReader("one\ntwo\n"), &stdout, &stderr)
	_ = relayConn.Close()
	if err != nil || code != 7 {
		t.Fatalf("relay: code %d, %v", code, err)
	}
	if started != request {
		t.Fatalf("starter got %+v", started)
	}
	if stdout.String() != "echo:one\necho:two\n" || stderr.String() != "server starting\n" {
		t.Fatalf("stdout %q stderr %q", stdout.String(), stderr.String())
	}
	if err := <-served; err != nil {
		t.Fatalf("serve: %v", err)
	}
}

func TestRelayReportsTheRefusal(t *testing.T) {
	relayConn, serverConn := net.Pipe()
	go func() {
		_, _ = ServeConn(context.Background(), serverConn, func(context.Context, Request) (Session, error) {
			return nil, errors.New("dcw-std1 is not signed in")
		}, time.Minute)
		_ = serverConn.Close()
	}()
	_, err := RunRelay(relayConn, testRequest(t), strings.NewReader(""), io.Discard, io.Discard)
	var refused *RefusedError
	if !errors.As(err, &refused) || refused.Reason != "dcw-std1 is not signed in" {
		t.Fatalf("refusal: %v", err)
	}
}

func TestServeKillsTheServerWhenTheRelayGoesAway(t *testing.T) {
	relayConn, serverConn := net.Pipe()
	session := newEchoSession(0, true)
	served := make(chan error, 1)
	go func() {
		_, err := ServeConn(context.Background(), serverConn, func(context.Context, Request) (Session, error) {
			return session, nil
		}, time.Minute)
		served <- err
	}()
	if err := writeJSONFrame(relayConn, FrameRequest, testRequest(t)); err != nil {
		t.Fatal(err)
	}
	if kind, _, err := ReadFrame(relayConn); err != nil || kind != FrameAnswer {
		t.Fatalf("answer %q, %v", kind, err)
	}
	go func() { _, _ = io.Copy(io.Discard, relayConn) }()
	_ = relayConn.Close()
	select {
	case <-session.killed:
	case <-time.After(stdinGrace + 5*time.Second):
		t.Fatal("the server outlived its relay")
	}
	_ = serverConn.Close()
	<-served
}

func TestServeKillsTheServerAtTheSessionLimit(t *testing.T) {
	relayConn, serverConn := net.Pipe()
	session := newEchoSession(0, true)
	go func() {
		_, _ = ServeConn(context.Background(), serverConn, func(context.Context, Request) (Session, error) {
			return session, nil
		}, 100*time.Millisecond)
		_ = serverConn.Close()
	}()
	stdinR, stdinW := io.Pipe()
	defer stdinW.Close()
	code, err := RunRelay(relayConn, testRequest(t), stdinR, io.Discard, io.Discard)
	if err != nil || code != 1 {
		t.Fatalf("limit: code %d, %v", code, err)
	}
	select {
	case <-session.killed:
	default:
		t.Fatal("the server was not killed at the limit")
	}
}

func TestServeRefusesAMalformedRequest(t *testing.T) {
	relayConn, serverConn := net.Pipe()
	go func() {
		_, _ = ServeConn(context.Background(), serverConn, func(context.Context, Request) (Session, error) {
			t.Error("started a server for a malformed request")
			return nil, errors.New("unreachable")
		}, time.Minute)
		_ = serverConn.Close()
	}()
	if err := WriteFrame(relayConn, FrameRequest, []byte(`{"version":1,"command":"cmd.exe"}`)); err != nil {
		t.Fatal(err)
	}
	kind, payload, err := ReadFrame(relayConn)
	if err != nil || kind != FrameAnswer || !strings.Contains(string(payload), `"ok":false`) {
		t.Fatalf("answer %q %s, %v", kind, payload, err)
	}
}
