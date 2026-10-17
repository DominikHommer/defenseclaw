// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package mcpasuser

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

// Conn is one relay connection: the pipe on Windows, an in-memory pipe in
// tests.
type Conn interface {
	io.ReadWriteCloser
	SetReadDeadline(time.Time) error
}

// Session is a server process the enumerator started as its user.
type Session interface {
	Stdin() io.WriteCloser
	Stdout() io.Reader
	Stderr() io.Reader
	// Wait returns the server's exit code once it has exited.
	Wait() (int, error)
	// Kill ends the server and every process it started; it may be called
	// more than once.
	Kill()
	// Close kills the server and releases it.
	Close()
}

// Starter starts the server a request names, or says why it does not.
type Starter func(ctx context.Context, request Request) (Session, error)

// RefusedError is the enumerator's reason for not starting a server.
type RefusedError struct{ Reason string }

func (e *RefusedError) Error() string { return e.Reason }

const (
	// requestTimeout bounds the wait for the relay's request.
	requestTimeout = 15 * time.Second
	// SessionLimit bounds one scan session; the gateway's own MCP scan
	// bound is five minutes.
	SessionLimit = 5 * time.Minute
	// stdinGrace is how long a server whose relay went away may take to
	// exit before it is killed.
	stdinGrace = 5 * time.Second
	// closeGrace is how long the enumerator waits for the relay to read
	// the exit frame and hang up.
	closeGrace = 5 * time.Second
	// maxStderrBytes bounds the server stderr relayed for diagnostics.
	maxStderrBytes = 64 << 10
)

// RunRelay is the relay half over conn: it sends request, then copies stdin
// into stdin frames and the server's stdout and stderr frames out, and
// returns the server's exit code. A refusal is a *RefusedError.
func RunRelay(conn io.ReadWriter, request Request, stdin io.Reader, stdout, stderr io.Writer) (int, error) {
	if err := request.Validate(); err != nil {
		return 0, err
	}
	if err := writeJSONFrame(conn, FrameRequest, request); err != nil {
		return 0, fmt.Errorf("send the request to the hook enumerator: %w", err)
	}
	kind, payload, err := ReadFrame(conn)
	if err != nil {
		return 0, fmt.Errorf("read the hook enumerator answer: %w", err)
	}
	if kind != FrameAnswer {
		return 0, fmt.Errorf("%w: expected an answer, got frame %q", ErrProtocol, kind)
	}
	var answer Answer
	if err := json.Unmarshal(payload, &answer); err != nil {
		return 0, fmt.Errorf("%w: answer is not JSON", ErrProtocol)
	}
	if !answer.OK {
		reason := answer.Error
		if reason == "" {
			reason = "the hook enumerator did not start the server"
		}
		return 0, &RefusedError{Reason: reason}
	}
	var writeMu sync.Mutex
	go func() {
		buffer := make([]byte, 32<<10)
		for {
			n, readErr := stdin.Read(buffer)
			if n > 0 {
				writeMu.Lock()
				err := WriteFrame(conn, FrameStdin, buffer[:n])
				writeMu.Unlock()
				if err != nil {
					return
				}
			}
			if readErr != nil {
				writeMu.Lock()
				_ = WriteFrame(conn, FrameStdinEOF, nil)
				writeMu.Unlock()
				return
			}
		}
	}()
	for {
		kind, payload, err := ReadFrame(conn)
		if err != nil {
			return 1, fmt.Errorf("the hook enumerator connection closed before the server exited: %w", err)
		}
		switch kind {
		case FrameStdout:
			if _, err := stdout.Write(payload); err != nil {
				return 1, fmt.Errorf("write the server output: %w", err)
			}
		case FrameStderr:
			_, _ = stderr.Write(payload)
		case FrameExit:
			if len(payload) != 4 {
				return 1, fmt.Errorf("%w: malformed exit frame", ErrProtocol)
			}
			return int(int32(binary.BigEndian.Uint32(payload))), nil
		default:
			return 1, fmt.Errorf("%w: unexpected frame %q", ErrProtocol, kind)
		}
	}
}

// ServeConn is the enumerator half of one connection: it reads the request,
// starts its server with start, relays the server's stdio until it exits
// and sends its exit code. limit bounds the whole session; the server is
// killed when it ends, when ctx ends, or shortly after the relay goes away.
func ServeConn(ctx context.Context, conn Conn, start Starter, limit time.Duration) (Request, error) {
	_ = conn.SetReadDeadline(time.Now().Add(requestTimeout))
	kind, payload, err := ReadFrame(conn)
	if err != nil {
		return Request{}, fmt.Errorf("read the relay request: %w", err)
	}
	if kind != FrameRequest {
		return Request{}, fmt.Errorf("%w: expected a request, got frame %q", ErrProtocol, kind)
	}
	request, err := decodeRequest(payload)
	if err != nil {
		_ = writeJSONFrame(conn, FrameAnswer, Answer{Error: truncate(err.Error(), maxAnswerError)})
		return Request{}, err
	}
	session, err := start(ctx, request)
	if err != nil {
		_ = writeJSONFrame(conn, FrameAnswer, Answer{Error: truncate(err.Error(), maxAnswerError)})
		return request, err
	}
	defer session.Close()
	_ = conn.SetReadDeadline(time.Time{})

	var writeMu sync.Mutex
	write := func(kind byte, payload []byte) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		return WriteFrame(conn, kind, payload)
	}
	if err := write(FrameAnswer, mustJSON(Answer{OK: true})); err != nil {
		return request, err
	}

	var pumps sync.WaitGroup
	pump := func(source io.Reader, kind byte, cap int) {
		defer pumps.Done()
		buffer := make([]byte, 32<<10)
		sent := 0
		for {
			n, readErr := source.Read(buffer)
			if n > 0 {
				chunk := buffer[:n]
				if cap > 0 {
					if sent >= cap {
						chunk = nil
					} else if sent+n > cap {
						chunk = chunk[:cap-sent]
					}
				}
				sent += len(chunk)
				if len(chunk) > 0 {
					if err := write(kind, chunk); err != nil {
						// The relay is gone; nothing reads the server.
						session.Kill()
					}
				}
			}
			if readErr != nil {
				return
			}
		}
	}
	pumps.Add(2)
	go pump(session.Stdout(), FrameStdout, 0)
	go pump(session.Stderr(), FrameStderr, maxStderrBytes)

	relayGone := make(chan struct{})
	go func() {
		defer close(relayGone)
		stdin := session.Stdin()
		defer stdin.Close()
		for {
			kind, payload, err := ReadFrame(conn)
			if err != nil {
				return
			}
			switch kind {
			case FrameStdin:
				// A server that closed its stdin keeps running; the relay
				// learns its end from the exit frame.
				_, _ = stdin.Write(payload)
			case FrameStdinEOF:
				_ = stdin.Close()
			default:
				return
			}
		}
	}()

	exited := make(chan struct{})
	go func() {
		timer := time.NewTimer(limit)
		defer timer.Stop()
		select {
		case <-exited:
		case <-ctx.Done():
			session.Kill()
		case <-timer.C:
			session.Kill()
		case <-relayGone:
			select {
			case <-exited:
			case <-time.After(stdinGrace):
				session.Kill()
			}
		}
	}()

	code, waitErr := session.Wait()
	close(exited)
	// The server is gone; end whatever it left running so its output
	// pipes close.
	session.Kill()
	pumps.Wait()
	if err := write(FrameExit, exitPayload(code)); err != nil {
		return request, errors.Join(waitErr, err)
	}
	select {
	case <-relayGone:
	case <-time.After(closeGrace):
	}
	return request, waitErr
}

func mustJSON(value any) []byte {
	data, _ := json.Marshal(value)
	return data
}
