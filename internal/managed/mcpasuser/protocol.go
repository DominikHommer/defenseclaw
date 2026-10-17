// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Package mcpasuser is the narrow contract between the managed Windows
// gateway's MCP admission scan and the hook enumerator service, which starts
// an enrolled user's local MCP server as that user for the scan (#1164).
//
// The gateway runs as LocalSystem with a write-restricted token and never
// reads inside user profiles, so it cannot start a server whose project lives
// in a profile, and it must never run a user's server with its own rights.
// The scanner runtime therefore starts a relay (the gateway executable,
// "enterprise windows mcp-relay") in place of the server. The relay names the
// server by account, connector, name, project and definition digest; it never
// sends a command. The enumerator looks the server up in the record it
// published itself, starts exactly that definition with the user's token in a
// folder it checked as the user, and relays the server's stdio. The scanner
// itself keeps running as the gateway, so the user cannot change its verdict.
package mcpasuser

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"unicode"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

const (
	// ProtocolVersion is the request version this build speaks.
	ProtocolVersion = 1
	// MaxFramePayload bounds one frame.
	MaxFramePayload = 64 << 10
	// maxRequestArgBytes bounds the encoded relay request argument.
	maxRequestArgBytes = 8 << 10
	// maxAnswerError bounds the refusal text sent to the relay.
	maxAnswerError = 1024

	// GatewayServiceEnv names the gateway service in every managed Windows
	// service environment; the pipe name derives from it.
	GatewayServiceEnv = "DEFENSECLAW_WINDOWS_GATEWAY_SERVICE_NAME"
)

// Frame kinds. The relay sends one request, then stdin data and the end of
// stdin; the enumerator sends one answer, then the server's stdout and
// stderr and finally its exit code.
const (
	FrameRequest  byte = 'R'
	FrameAnswer   byte = 'A'
	FrameStdin    byte = 'i'
	FrameStdinEOF byte = 'c'
	FrameStdout   byte = 'o'
	FrameStderr   byte = 'e'
	FrameExit     byte = 'x'
)

// ErrProtocol marks a malformed frame or message.
var ErrProtocol = errors.New("mcp as-user protocol violation")

// Connectors whose servers the enumerator publishes, and so can start.
var publishedConnectors = map[string]bool{"claudecode": true, "kiro": true}

// PublishedConnector reports whether the enumerator publishes the MCP
// servers of connector, so a scan can start them as their user.
func PublishedConnector(connector string) bool {
	return publishedConnectors[connector]
}

var (
	serviceNamePattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,80}$`)
	sidPattern         = regexp.MustCompile(`^S-1-[0-9]+(-[0-9]+){1,14}$`)
	digestPattern      = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Request names one published server. It carries no command: the enumerator
// starts the definition it published for SID, never one the gateway sends.
type Request struct {
	Version        int    `json:"version"`
	GatewayService string `json:"gateway_service"`
	SID            string `json:"sid"`
	Connector      string `json:"connector"`
	Name           string `json:"name"`
	Project        string `json:"project,omitempty"`
	// Digest is Digest of the definition the gateway scans; a server whose
	// published definition changed since is not started.
	Digest string `json:"digest"`
}

// Validate checks the form of every field.
func (r Request) Validate() error {
	switch {
	case r.Version != ProtocolVersion:
		return fmt.Errorf("%w: unsupported request version %d", ErrProtocol, r.Version)
	case !serviceNamePattern.MatchString(r.GatewayService):
		return fmt.Errorf("%w: invalid gateway service name", ErrProtocol)
	case !sidPattern.MatchString(strings.ToUpper(r.SID)):
		return fmt.Errorf("%w: invalid account SID", ErrProtocol)
	case !publishedConnectors[r.Connector]:
		return fmt.Errorf("%w: connector %q has no published MCP servers", ErrProtocol, r.Connector)
	case !printable(r.Name, 256) || r.Name == "":
		return fmt.Errorf("%w: invalid server name", ErrProtocol)
	case !printable(r.Project, 4096):
		return fmt.Errorf("%w: invalid project folder", ErrProtocol)
	case !digestPattern.MatchString(r.Digest):
		return fmt.Errorf("%w: invalid definition digest", ErrProtocol)
	}
	return nil
}

func printable(value string, limit int) bool {
	if len(value) > limit {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

// NewRequest names entry, a server published for the account sid.
func NewRequest(gatewayService, sid string, entry config.MCPServerEntry) (Request, error) {
	request := Request{
		Version: ProtocolVersion, GatewayService: strings.TrimSpace(gatewayService),
		SID: strings.ToUpper(strings.TrimSpace(sid)), Connector: entry.Connector,
		Name: entry.Name, Project: entry.Project, Digest: Digest(entry),
	}
	return request, request.Validate()
}

// Digest identifies the launch-relevant part of a published definition: the
// same server read from the same record has the same digest.
func Digest(entry config.MCPServerEntry) string {
	fields := struct {
		Name    string            `json:"name"`
		Command string            `json:"command"`
		Args    []string          `json:"args"`
		Env     map[string]string `json:"env"`
		CWD     string            `json:"cwd"`
		URL     string            `json:"url"`
		Project string            `json:"project"`
	}{entry.Name, entry.Command, entry.Args, entry.Env, entry.CWD, entry.URL, entry.Project}
	if len(fields.Args) == 0 {
		fields.Args = nil
	}
	if len(fields.Env) == 0 {
		fields.Env = nil
	}
	data, _ := json.Marshal(fields)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// EncodeRequestArg encodes request as the relay's --request value.
func EncodeRequestArg(request Request) (string, error) {
	if err := request.Validate(); err != nil {
		return "", err
	}
	data, err := json.Marshal(request)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

// DecodeRequestArg decodes and validates a --request value.
func DecodeRequestArg(arg string) (Request, error) {
	if arg == "" || len(arg) > maxRequestArgBytes {
		return Request{}, fmt.Errorf("%w: missing or oversized request", ErrProtocol)
	}
	data, err := base64.RawURLEncoding.DecodeString(arg)
	if err != nil {
		return Request{}, fmt.Errorf("%w: request is not base64url", ErrProtocol)
	}
	return decodeRequest(data)
}

func decodeRequest(data []byte) (Request, error) {
	var request Request
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		return Request{}, fmt.Errorf("%w: request is not JSON: %v", ErrProtocol, err)
	}
	if decoder.More() {
		return Request{}, fmt.Errorf("%w: trailing data after the request", ErrProtocol)
	}
	request.SID = strings.ToUpper(request.SID)
	return request, request.Validate()
}

// RelayArgs are the gateway executable's arguments that run the relay.
func RelayArgs(requestArg string) []string {
	return []string{"enterprise", "windows", "mcp-relay", "--request", requestArg}
}

// PipeName is the enumerator's as-user pipe for the gateway service.
func PipeName(gatewayService string) (string, error) {
	if !serviceNamePattern.MatchString(gatewayService) {
		return "", fmt.Errorf("%w: invalid gateway service name", ErrProtocol)
	}
	return `\\.\pipe\DefenseClaw-` + gatewayService + `-mcp-as-user`, nil
}

// Answer is the enumerator's reply to a request.
type Answer struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// WriteFrame writes one frame: its kind, the big-endian payload length and
// the payload.
func WriteFrame(w io.Writer, kind byte, payload []byte) error {
	if len(payload) > MaxFramePayload {
		return fmt.Errorf("%w: frame of %d bytes", ErrProtocol, len(payload))
	}
	frame := make([]byte, 5+len(payload))
	frame[0] = kind
	binary.BigEndian.PutUint32(frame[1:5], uint32(len(payload)))
	copy(frame[5:], payload)
	_, err := w.Write(frame)
	return err
}

// ReadFrame reads one frame.
func ReadFrame(r io.Reader) (byte, []byte, error) {
	var header [5]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return 0, nil, err
	}
	size := binary.BigEndian.Uint32(header[1:5])
	if size > MaxFramePayload {
		return 0, nil, fmt.Errorf("%w: frame of %d bytes", ErrProtocol, size)
	}
	payload := make([]byte, size)
	if _, err := io.ReadFull(r, payload); err != nil {
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		return 0, nil, err
	}
	return header[0], payload, nil
}

func writeJSONFrame(w io.Writer, kind byte, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return WriteFrame(w, kind, data)
}

func exitPayload(code int) []byte {
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload, uint32(int32(code)))
	return payload
}

func truncate(text string, limit int) string {
	if len(text) <= limit {
		return text
	}
	return text[:limit] + "..."
}
