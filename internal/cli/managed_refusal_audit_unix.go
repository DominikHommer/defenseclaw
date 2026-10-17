// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"net/http"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

var managedRefusalSocket = func() string {
	descriptor, err := managed.LoadRuntimeDescriptor(managedHostDescriptorPath())
	if err != nil || descriptor.HookSocket == "" {
		return ""
	}
	return descriptor.HookSocket
}

// reportManagedCommandRefusal is best effort: the gateway owns the audit store
// and attributes this request using the hook socket's kernel peer credentials.
// Only fixed command names reach the record; CLI arguments can contain secrets.
var reportManagedCommandRefusal = func(command, reason string) {
	socket := managedRefusalSocket()
	if socket == "" {
		return
	}
	request, err := json.Marshal(struct {
		Action  string `json:"action"`
		Target  string `json:"target"`
		Details string `json:"details"`
		Reason  string `json:"reason,omitempty"`
	}{Action: "action", Target: command, Details: "command=" + command, Reason: reason})
	if err != nil {
		return
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	response, err := client.Post("http://localhost/api/v1/managed/refusal", "application/json", bytes.NewReader(request))
	if err == nil {
		_ = response.Body.Close()
	}
}
