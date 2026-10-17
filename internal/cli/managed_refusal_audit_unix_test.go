// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"encoding/json"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"
)

func TestManagedCommandRefusalUsesHookSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hook.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	type record struct {
		Action  string `json:"action"`
		Target  string `json:"target"`
		Details string `json:"details"`
		Reason  string `json:"reason"`
	}
	received := make(chan record, 1)
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/managed/refusal" || r.Method != http.MethodPost {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		var payload record
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Error(err)
		}
		received <- payload
		w.WriteHeader(http.StatusNoContent)
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	postManagedCommandRefusal(path, "enterprise linux ensure", "not_root")
	select {
	case got := <-received:
		if got != (record{Action: "action", Target: "enterprise linux ensure", Details: "command=enterprise linux ensure", Reason: "not_root"}) {
			t.Fatalf("socket payload = %+v", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no refusal reached the hook socket")
	}
}
