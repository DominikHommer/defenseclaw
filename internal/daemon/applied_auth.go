// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package daemon

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// AppliedAuthFileName is the record in which a gateway started by Daemon.Start
// keeps the credential configuration it applied.
const AppliedAuthFileName = "gateway-auth.json"

// AppliedAuth is the gateway credential configuration a running gateway
// applied when it started: the variable it reads its token from, the inline
// token of the config it loaded, and the data directory it runs on (the
// config's data_dir, whose .env it read its token from). A gateway reads
// them once (a change needs a restart), so they hold for the life of the
// process, also after config.yaml was edited into a state the gateway
// rejected or holds. A value that came from the process environment is
// never written.
type AppliedAuth struct {
	TokenEnv string `json:"token_env,omitempty"`
	Token    string `json:"token,omitempty"`
	DataDir  string `json:"data_dir,omitempty"`
}

type appliedAuthRecord struct {
	PID           int    `json:"pid"`
	StartIdentity string `json:"start_identity"`
	AppliedAuth
}

// RecordAppliedAuth writes auth, with this process's PID and kernel start
// identity, beside the PID record of the data directory that started it. Only
// a daemon child writes it: no PID record can name another process.
func RecordAppliedAuth(auth AppliedAuth) error {
	if !IsDaemonChild() {
		return nil
	}
	dataDir := strings.TrimSpace(os.Getenv(EnvDataDir))
	if dataDir == "" {
		return errors.New("daemon: " + EnvDataDir + " is empty for daemon child")
	}
	pid := os.Getpid()
	startIdentity, err := processStartIdentity(pid)
	if err != nil {
		return err
	}
	if startIdentity == "" {
		return errors.New("daemon: process start identity is unavailable")
	}
	data, err := json.Marshal(appliedAuthRecord{PID: pid, StartIdentity: startIdentity, AppliedAuth: auth})
	if err != nil {
		return err
	}
	return managed.WriteServiceRuntimeFile(managed.PinnedDeploymentMode(),
		filepath.Join(dataDir, AppliedAuthFileName), "gateway auth record", data)
}

// AppliedAuth returns the credential configuration gateway process pid
// recorded in this data directory: only a record that names pid and the
// kernel start identity pid has now, so a record the gateway before it left
// behind, or one naming a PID the OS gave to another process, is none.
func (d *Daemon) AppliedAuth(pid int) (AppliedAuth, bool) {
	if pid <= 0 {
		return AppliedAuth{}, false
	}
	data, err := readManagedIdentityFile(filepath.Join(d.dataDir, AppliedAuthFileName), maxProcessIdentityBytes)
	if err != nil {
		return AppliedAuth{}, false
	}
	var record appliedAuthRecord
	if json.Unmarshal(data, &record) != nil || record.PID != pid || record.StartIdentity == "" {
		return AppliedAuth{}, false
	}
	live, err := processStartIdentity(pid)
	if err != nil || live != record.StartIdentity {
		return AppliedAuth{}, false
	}
	return record.AppliedAuth, true
}
