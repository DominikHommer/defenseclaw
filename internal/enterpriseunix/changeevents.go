// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"errors"
	"fmt"
	"os"
	"syscall"

	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// RecordChange writes one trust anchor or credential change event into the
// change spool (<etc>/bundles/change-events), which the gateway reports as
// an audit event. The folder is 0750 and each event 0640, owned by root
// with the service account's group, so the gateway reads them and no other
// account does. Only root records. A command calls ChangeSpoolReady before
// it changes anything and reports a failure here in its result
// (change_unrecorded).
func (e *Env) RecordChange(ev enterprisestatus.ChangeEvent) error {
	spool, err := e.changeSpool()
	if err != nil {
		return err
	}
	return spool.Write(ev)
}

// ChangeSpoolReady checks that the change spool can take the event of a
// change about to be made (enterprisestatus.ChangeSpool.Ready).
func (e *Env) ChangeSpoolReady() error {
	spool, err := e.changeSpool()
	if err != nil {
		return err
	}
	return spool.Ready()
}

func (e *Env) changeSpool() (enterprisestatus.ChangeSpool, error) {
	e.fillDefaults()
	if e.Geteuid() != 0 {
		return enterprisestatus.ChangeSpool{}, errors.New("only root records a change event")
	}
	dir := e.P(enterprisestatus.ChangeEventsDir(e.Layout.ConfigDir))
	owner, err := e.changeSpoolOwner(dir)
	if err != nil {
		return enterprisestatus.ChangeSpool{}, err
	}
	dataDir := e.P(e.Layout.DataDir)
	return enterprisestatus.ChangeSpool{
		Dir:      dir,
		Reported: func(id string) bool { return enterprisestatus.ChangeReported(dataDir, id) },
		Prepare:  func(dir string) error { return e.ensureDir(dir, 0o750, owner) },
		Publish: func(path string) error {
			if err := os.Chmod(path, 0o640); err != nil {
				return err
			}
			return e.Lchown(path, owner.UID, owner.GID)
		},
	}, nil
}

// changeSpoolOwner is root with the gateway service account's group. A
// failed lookup is an error: falling back to root's group would lock the
// gateway out of the spool. Before the account exists, an existing folder
// keeps its group (a new one gets root's; ensure sets the service group).
func (e *Env) changeSpoolOwner(dir string) (fileOwner, error) {
	account, ok, err := e.Accounts.Lookup(context.Background(), e.Layout.ServiceUser)
	if err != nil {
		return fileOwner{}, fmt.Errorf("look up the gateway service account %s: %w", e.Layout.ServiceUser, err)
	}
	if ok {
		return fileOwner{UID: 0, GID: account.GID}, nil
	}
	if info, err := os.Lstat(dir); err == nil && info.IsDir() {
		if st, isStat := info.Sys().(*syscall.Stat_t); isStat {
			return fileOwner{UID: 0, GID: int(st.Gid)}, nil
		}
	}
	return rootOwner(), nil
}

// recordAnchorsChange records what InstallBundleAnchors did: an applied
// install with the new and the previous hash and the key ids it added and
// removed, or a refused or failed one with its code. A byte-identical
// install wrote nothing and records nothing; so does a caller that is not
// root.
func (e *Env) recordAnchorsChange(out *AnchorsInstall, err error) error {
	if e.Geteuid() != 0 || out == nil {
		return nil
	}
	outcome, code := enterprisestatus.ChangeApplied, ""
	switch {
	case err != nil && out.attempted:
		outcome, code = enterprisestatus.ChangeFailed, string(enterprisebundle.CodeOf(err))
	case err != nil:
		outcome, code = enterprisestatus.ChangeRefused, string(enterprisebundle.CodeOf(err))
	case out.Result == AnchorsUnchanged:
		return nil
	}
	ev, evErr := enterprisestatus.NewChangeEvent(enterprisestatus.ChangeKindTrustAnchors, enterprisestatus.ChangeActionInstall, outcome, code)
	if evErr != nil {
		return evErr
	}
	ev.SHA256 = out.SHA256
	if err == nil {
		ev.PreviousSHA256 = out.PreviousSHA256
		var next []string
		if out.Anchors != nil {
			for _, key := range out.Anchors.Keys {
				next = append(next, key.KeyID)
			}
		}
		ev.KeyIDsAdded, ev.KeyIDsRemoved = enterprisestatus.ChangedKeyIDs(out.previousKeyIDs, next)
	}
	return e.RecordChange(ev)
}
