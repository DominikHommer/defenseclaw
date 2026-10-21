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
	"os"

	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// RecordChange writes one trust anchor or credential change event into the
// change spool (<etc>/bundles/change-events), which the gateway reports as
// an audit event. The folder is 0750 and each event 0640, owned by root
// with the service account's group, so the gateway reads them and no other
// account does. Only root records; the command's result stays the
// authoritative answer, so a caller treats a failure here as a warning.
func (e *Env) RecordChange(ev enterprisestatus.ChangeEvent) error {
	e.fillDefaults()
	if e.Geteuid() != 0 {
		return errors.New("only root records a change event")
	}
	owner := rootOwner()
	if e.Accounts != nil {
		if account, ok, err := e.Accounts.Lookup(context.Background(), e.Layout.ServiceUser); err == nil && ok {
			owner = fileOwner{UID: 0, GID: account.GID}
		}
	}
	return enterprisestatus.ChangeSpool{
		Dir:     e.P(enterprisestatus.ChangeEventsDir(e.Layout.ConfigDir)),
		Prepare: func(dir string) error { return e.ensureDir(dir, 0o750, owner) },
		Publish: func(path string) error {
			if err := os.Chmod(path, 0o640); err != nil {
				return err
			}
			return e.Lchown(path, owner.UID, owner.GID)
		},
	}.Write(ev)
}

// recordAnchorsChange records what InstallBundleAnchors did: an applied
// install with the new and the previous hash and the key ids it added and
// removed, or a refused or failed one with its code. A byte-identical
// install wrote nothing and records nothing; so does a caller that is not
// root.
func (e *Env) recordAnchorsChange(out *AnchorsInstall, err error) {
	if e.Geteuid() != 0 || out == nil {
		return
	}
	outcome, code := enterprisestatus.ChangeApplied, ""
	switch {
	case err != nil && out.attempted:
		outcome, code = enterprisestatus.ChangeFailed, string(enterprisebundle.CodeOf(err))
	case err != nil:
		outcome, code = enterprisestatus.ChangeRefused, string(enterprisebundle.CodeOf(err))
	case out.Result == AnchorsUnchanged:
		return
	}
	ev, evErr := enterprisestatus.NewChangeEvent(enterprisestatus.ChangeKindTrustAnchors, enterprisestatus.ChangeActionInstall, outcome, code)
	if evErr != nil {
		return
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
	_ = e.RecordChange(ev)
}
