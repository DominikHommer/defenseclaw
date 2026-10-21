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

package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// The root trust anchor and credential commands leave one change event per
// change in the change spool; the gateway reports each as an audit event
// (config.trust_anchors.changed, config.secret.changed or
// config.secret.change_failed). The events below never hold a credential
// value or a hash of one.

// secretFailureCode is the errors[].code a failed secret command reports:
// the refusal's own code, invalid_arguments for a usage exit, state_invalid
// otherwise.
func secretFailureCode(err error, invalidExit int) string {
	var refusal *secretRefusal
	var view *managedViewRefusal
	switch {
	case errors.As(err, &refusal):
		return refusal.code
	case errors.As(err, &view):
		return view.code
	case commandExitCode(err) == invalidExit:
		return "invalid_arguments"
	default:
		return string(enterprisebundle.CodeStateInvalid)
	}
}

// secretChangeEvent is the change event of one secret set or remove. err
// is a failure (failureCode its code): a failure once the change was
// attempted (attempted, or the codes change_failed and restart_failed) is
// failed, any other a refusal. changed reports whether a successful run
// changed anything: a set of the stored value and a removal of an absent
// credential record nothing (ok false). A refused name is left out.
func secretChangeEvent(action, name string, changed bool, failureCode string, err error, attempted bool) (enterprisestatus.ChangeEvent, bool) {
	outcome := enterprisestatus.ChangeApplied
	switch {
	case err != nil && (attempted || failureCode == "change_failed" || failureCode == "restart_failed"):
		outcome = enterprisestatus.ChangeFailed
	case err != nil:
		outcome = enterprisestatus.ChangeRefused
	case !changed:
		return enterprisestatus.ChangeEvent{}, false
	}
	if action != enterprisestatus.ChangeActionSet && action != enterprisestatus.ChangeActionRemove {
		return enterprisestatus.ChangeEvent{}, false
	}
	ev, evErr := enterprisestatus.NewChangeEvent(enterprisestatus.ChangeKindSecret, action, outcome, failureCode)
	if evErr != nil {
		return enterprisestatus.ChangeEvent{}, false
	}
	if managed.ValidCredentialName(name) {
		ev.SecretName = name
	}
	return ev, true
}

// anchorsChangeEvent is the applied change event of an anchor install that
// replaced previous (nil when there was none or it was unreadable) with
// installed; ok is false for identical bytes.
func anchorsChangeEvent(previous, installed []byte) (enterprisestatus.ChangeEvent, bool) {
	if previous != nil && bytes.Equal(previous, installed) {
		return enterprisestatus.ChangeEvent{}, false
	}
	ev, err := enterprisestatus.NewChangeEvent(enterprisestatus.ChangeKindTrustAnchors, enterprisestatus.ChangeActionInstall,
		enterprisestatus.ChangeApplied, "")
	if err != nil {
		return enterprisestatus.ChangeEvent{}, false
	}
	ev.SHA256 = anchorsSHA256(installed)
	if previous != nil {
		ev.PreviousSHA256 = anchorsSHA256(previous)
	}
	ev.KeyIDsAdded, ev.KeyIDsRemoved = enterprisestatus.ChangedKeyIDs(anchorKeyIDs(previous), anchorKeyIDs(installed))
	return ev, true
}

// anchorsFailureEvent is the change event of a refused (nothing written) or
// failed anchor install; installed is the file still installed (nil: none).
func anchorsFailureEvent(code string, failed bool, installed []byte) (enterprisestatus.ChangeEvent, bool) {
	outcome := enterprisestatus.ChangeRefused
	if failed {
		outcome = enterprisestatus.ChangeFailed
	}
	ev, err := enterprisestatus.NewChangeEvent(enterprisestatus.ChangeKindTrustAnchors, enterprisestatus.ChangeActionInstall, outcome, code)
	if err != nil {
		return enterprisestatus.ChangeEvent{}, false
	}
	if installed != nil {
		ev.SHA256 = anchorsSHA256(installed)
	}
	return ev, true
}

func anchorsSHA256(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func anchorKeyIDs(raw []byte) []string {
	if raw == nil {
		return nil
	}
	anchors, err := enterprisebundle.DecodeAnchors(raw)
	if err != nil {
		return nil
	}
	ids := make([]string, 0, len(anchors.Keys))
	for _, key := range anchors.Keys {
		ids = append(ids, key.KeyID)
	}
	return ids
}
