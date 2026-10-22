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

package connector

// until 1.1: DefenseClaw 1.0.4 removed the OpenHands and OmniGent connectors
// (#1182). A host that an older release set up still has their hooks or
// policy module, which point at a gateway route that no longer exists. These
// teardown-only connectors undo what that release wrote, so the upgrade
// (gateway boot), `defenseclaw uninstall` and native Windows Setup leave the
// agent working without DefenseClaw. Delete this file in 1.1.
//
// Teardown changes a file only when it can prove the file is DefenseClaw's as
// it is now: its bytes are exactly what the older setup wrote (the hash in its
// backup record; for the OpenHands hook script, the digest in the hook
// contract lock). Such a file is put back the way setup found it, removed when
// setup created it, or (the hook script) replaced by the disabled tombstone.
// Any other file that still names DefenseClaw (the user changed it, there is
// no record, it is a link, or it cannot be read) is left byte for byte, and
// then nothing at all is changed: the steps to finish by hand are recorded,
// which status and doctor show, and printed once. A file is never parsed and
// written back: a saved copy goes back byte for byte, and one that names
// DefenseClaw is dropped only when it is exactly what setup itself wrote. The
// OpenHands hook script becomes a tombstone that blocks every call and says
// how to remove the hook, so a hook that still runs it, by any path, link,
// wrapper or shell, never allows a call. Writes replace the
// file itself, never a link's target, and a change that fails, even after its
// new bytes are in place, is rolled back with the changes before it. Rollback
// writes a file back only while it still holds what teardown wrote: a file
// someone changed since is kept as it is, with the backup records.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	removedOpenHandsID         = "openhands"
	removedOpenHandsHookScript = "openhands-hook.sh"
	removedOmnigentID          = "omnigent"
	removedOmnigentModuleName  = "defenseclaw_omnigent_policy"
	// removedCleanupDir holds one record per removed connector whose
	// teardown left files for the user to clean up by hand. The Python CLI
	// (defenseclaw/removed_connectors.py) reads it for status and doctor.
	removedCleanupDir = "removed_connector_cleanup"
)

// removedConnector returns the teardown-only connector for a removed
// connector ID, or false.
func removedConnector(name string) (Connector, bool) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case removedOpenHandsID, "open-hands", "open_hands":
		return removedOpenHandsConnector{removedConnectorBase{name: removedOpenHandsID, label: "OpenHands"}}, true
	case removedOmnigentID:
		return removedOmnigentConnector{removedConnectorBase{name: removedOmnigentID, label: "OmniGent"}}, true
	}
	return nil, false
}

// removedConnectorBase holds what both removed connectors share: they never
// set up, authenticate or route anything.
type removedConnectorBase struct{ name, label string }

func (c removedConnectorBase) Name() string { return c.name }

func (c removedConnectorBase) Description() string {
	return c.label + " connector was removed in DefenseClaw 1.0.4; teardown only"
}

func (c removedConnectorBase) ToolInspectionMode() ToolInspectionMode {
	return ToolModePreExecution
}

func (c removedConnectorBase) SubprocessPolicy() SubprocessPolicy { return SubprocessNone }

func (c removedConnectorBase) Setup(context.Context, SetupOpts) error {
	return fmt.Errorf("connector %q was removed in DefenseClaw 1.0.4; choose a supported connector", c.name)
}

func (c removedConnectorBase) Authenticate(*http.Request) bool { return false }

func (c removedConnectorBase) Route(*http.Request, []byte) (*ConnectorSignals, error) {
	return nil, fmt.Errorf("connector %q was removed", c.name)
}

func (c removedConnectorBase) SetCredentials(string, string) {}

// removeCredentials revokes the connector-scoped hook and OTLP tokens an
// older release minted, and its hook contract lock entry. Callers run it
// only after the agent's config no longer references DefenseClaw.
func (c removedConnectorBase) removeCredentials(dataDir string) error {
	var errs []error
	if err := RemoveHookAPIToken(dataDir, c.name); err != nil {
		errs = append(errs, err)
	}
	// The OTLP scope is no longer on the allow-list, so the file is removed
	// directly; nothing accepts it any more.
	token := filepath.Join(dataDir, "hooks", otlpPathTokenFileName(OTLPPathTokenScope(c.name)))
	for _, path := range []string{token, token + ".tmp"} {
		if err := removeOwnedOTLPPathTokenFile(path); err != nil {
			errs = append(errs, fmt.Errorf("remove %s: %w", path, err))
		}
	}
	if err := ClearHookContractLockEntry(dataDir, c.name); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// removedPlanner lists what a removed connector's teardown would change.
type removedPlanner func(SetupOpts) (*removedCleanupPlan, error)

// teardown runs plan. With every file provably DefenseClaw's it makes all the
// changes or none (a failure rolls back and is returned, so the next start
// retries), drops the backup records named by logicals, runs finish, revokes
// the credentials and clears an earlier manual-cleanup record. Otherwise it
// changes nothing, records the manual steps and prints them once.
func (c removedConnectorBase) teardown(opts SetupOpts, plan removedPlanner, logicals []string, finish func() error) error {
	if strings.TrimSpace(opts.DataDir) == "" {
		return fmt.Errorf("%s cleanup: empty data directory", c.name)
	}
	p, err := plan(opts)
	if err != nil {
		return fmt.Errorf("%s cleanup: %w", c.name, err)
	}
	if len(p.manual) > 0 {
		return c.leaveForManualCleanup(opts.DataDir, p.manual)
	}
	if err := p.apply(); err != nil {
		return fmt.Errorf("%s cleanup: %w; the next start tries again", c.name, err)
	}
	for _, logical := range logicals {
		discardManagedFileBackup(opts.DataDir, c.name, logical)
	}
	if finish != nil {
		if err := finish(); err != nil {
			return fmt.Errorf("%s cleanup: %w", c.name, err)
		}
	}
	if err := c.removeCredentials(opts.DataDir); err != nil {
		return err
	}
	if err := os.Remove(removedCleanupRecordPath(opts.DataDir, c.name)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%s cleanup: %w", c.name, err)
	}
	return nil
}

// verifyClean fails while plan would still change a file, or while a file
// left for manual cleanup is not in the recorded steps.
func (c removedConnectorBase) verifyClean(opts SetupOpts, plan removedPlanner) error {
	p, err := plan(opts)
	if err != nil {
		return fmt.Errorf("%s cleanup: %w", c.name, err)
	}
	if len(p.manual) > 0 {
		recorded := loadRemovedCleanupRecord(opts.DataDir, c.name)
		for _, item := range p.manual {
			if !recorded.lists(item.Path) {
				return fmt.Errorf("%s cleanup incomplete: %s still names DefenseClaw (%s), and no manual cleanup step was recorded for it", c.name, item.Path, item.Reason)
			}
		}
		return nil
	}
	if len(p.files) > 0 {
		return fmt.Errorf("%s cleanup incomplete: %s is still as DefenseClaw wrote it", c.name, p.files[0].path)
	}
	return nil
}

// --- Manual cleanup record ---

// removedConnectorNotices receives the one warning a teardown prints when it
// leaves files for manual cleanup.
var removedConnectorNotices io.Writer = os.Stderr

type removedCleanupItem struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
	Step   string `json:"step"`
}

type removedCleanupRecord struct {
	Version   int                  `json:"version"`
	Connector string               `json:"connector"`
	Label     string               `json:"label"`
	Items     []removedCleanupItem `json:"items"`
	// Finish is the command that removes the rest once the steps are done.
	Finish string `json:"finish"`
}

func removedCleanupRecordPath(dataDir, connectorName string) string {
	return filepath.Join(dataDir, removedCleanupDir, connectorName+".json")
}

func loadRemovedCleanupRecord(dataDir, connectorName string) removedCleanupRecord {
	var record removedCleanupRecord
	if data, err := os.ReadFile(removedCleanupRecordPath(dataDir, connectorName)); err == nil {
		_ = json.Unmarshal(data, &record)
	}
	return record
}

func (r removedCleanupRecord) lists(path string) bool {
	for _, item := range r.Items {
		if sameManagedTargetPath(item.Path, path) {
			return true
		}
	}
	return false
}

func (c removedConnectorBase) leaveForManualCleanup(dataDir string, items []removedCleanupItem) error {
	record := removedCleanupRecord{
		Version:   1,
		Connector: c.name,
		Label:     c.label,
		Items:     items,
		Finish:    "defenseclaw-gateway connector teardown --connector " + c.name,
	}
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	path := removedCleanupRecordPath(dataDir, c.name)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("%s cleanup: record the manual steps: %w", c.name, err)
	}
	if err := atomicWriteFileNoFollow(path, append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("%s cleanup: record the manual steps: %w", c.name, err)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "[%s] WARNING: the %s connector was removed in DefenseClaw 1.0.4, but its cleanup changed nothing: these files are not exactly as DefenseClaw wrote them, so they are yours to finish.\n", c.name, c.label)
	for _, item := range items {
		fmt.Fprintf(&b, "  - %s (%s): %s\n", item.Path, item.Reason, item.Step)
	}
	fmt.Fprintf(&b, "  Then run `%s` to remove the rest. `defenseclaw doctor` lists these steps.\n", record.Finish)
	fmt.Fprint(removedConnectorNotices, b.String())
	return nil
}

// --- Plan ---

// removedCleanupPlan is what a teardown would do: files it can prove are
// DefenseClaw's, in the order it changes them, and files it must leave for
// the user.
type removedCleanupPlan struct {
	files  []removedFile
	manual []removedCleanupItem
}

// removedFile is a file whose bytes are exactly what an older setup wrote.
type removedFile struct {
	path string
	data []byte // the bytes the plan read: checked again before the change and written back on rollback
	mode os.FileMode
	// restore holds the bytes setup found (written with restoreMode); nil
	// removes the file.
	restore     []byte
	restoreMode os.FileMode
}

// removedFileKind says how to read one kind of file an older release wrote.
type removedFileKind struct {
	// names reports whether bytes still hold DefenseClaw's entry. An error
	// means teardown cannot tell, which counts as naming it.
	names func([]byte) (bool, error)
	// ownedName is set for a file under DefenseClaw's own name (the policy
	// module, its .pth file). When the copy setup found names DefenseClaw
	// too, the file is removed only if that copy is byte for byte what setup
	// itself wrote: an earlier DefenseClaw setup left it (GAP-1926). Any
	// other such copy may be the user's and is left for them, as is every
	// such copy of the agent's own config.
	ownedName bool
	// keepSaved puts the saved copy back byte for byte even when it names
	// DefenseClaw: the .pth line the user's own policy module needs.
	keepSaved bool
	// step says how to remove DefenseClaw's entry by hand.
	step string
}

func (p *removedCleanupPlan) leave(path, reason, step string) {
	p.manual = append(p.manual, removedCleanupItem{Path: path, Reason: reason, Step: step})
}

// errRemovedNotRegular marks a path that is not a regular file.
var errRemovedNotRegular = errors.New("not a regular file")

// readRemovedFile reads a regular file without following a symlink; a
// missing file returns nil data and nil info.
func readRemovedFile(path string) ([]byte, os.FileInfo, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, info, errRemovedNotRegular
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, nil
	}
	return data, info, err
}

// addRecorded plans the file a setup backup record names and returns its
// path ("" without a record).
func (p *removedCleanupPlan) addRecorded(dataDir, connectorName, logical string, kind removedFileKind) (string, error) {
	recordPath := managedFileBackupPath(dataDir, connectorName, logical)
	record, err := loadManagedFileBackupPath(recordPath)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("read %s: %w", recordPath, err)
	}
	path, err := validateManagedFileBackupTarget(record, connectorName, logical, record.Path)
	if err != nil {
		return "", fmt.Errorf("%s: %w", recordPath, err)
	}
	data, info, err := readRemovedFile(path)
	switch {
	case errors.Is(err, errRemovedNotRegular):
		p.leave(path, "it is not a regular file", kind.step)
		return path, nil
	case err != nil:
		return path, err
	case info == nil:
		return path, nil
	case record.PostSHA256 == "" || sha256Hex(data) != record.PostSHA256:
		p.addFound(path, data, kind, "it changed after DefenseClaw wrote it")
		return path, nil
	}
	file := removedFile{path: path, data: data, mode: info.Mode().Perm()}
	if record.Existed {
		saved := record.PristineBytes
		if saved == nil {
			saved = []byte{}
		}
		names, err := kind.names(saved)
		switch {
		case kind.keepSaved || (err == nil && !names):
			file.restore = saved
		case err == nil && kind.ownedName && sha256Hex(saved) == record.PostSHA256:
			// The saved copy is what setup wrote: an earlier setup's.
		default:
			p.leave(path, "the copy DefenseClaw saved before its setup names DefenseClaw too, so it may be yours",
				"copy what you need from that copy (pristine_bytes, base64, in "+recordPath+"), then "+kind.step)
			return path, nil
		}
		if file.restore != nil {
			file.restoreMode = os.FileMode(record.Mode)
			if file.restoreMode == 0 {
				file.restoreMode = 0o600
			}
		}
	}
	p.files = append(p.files, file)
	return path, nil
}

// readRemovedFileThrough reads a file teardown only checks and never changes,
// following a link (a link to nothing is a missing file): what the agent
// reads there is what counts. Anything but a regular file is
// errRemovedNotRegular.
func readRemovedFileThrough(path string) ([]byte, os.FileInfo, error) {
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, info, errRemovedNotRegular
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil, nil
	}
	return data, info, err
}

// addUnrecorded plans a file no backup record names: it is left for the user
// when it still names DefenseClaw. It is never changed, so a link is read
// through.
func (p *removedCleanupPlan) addUnrecorded(path string, kind removedFileKind) error {
	data, info, err := readRemovedFileThrough(path)
	switch {
	case errors.Is(err, errRemovedNotRegular):
		p.leave(path, "it is not a regular file", kind.step)
		return nil
	case err != nil:
		return err
	case info == nil:
		return nil
	}
	p.addFound(path, data, kind, "DefenseClaw has no record of writing it")
	return nil
}

func (p *removedCleanupPlan) addFound(path string, data []byte, kind removedFileKind, reason string) {
	names, err := kind.names(data)
	switch {
	case err != nil:
		p.leave(path, fmt.Sprintf("DefenseClaw cannot tell whether it still names DefenseClaw: %v", err), kind.step)
	case names:
		p.leave(path, reason, kind.step)
	}
}

// apply makes every planned change or none: a change that fails, or a file
// that changed since the plan read it, rolls back the changes already made.
// A change that failed after its new bytes were in place (the parent
// directory sync after the rename, say) is rolled back too.
func (p *removedCleanupPlan) apply() error {
	for i, file := range p.files {
		if changing, err := file.apply(); err != nil {
			n := i
			if changing {
				n = i + 1
			}
			if rollbackErr := p.rollback(n); rollbackErr != nil {
				return errors.Join(err, rollbackErr)
			}
			return fmt.Errorf("%w; nothing was changed", err)
		}
	}
	return nil
}

// apply makes the change; changing reports that a failure came from the
// change itself, not from the check before it.
func (f removedFile) apply() (changing bool, err error) {
	data, info, err := readRemovedFile(f.path)
	if err != nil {
		return false, fmt.Errorf("read %s: %w", f.path, err)
	}
	if info == nil || !bytes.Equal(data, f.data) {
		return false, fmt.Errorf("%s changed during cleanup", f.path)
	}
	if f.restore == nil {
		if err := os.Remove(f.path); err != nil {
			return true, fmt.Errorf("remove %s: %w", f.path, err)
		}
		return true, nil
	}
	if err := atomicWriteFileNoFollow(f.path, f.restore, f.restoreMode); err != nil {
		return true, newManagedRestoreError(f.path, err)
	}
	return true, nil
}

// published reports whether data and info (a read of the file) are what the
// change left: the bytes it restored, or no file after a removal.
func (f removedFile) published(data []byte, info os.FileInfo) bool {
	if f.restore == nil {
		return info == nil
	}
	return info != nil && bytes.Equal(data, f.restore)
}

// rollback puts back the first n files as the plan read them. A file is
// written back only while it holds what the change left; one that already
// holds the bytes the plan read needs nothing. Any other file was changed by
// someone else since (edited, deleted, recreated, or replaced by a link): it
// is kept as it is and reported, and the backup records stay, so the next
// start plans from what is there.
func (p *removedCleanupPlan) rollback(n int) error {
	var errs []error
	for i := n - 1; i >= 0; i-- {
		file := p.files[i]
		data, info, err := readRemovedFile(file.path)
		switch {
		case err != nil:
			errs = append(errs, fmt.Errorf("did not put back %s: %w; it is kept as it is", file.path, err))
		case info != nil && bytes.Equal(data, file.data):
		case !file.published(data, info):
			errs = append(errs, fmt.Errorf("did not put back %s: it changed after the cleanup wrote it, so it is kept as it is", file.path))
		default:
			if err := atomicWriteFileNoFollow(file.path, file.data, file.mode); err != nil {
				errs = append(errs, fmt.Errorf("could not put back %s: %w", file.path, err))
			}
		}
	}
	return errors.Join(errs...)
}

// --- OpenHands ---

type removedOpenHandsConnector struct{ removedConnectorBase }

func (removedOpenHandsConnector) hookScript(opts SetupOpts) string {
	return filepath.Join(opts.DataDir, "hooks", removedOpenHandsHookScript)
}

// hooksPaths are the hooks.json files an older release may have written
// besides the one its setup backup names: the explicit config home native
// maintenance passes, else the user-global default, and every hooks.json the
// hook contract lock says setup wrote (a workspace's .openhands/hooks.json).
func (c removedOpenHandsConnector) hooksPaths(opts SetupOpts) []string {
	var paths []string
	if homes := removedResolvedPaths(opts.ConfigHome); len(homes) > 0 {
		for _, home := range homes {
			paths = append(paths, filepath.Join(home, "hooks.json"))
		}
	} else {
		paths = append(paths, homePath(".openhands", "hooks.json"))
	}
	if entry, err := LoadHookContractLockEntryForMode(opts.DataDir, c.name, opts.ManagedEnterprise); err == nil {
		for _, path := range entry.Locations.HookConfigPaths {
			if filepath.Base(path) == "hooks.json" {
				paths = append(paths, removedResolvedPaths(path)...)
			}
		}
	}
	return uniqueNonEmptyStrings(paths)
}

func (c removedOpenHandsConnector) plan(opts SetupOpts) (*removedCleanupPlan, error) {
	script := c.hookScript(opts)
	kind := removedFileKind{
		names: func(data []byte) (bool, error) { return removedJSONNames(data, script) },
		step:  "remove the hook entries whose command runs " + script,
	}
	p := &removedCleanupPlan{}
	recorded, err := p.addRecorded(opts.DataDir, c.name, "config", kind)
	if err != nil {
		return nil, err
	}
	for _, path := range c.hooksPaths(opts) {
		if recorded != "" && sameManagedTargetPath(path, recorded) {
			continue
		}
		if err := p.addUnrecorded(path, kind); err != nil {
			return nil, err
		}
	}
	// Last: the script becomes the tombstone once the hooks files are back.
	if err := c.addHookScript(p, opts); err != nil {
		return nil, err
	}
	return p, nil
}

// addHookScript plans DefenseClaw's hook script. A script exactly as setup
// wrote it (its digest in the hook contract lock), or a tombstone that exits
// 0 (removedOpenHandsAllowTombstone), becomes the OpenHands tombstone, which
// blocks every call. So a hook that still runs the script once the cleanup is
// done (one in a hooks.json the cleanup puts back, one the user wrote, or an
// OpenHands conversation that loaded the hook before teardown) never allows a
// call, whatever path, link, wrapper or shell runs it, and OpenHands shows
// how to remove it. A script DefenseClaw cannot prove it wrote (it changed,
// there is no digest, or it is a link or not a regular file), or one with
// another name (a hard link, which keeps the old bytes when the tombstone
// replaces the file), is left for the user, and so is everything else.
func (c removedOpenHandsConnector) addHookScript(p *removedCleanupPlan, opts SetupOpts) error {
	script := c.hookScript(opts)
	const step = "delete it once no OpenHands hooks file runs it"
	data, info, err := readRemovedFile(script)
	switch {
	case errors.Is(err, errRemovedNotRegular):
		p.leave(script, "it is not a regular file", step)
		return nil
	case err != nil:
		return err
	case info == nil, removedOpenHandsTombstone(data):
		return nil
	case removedHardLinked(script, info):
		p.leave(script, "it has another name (a hard link), which would keep running it as it is",
			"delete it and every hard link to it once no OpenHands hooks file runs them")
		return nil
	}
	if !removedOpenHandsAllowTombstone(data) {
		entry, err := LoadHookContractLockEntryForMode(opts.DataDir, c.name, opts.ManagedEnterprise)
		if err != nil {
			p.leave(script, fmt.Sprintf("DefenseClaw cannot read its record of the script: %v", err), step)
			return nil
		}
		switch want := entry.HookScriptDigests[removedOpenHandsHookScript]; {
		case want == "":
			p.leave(script, "DefenseClaw has no record of writing it", step)
			return nil
		case !strings.EqualFold(strings.TrimPrefix(want, "sha256:"), sha256Hex(data)):
			p.leave(script, "it changed after DefenseClaw wrote it", step)
			return nil
		}
	}
	p.files = append(p.files, removedFile{
		path: script, data: data, mode: info.Mode().Perm(),
		restore: []byte(removedOpenHandsTombstoneBody), restoreMode: 0o700,
	})
	return nil
}

// removedHardLinked reports whether the file at path (info, from Lstat) has
// more than one name, or the count cannot be read.
func removedHardLinked(path string, info os.FileInfo) bool {
	file, err := os.Open(path)
	if err != nil {
		return true
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(opened, info) {
		return true
	}
	links, err := atomicTransformBoundLinkCountPlatform(file)
	return err != nil || links != 1
}

// removedOpenHandsDenyReason is the one line the OpenHands tombstone gives
// OpenHands with every block.
const removedOpenHandsDenyReason = "DefenseClaw blocked this call: OpenHands support was removed in DefenseClaw 1.0.4. " +
	"To use OpenHands without DefenseClaw, remove every hook that runs " + removedOpenHandsHookScript +
	" from your OpenHands hooks.json (~/.openhands/hooks.json, or .openhands/hooks.json in a workspace), then restart OpenHands."

// removedOpenHandsTombstoneBody is the hook script an OpenHands teardown
// leaves. It blocks every call: OpenHands blocks on exit status 2 and shows
// the deny reason. It is the same run directly or by any shell (sh, bash,
// dash, zsh, ksh, csh, tcsh, fish, busybox), through a link or a wrapper,
// with any option (-l, -e, -c), or sourced: it uses only echo and exit, and
// its one quoted string holds no $, !, backslash or single quote, so no
// shell expands or splits anything in it, and nothing runs before the exit
// that could end the script with another status. The v0 marker keeps it
// DefenseClaw's for doctor and the hook owner checks.
const removedOpenHandsTombstoneBody = "#!/bin/sh\n" +
	"# defenseclaw-managed-hook v0 (disabled tombstone)\n" +
	"# OpenHands support was removed in DefenseClaw 1.0.4. This hook blocks every\n" +
	"# call. Remove the hooks that run it from your OpenHands hooks.json.\n" +
	"echo '{\"decision\":\"deny\",\"reason\":\"" + removedOpenHandsDenyReason + "\"}'\n" +
	"exit 2\n"

// removedOpenHandsTombstone reports whether data is the tombstone an
// OpenHands teardown leaves.
func removedOpenHandsTombstone(data []byte) bool {
	return string(data) == removedOpenHandsTombstoneBody
}

// removedOpenHandsAllowTombstone reports whether data is a tombstone that
// exits 0: the one a 1.0.x OpenHands teardown wrote ("openhands"), or an
// earlier 1.0.4 build's ("OpenHands"). Its bytes prove it is DefenseClaw's,
// so teardown replaces it with the tombstone that blocks.
func removedOpenHandsAllowTombstone(data []byte) bool {
	return string(data) == disabledHookTombstone(removedOpenHandsID) || string(data) == disabledHookTombstone("OpenHands")
}

// Teardown puts back the hooks.json an older release's setup found and turns
// DefenseClaw's hook script into the tombstone that blocks every call, when
// each is exactly as setup left it (see the file comment).
func (c removedOpenHandsConnector) Teardown(_ context.Context, opts SetupOpts) error {
	return c.teardown(opts, c.plan, []string{"config"}, func() error {
		record := filepath.Join(opts.DataDir, "hooks", hookConfigSidecarName+"."+c.name)
		if err := os.Remove(record); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove %s: %w", record, err)
		}
		return nil
	})
}

// VerifyClean fails while a hooks file or the hook script is still as
// DefenseClaw wrote it, or a file it cannot prove it wrote still names
// DefenseClaw without a recorded manual step.
func (c removedOpenHandsConnector) VerifyClean(opts SetupOpts) error {
	return c.verifyClean(opts, c.plan)
}

// removedJSONNames reports whether a decoded JSON document has needle in a
// key or string value; JSON that does not decode is an error.
func removedJSONNames(data []byte, needle string) (bool, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return false, nil
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	var document interface{}
	if err := decoder.Decode(&document); err != nil {
		return false, fmt.Errorf("not valid JSON: %w", err)
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return false, errors.New("not valid JSON: data after the document")
	}
	return jsonValueNames(document, needle), nil
}

func jsonValueNames(value interface{}, needle string) bool {
	switch v := value.(type) {
	case string:
		return strings.Contains(v, needle)
	case []interface{}:
		for _, item := range v {
			if jsonValueNames(item, needle) {
				return true
			}
		}
	case map[string]interface{}:
		for key, item := range v {
			if strings.Contains(key, needle) || jsonValueNames(item, needle) {
				return true
			}
		}
	}
	return false
}

// --- OmniGent ---

type removedOmnigentConnector struct{ removedConnectorBase }

func (removedOmnigentConnector) modulePath(opts SetupOpts) string {
	return filepath.Join(opts.DataDir, "hooks", removedOmnigentModuleName+".py")
}

// configPaths are the OmniGent config files an older release may have patched
// besides the one its setup backup names, and that OmniGent may still read:
// the explicit config home native maintenance passes, the file
// OMNIGENT_CONFIG selects (OmniGent reads it before any config home),
// OMNIGENT_CONFIG_HOME, ~/.omnigent and every config file the hook contract
// lock says setup wrote, a relative or ~ one resolved (removedResolvedPaths). All of them are checked, whichever is given: they are
// only read, and one that still names the module keeps every file in place.
func (c removedOmnigentConnector) configPaths(opts SetupOpts) []string {
	var paths []string
	for _, home := range removedResolvedPaths(opts.ConfigHome) {
		paths = append(paths, filepath.Join(home, "config.yaml"))
	}
	paths = append(paths, removedOmnigentExplicitConfig())
	for _, home := range removedResolvedPaths(os.Getenv("OMNIGENT_CONFIG_HOME")) {
		paths = append(paths, filepath.Join(home, "config.yaml"))
	}
	paths = append(paths, homePath(".omnigent", "config.yaml"))
	if entry, err := LoadHookContractLockEntryForMode(opts.DataDir, c.name, opts.ManagedEnterprise); err == nil {
		for _, path := range entry.Locations.HookConfigPaths {
			switch strings.ToLower(filepath.Ext(path)) {
			case ".yaml", ".yml":
				paths = append(paths, removedResolvedPaths(path)...)
			}
		}
	}
	return uniqueNonEmptyStrings(paths)
}

// removedResolvedPaths resolves a config home or config file an older
// release may have used, every way it may have read it (nil for ""): a
// relative path from the working directory (the Go setup used the value as
// given), and ~, ~/ or ~\ also as the user's home (the Python CLI expands
// it). Teardown only reads these files, so checking one more costs nothing.
func removedResolvedPaths(value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	var paths []string
	switch {
	case value == "~":
		paths = append(paths, homePath())
	case strings.HasPrefix(value, "~/") || strings.HasPrefix(value, `~\`):
		paths = append(paths, filepath.Join(homePath(), value[2:]))
	}
	if absolute, err := filepath.Abs(value); err == nil {
		paths = append(paths, absolute)
	} else if filepath.IsAbs(value) {
		paths = append(paths, filepath.Clean(value))
	}
	return paths
}

// removedOmnigentExplicitConfig resolves OMNIGENT_CONFIG the way an older
// setup did ("" when it is unset): ~/ is the user's home, and a relative path
// is taken from the working directory.
func removedOmnigentExplicitConfig() string {
	explicit := strings.TrimSpace(os.Getenv("OMNIGENT_CONFIG"))
	switch {
	case explicit == "":
		return ""
	case strings.HasPrefix(explicit, "~/") || strings.HasPrefix(explicit, `~\`):
		return filepath.Join(homePath(), explicit[2:])
	}
	if absolute, err := filepath.Abs(explicit); err == nil {
		return filepath.Clean(absolute)
	}
	return filepath.Clean(explicit)
}

var removedOmnigentConfigKind = removedFileKind{
	names: removedOmnigentConfigNames,
	step: "remove " + removedOmnigentModuleName + " from policy_modules, and the policy whose handler starts with " +
		removedOmnigentModuleName + ".",
}

// removedOmnigentModuleMarker heads every policy module an older release
// wrote (0.8.3 through 1.0.3).
const removedOmnigentModuleMarker = "# defenseclaw-managed-policy v"

// The policy module lives in DefenseClaw's hook directory under DefenseClaw's
// name, but it is DefenseClaw's only while it carries DefenseClaw's marker: a
// module the user put there before setup is put back, and one the user wrote
// since is left alone.
var removedOmnigentModuleKind = removedFileKind{
	names:     removedOmnigentModuleNames,
	ownedName: true,
	step: "delete it once config.yaml no longer names " + removedOmnigentModuleName +
		" (to keep it as yours, delete its line that starts with " + removedOmnigentModuleMarker + ")",
}

func removedOmnigentModuleNames(data []byte) (bool, error) {
	return bytes.Contains(data, []byte(removedOmnigentModuleMarker)), nil
}

// removedOmnigentImportPathKind reads DefenseClaw's .pth file. Its saved copy
// goes back byte for byte when the user's own policy module stays in hookDir
// (userModule), since that module needs the line.
func removedOmnigentImportPathKind(hookDir string, userModule bool) removedFileKind {
	return removedFileKind{
		names: func(data []byte) (bool, error) {
			for _, line := range strings.Split(string(data), "\n") {
				if entry := strings.TrimSpace(line); entry != "" && sameManagedTargetPath(entry, hookDir) {
					return true, nil
				}
			}
			return false, nil
		},
		ownedName: true,
		keepSaved: userModule,
		step:      "delete the line " + hookDir + " once config.yaml no longer names " + removedOmnigentModuleName,
	}
}

// userModuleStays reports whether a policy module of the user's own (one
// without DefenseClaw's marker) is in DefenseClaw's hook directory after the
// cleanup: setup saved one, or the user wrote one since.
func (c removedOmnigentConnector) userModuleStays(opts SetupOpts) bool {
	own := c.modulePath(opts)
	record, err := loadManagedFileBackupPath(managedFileBackupPath(opts.DataDir, c.name, "module"))
	if err == nil && record.Existed && sameManagedTargetPath(record.Path, own) {
		if names, _ := removedOmnigentModuleNames(record.PristineBytes); !names {
			return true
		}
	}
	data, info, err := readRemovedFile(own)
	if err != nil || info == nil {
		return false
	}
	names, _ := removedOmnigentModuleNames(data)
	return !names
}

// plan lists config.yaml first, then the .pth file, then the module: changes
// are made in that order, so OmniGent is never left with a config that names
// a module it cannot import.
func (c removedOmnigentConnector) plan(opts SetupOpts) (*removedCleanupPlan, error) {
	p := &removedCleanupPlan{}
	recorded, err := p.addRecorded(opts.DataDir, c.name, "config", removedOmnigentConfigKind)
	if err != nil {
		return nil, err
	}
	for _, path := range c.configPaths(opts) {
		if recorded != "" && sameManagedTargetPath(path, recorded) {
			continue
		}
		if err := p.addUnrecorded(path, removedOmnigentConfigKind); err != nil {
			return nil, err
		}
	}
	own := c.modulePath(opts)
	pthKind := removedOmnigentImportPathKind(filepath.Dir(own), c.userModuleStays(opts))
	if _, err := p.addRecorded(opts.DataDir, c.name, "pth", pthKind); err != nil {
		return nil, err
	}
	module, err := p.addRecorded(opts.DataDir, c.name, "module", removedOmnigentModuleKind)
	if err != nil {
		return nil, err
	}
	if module == "" || !sameManagedTargetPath(module, own) {
		if err := p.addUnrecorded(own, removedOmnigentModuleKind); err != nil {
			return nil, err
		}
	}
	return p, nil
}

// Teardown puts back config.yaml, the .pth file and the policy module the
// way an older release's setup found them (removing what it created), when
// each is exactly as setup left it (see the file comment).
func (c removedOmnigentConnector) Teardown(_ context.Context, opts SetupOpts) error {
	return c.teardown(opts, c.plan, []string{"config", "pth", "module"}, nil)
}

// VerifyClean fails while a file is still as DefenseClaw wrote it, or still
// names DefenseClaw without a recorded manual step.
func (c removedOmnigentConnector) VerifyClean(opts SetupOpts) error {
	return c.verifyClean(opts, c.plan)
}

// removedOmnigentConfigNames reports whether OmniGent config.yaml bytes name
// DefenseClaw's module in what a YAML loader reads: a decoded key, value or
// tag in any document, including a !!binary value and a double-quoted escape
// that spells the name without its literal text. Comments do not count. YAML
// that does not parse is an error: what OmniGent reads from it is unknown.
// The file is only read, never rewritten.
func removedOmnigentConfigNames(data []byte) (bool, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	for {
		var document yaml.Node
		err := decoder.Decode(&document)
		if errors.Is(err, io.EOF) {
			return false, nil
		}
		if err != nil {
			return false, fmt.Errorf("not valid YAML: %w", err)
		}
		if yamlNodeNames(&document, removedOmnigentModuleName) {
			return true, nil
		}
	}
}

// yamlNodeNames reports whether a parsed YAML tree spells name in a decoded
// scalar (key or value), in a !!binary scalar's decoded bytes, or in a tag.
// Aliases need no following: the nodes they name are in the tree.
func yamlNodeNames(node *yaml.Node, name string) bool {
	if node == nil {
		return false
	}
	if strings.Contains(node.Value, name) || strings.Contains(node.Tag, name) {
		return true
	}
	if node.Kind == yaml.ScalarNode && node.ShortTag() == "!!binary" {
		data, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(node.Value), ""))
		if err == nil && strings.Contains(string(data), name) {
			return true
		}
	}
	for _, child := range node.Content {
		if yamlNodeNames(child, name) {
			return true
		}
	}
	return false
}
