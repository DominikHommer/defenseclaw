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
// OpenHands hook script becomes the tombstone only when no hooks file can
// still run it, the copies teardown puts back included. Writes replace the
// file itself, never a link's target, and a change that fails, even after its
// new bytes are in place, is rolled back with the changes before it. Rollback
// writes a file back only while it still holds what teardown wrote: a file
// someone changed since is kept as it is, with the backup records.

import (
	"bytes"
	"context"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
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

// planned returns the change the plan makes to path; lists reports whether
// the plan leaves path for the user.
func (p *removedCleanupPlan) planned(path string) (removedFile, bool) {
	for _, file := range p.files {
		if sameManagedTargetPath(file.path, path) {
			return file, true
		}
	}
	return removedFile{}, false
}

func (p *removedCleanupPlan) lists(path string) bool {
	for _, item := range p.manual {
		if sameManagedTargetPath(item.Path, path) {
			return true
		}
	}
	return false
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
	var checked []string
	if recorded != "" {
		checked = append(checked, recorded)
	}
	for _, path := range c.hooksPaths(opts) {
		if recorded != "" && sameManagedTargetPath(path, recorded) {
			continue
		}
		if err := p.addUnrecorded(path, kind); err != nil {
			return nil, err
		}
		checked = append(checked, path)
	}
	// Last: the script becomes the tombstone only once no hooks file runs it.
	if err := c.addHookScript(p, opts, checked); err != nil {
		return nil, err
	}
	return p, nil
}

// removedHooksFile is a hooks file that may still run the hook script once
// the cleanup is done; restored marks the copy setup found, which the
// cleanup would put back.
type removedHooksFile struct {
	path     string
	restored bool
}

// hooksThatMayRunScript lists the hooks files in paths that may still run
// the hook script (script, read as info) once the plan is done: what the
// plan leaves in place, and the copy setup found where the plan puts that
// back. A file the plan leaves for the user is listed already, and one it
// removes runs nothing. Every command in a hooks file must be ruled out (see
// removedScriptCheck), the saved copy's included: a copy setup found may run
// the script through a link or a wrapper too.
func (c removedOpenHandsConnector) hooksThatMayRunScript(p *removedCleanupPlan, opts SetupOpts, paths []string, script string, info os.FileInfo) []removedHooksFile {
	check := newRemovedScriptCheck(script, info, opts.DataDir)
	var out []removedHooksFile
	for _, path := range paths {
		if p.lists(path) {
			continue
		}
		if file, ok := p.planned(path); ok {
			if file.restore != nil && check.hooksMayRun(file.restore) {
				out = append(out, removedHooksFile{path: path, restored: true})
			}
			continue
		}
		data, found, err := readRemovedFileThrough(path)
		if err != nil || found == nil {
			continue
		}
		if check.hooksMayRun(data) {
			out = append(out, removedHooksFile{path: path})
		}
	}
	return out
}

// removedScriptCheck tells whether OpenHands hooks may run DefenseClaw's hook
// script. It rules a command out only when it can see what the command runs:
// the command is plain words (no variables, ~, globs, pipes, lists or
// redirections; quotes are fine), it starts with an absolute path, and every
// other word is an absolute path or a bare flag (-x, or --name with no
// value) given to a program other than a shell. A program may run what an
// argument names: a command found on PATH (env -S relay, env 30), a module
// (python3 -mrelay), a command line split at its blanks (env -S '/bin/env
// relay') or a list (--require=/a,relay), and a shell's own options may run
// its startup files (sh -l). So an option with a value is ruled out only
// when the value is an absolute path, an absolute path is ruled out only
// when it and every part of it (split at blanks, :, , and =) is an absolute
// path that is ruled out, and a number, any other word, a cluster of flags
// (-Srelay) and a shell's option before its script may run the script. A
// command found on PATH, a relative path or any shell syntax may run
// anything, so it may run the script. A path in the command may run the
// script when it names
// DefenseClaw or the script, is the script (through links or as a hard link),
// is a directory that holds the script or names DefenseClaw, or is a file
// whose bytes name either. Only a program (machine code this system's loader
// runs) is ruled out by the names in its bytes alone. Any other file with a
// NUL byte may run the script: a shell reads a script that holds one, and
// runs as a script a file the loader cannot run. A text file (a wrapper) may
// also run it through the paths it names, checked the same way a few levels
// deep (a quoted path
// with a blank whole, a list of paths part by part), and through what the
// check cannot follow: a relative path or cd, a variable or a command
// substitution in a path, a path that goes on past the plain characters the
// check reads (an escape, a quote that joins more text, any other character)
// or that ends a longer word, a script in a language other than the shell,
// or a command found on PATH while a PATH directory holds the script.
type removedScriptCheck struct {
	script  os.FileInfo
	needles [][]byte // lower case
	home    string
	seen    map[string]bool
	files   int
	onPath  *bool
}

const (
	removedScriptCheckDepth      = 4
	removedScriptCheckFiles      = 64
	removedScriptCheckDirEntries = 10000
	removedScriptCheckTextLimit  = 1 << 20
	removedScriptCheckScanLimit  = 512 << 20
)

var (
	// removedTextPath finds the absolute paths a wrapper names, ~ and
	// $HOME ones included (group 1 is the home prefix, group 2 the path).
	removedTextPath = regexp.MustCompile(`(~|\$HOME|\$\{HOME\})?["']?((?:/[A-Za-z0-9_.+@%,:=-]+)+)`)
	// removedTextRelative finds a relative ./ or ../ path, a cd, or a path
	// that starts with a command substitution.
	removedTextRelative = regexp.MustCompile("(?:^|[\\s;&|(=\"'`])(?:\\.{1,2}/|(?:cd|pushd)\\s)|[)`][\"']?/")
	// removedTextVariable finds a path that starts with a variable (group 1
	// is its name; HOME is followed).
	removedTextVariable = regexp.MustCompile(`\$\{?([A-Za-z_][A-Za-z0-9_]*|[0-9@*#?!$-])\}?["']?/`)
	// removedBareOption is a flag with no value: -x, or --name.
	removedBareOption = regexp.MustCompile(`^(?:-[A-Za-z0-9]|--[A-Za-z0-9][A-Za-z0-9_.-]*)$`)
	// removedPathOption is an option whose value is an absolute path
	// (group 1): -name=/path or --name=/path.
	removedPathOption = regexp.MustCompile(`^--?[A-Za-z0-9][A-Za-z0-9_.-]*=(/.*)$`)
	// removedArgument is an absolute path argument the check can read: plain
	// characters and blanks.
	removedArgument = regexp.MustCompile(`^/[A-Za-z0-9_./:,@%+= \t-]*$`)
)

func newRemovedScriptCheck(script string, info os.FileInfo, dataDir string) *removedScriptCheck {
	names := []string{"defenseclaw", strings.TrimSuffix(removedOpenHandsHookScript, ".sh")}
	for _, dir := range []string{dataDir, filepath.Dir(script)} {
		if strings.TrimSpace(dir) == "" {
			continue
		}
		names = append(names, filepath.Clean(dir))
		if resolved, err := filepath.EvalSymlinks(dir); err == nil {
			names = append(names, resolved)
		}
	}
	check := &removedScriptCheck{script: info, home: homePath(), seen: map[string]bool{}}
	for _, name := range uniqueNonEmptyStrings(names) {
		check.needles = append(check.needles, []byte(strings.ToLower(name)))
	}
	return check
}

// hooksMayRun reports whether a hooks file may run the script: a string in it
// other than a "matcher" or "type" value is a command, and an empty file runs
// nothing. A file that is not one JSON document may run anything.
func (c *removedScriptCheck) hooksMayRun(data []byte) bool {
	if len(bytes.TrimSpace(data)) == 0 {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	var document interface{}
	if err := decoder.Decode(&document); err != nil {
		return true
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return true
	}
	var runs func(value interface{}, key string) bool
	runs = func(value interface{}, key string) bool {
		switch v := value.(type) {
		case string:
			switch {
			case key == "matcher", key == "type":
				return false
			case key != "command" && strings.Trim(v, " \t0123456789") == "":
				// A number written as a string (a timeout, say). A
				// command that is a number runs what PATH finds.
				return false
			}
			return c.commandMayRun(v)
		case []interface{}:
			for _, item := range v {
				if runs(item, key) {
					return true
				}
			}
		case map[string]interface{}:
			for k, item := range v {
				if runs(item, k) {
					return true
				}
			}
		}
		return false
	}
	return runs(document, "")
}

func (c *removedScriptCheck) commandMayRun(command string) bool {
	if strings.TrimSpace(command) == "" {
		return false
	}
	words, ok := removedPlainWords(command)
	if !ok || len(words) == 0 {
		return true
	}
	// shellOptions: the last program named is a shell and no operand came
	// after it, so an option is the shell's own (-l reads its profile).
	shellOptions := false
	for i, word := range words {
		if c.names([]byte(word)) {
			return true
		}
		switch {
		case i == 0:
			// The shell runs the first word as it is.
			if !filepath.IsAbs(word) || c.pathMayRun(word, 0) {
				return true
			}
		case strings.HasPrefix(word, "-"):
			if shellOptions {
				return true
			}
			if removedBareOption.MatchString(word) {
				continue
			}
			match := removedPathOption.FindStringSubmatch(word)
			if match == nil || c.argumentMayRun(match[1]) {
				return true
			}
			continue
		case c.argumentMayRun(word):
			return true
		}
		shellOptions = removedRunsShell(word)
	}
	return false
}

// argumentMayRun reports whether a word given to a program (an argument or
// an option's value) may run the script. The program may read it whole, or
// split it at its blanks (env -S) or as a list (a:b, a,b, a=b), so the whole
// and every part must be an absolute path that is ruled out.
func (c *removedScriptCheck) argumentMayRun(value string) bool {
	if !removedArgument.MatchString(value) || c.pathMayRun(value, 0) {
		return true
	}
	parts := strings.FieldsFunc(value, func(r rune) bool { return strings.ContainsRune(" \t:,=", r) })
	if len(parts) < 2 {
		return false
	}
	for _, part := range parts {
		if !filepath.IsAbs(part) || c.pathMayRun(part, 0) {
			return true
		}
	}
	return false
}

// removedCommandShells are the shells whose own options (-l, -i, --rcfile,
// -c) may run code the command does not show.
var removedCommandShells = map[string]bool{
	"sh": true, "bash": true, "rbash": true, "dash": true, "zsh": true, "ksh": true, "mksh": true, "pdksh": true,
	"oksh": true, "ash": true, "csh": true, "tcsh": true, "fish": true, "yash": true, "posh": true, "busybox": true,
}

// removedRunsShell reports whether path is a shell, by its name or the name
// of what it links to (a version suffix such as bash5.2 dropped).
func removedRunsShell(path string) bool {
	names := []string{filepath.Base(path)}
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		names = append(names, filepath.Base(resolved))
	}
	for _, name := range names {
		if removedCommandShells[strings.TrimRight(strings.ToLower(name), "0123456789.-")] {
			return true
		}
	}
	return false
}

// removedPlainWords splits a command made only of plain words: letters,
// digits and _ . / - + = : , @ %, separated by blanks, with single quotes and
// with double quotes that hold no $, `, \ or !. Anything else is shell syntax
// the check cannot follow (ok is false).
func removedPlainWords(command string) (words []string, ok bool) {
	var word strings.Builder
	inWord := false
	for i := 0; i < len(command); i++ {
		ch := command[i]
		switch {
		case ch == ' ' || ch == '\t':
			if inWord {
				words = append(words, word.String())
				word.Reset()
				inWord = false
			}
		case ch == '\'' || ch == '"':
			end := strings.IndexByte(command[i+1:], ch)
			if end < 0 {
				return nil, false
			}
			quoted := command[i+1 : i+1+end]
			if ch == '"' && strings.ContainsAny(quoted, "$`\\!") {
				return nil, false
			}
			word.WriteString(quoted)
			inWord = true
			i += end + 1
		case ch >= 'a' && ch <= 'z', ch >= 'A' && ch <= 'Z', ch >= '0' && ch <= '9', strings.IndexByte("_./-+=:,@%", ch) >= 0:
			word.WriteByte(ch)
			inWord = true
		default:
			return nil, false
		}
	}
	if inWord {
		words = append(words, word.String())
	}
	return words, true
}

func (c *removedScriptCheck) names(data []byte) bool {
	lower := bytes.ToLower(data)
	for _, needle := range c.needles {
		if bytes.Contains(lower, needle) {
			return true
		}
	}
	return false
}

// pathMayRun reports whether an absolute path may run the script. Nothing
// there runs nothing; a path it cannot look at may run anything.
func (c *removedScriptCheck) pathMayRun(path string, depth int) bool {
	path = filepath.Clean(path)
	if c.names([]byte(path)) {
		return true
	}
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false
	}
	if err != nil || os.SameFile(info, c.script) {
		return true
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || c.names([]byte(resolved)) {
		return true
	}
	switch {
	case info.IsDir():
		return c.dirMayRun(resolved)
	case info.Mode().IsRegular():
		return c.fileMayRun(resolved, info, depth)
	}
	return false
}

// dirMayRun reports whether a directory holds the script, or an entry whose
// name names DefenseClaw or the script.
func (c *removedScriptCheck) dirMayRun(dir string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) > removedScriptCheckDirEntries {
		return true
	}
	for _, entry := range entries {
		if c.names([]byte(entry.Name())) {
			return true
		}
	}
	return c.holdsScript(dir)
}

// fileMayRun reports whether a regular file may run the script: its bytes
// name DefenseClaw or the script, or it is a text file that may run it
// through a path it names.
func (c *removedScriptCheck) fileMayRun(path string, info os.FileInfo, depth int) bool {
	if c.seen[path] {
		return false
	}
	c.seen[path] = true
	c.files++
	if c.files > removedScriptCheckFiles || info.Size() > removedScriptCheckScanLimit {
		return true
	}
	file, err := os.Open(path)
	if err != nil {
		return true
	}
	defer file.Close()
	overlap := 0
	for _, needle := range c.needles {
		if len(needle) > overlap {
			overlap = len(needle)
		}
	}
	var text, window []byte
	nul := false
	chunk := make([]byte, 64<<10)
	for {
		n, err := file.Read(chunk)
		if n > 0 {
			nul = nul || bytes.IndexByte(chunk[:n], 0) >= 0
			if !nul && len(text) <= removedScriptCheckTextLimit {
				text = append(text, chunk[:n]...)
			}
			window = append(window, chunk[:n]...)
			if c.names(window) {
				return true
			}
			if len(window) > overlap {
				window = append(window[:0], window[len(window)-overlap:]...)
			}
		}
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return true
		}
	}
	if nul {
		// A NUL byte does not make a file a program: dash drops NUL bytes,
		// bash refuses one only on the first line, and a file the loader
		// cannot run (a script with no #! line, an image for another
		// system) is run by the shell as a script (the ENOEXEC fallback).
		return !removedLoadableImage(file, runtime.GOOS)
	}
	if !removedShellText(path, text) {
		return true
	}
	if len(text) > removedScriptCheckTextLimit || removedTextRelative.Match(text) || c.scriptOnPath() {
		return true
	}
	for _, match := range removedTextVariable.FindAllSubmatch(text, -1) {
		if string(match[1]) != "HOME" {
			return true
		}
	}
	quoting := newRemovedTextQuoting(text)
	covered := 0
	for _, match := range removedTextPath.FindAllSubmatchIndex(text, -1) {
		if match[0] < covered {
			// Part of a quoted path already checked whole.
			continue
		}
		if depth+1 >= removedScriptCheckDepth {
			return true
		}
		mayRun, through := c.textPathMayRun(text, quoting, match, depth+1)
		if mayRun {
			return true
		}
		covered = through
	}
	return false
}

// removedLoadableImage reports whether file is machine code that the loader
// of goos runs itself: an ELF executable or shared object (Linux and the
// other Unix systems), a Mach-O executable, library or bundle, thin or
// universal (macOS), or a PE image (Windows). A program may run any path it
// holds; the check rules one out by the names in its bytes alone.
func removedLoadableImage(file io.ReaderAt, goos string) bool {
	switch goos {
	case "windows":
		_, err := pe.NewFile(file)
		return err == nil
	case "darwin", "ios":
		if thin, err := macho.NewFile(file); err == nil {
			return removedMachOLoadable(thin.Type)
		}
		fat, err := macho.NewFatFile(file)
		if err != nil || len(fat.Arches) == 0 {
			return false
		}
		for _, arch := range fat.Arches {
			if !removedMachOLoadable(arch.Type) {
				return false
			}
		}
		return true
	}
	image, err := elf.NewFile(file)
	return err == nil && (image.Type == elf.ET_EXEC || image.Type == elf.ET_DYN)
}

func removedMachOLoadable(t macho.Type) bool {
	return t == macho.TypeExec || t == macho.TypeDylib || t == macho.TypeBundle
}

// removedShells are the interpreters whose scripts the check reads.
var removedShells = map[string]bool{"sh": true, "bash": true, "dash": true, "zsh": true, "ksh": true, "mksh": true, "ash": true}

// removedScriptExtensions name scripts in a language other than the shell.
var removedScriptExtensions = map[string]bool{
	".py": true, ".pyw": true, ".js": true, ".mjs": true, ".cjs": true, ".ts": true, ".mts": true, ".cts": true,
	".rb": true, ".pl": true, ".pm": true, ".php": true, ".lua": true, ".tcl": true, ".r": true, ".ps1": true,
	".psm1": true, ".groovy": true, ".kts": true, ".swift": true, ".exs": true, ".jl": true, ".awk": true,
}

// removedShellText reports whether a text file is one the check can read: a
// shell script (its #! line runs sh, bash, dash, zsh, ksh, mksh or ash,
// directly or through env), or a file with no #! line whose name has no
// extension of another language (a config file, say). A script in another
// language may build the path it runs at run time (os.path.join, say), so
// it may run the script.
func removedShellText(path string, text []byte) bool {
	if !bytes.HasPrefix(text, []byte("#!")) {
		return !removedScriptExtensions[strings.ToLower(filepath.Ext(path))]
	}
	line, _, _ := bytes.Cut(text[2:], []byte("\n"))
	fields := strings.Fields(string(line))
	if len(fields) == 0 {
		return false
	}
	interpreter := filepath.Base(fields[0])
	if interpreter == "env" {
		interpreter = ""
		for _, field := range fields[1:] {
			if !strings.HasPrefix(field, "-") && !strings.Contains(field, "=") {
				interpreter = filepath.Base(field)
				break
			}
		}
	}
	return removedShells[interpreter]
}

// textPathMayRun reports whether a path a wrapper names (match, a
// removedTextPath match in text) may run the script. The pattern reads only
// plain characters, so a path counts only when it is a word of its own: one
// that goes on past what the pattern read (a blank inside its quotes, an
// escape, a quote that joins more text, a character outside the plain set)
// or that ends a longer word (a relative path such as lib/run, or
// "dir"/run) is a path the check cannot see, and may run the script. A path
// that starts a quoted string with a blank in it ("/tmp/audit dir/relay") is
// checked whole as well; when that path is there, the rest of the string is
// part of it (through is where the string ends, else 0). A list of paths
// (a:b, a,b, a=b) is checked part by part. In a comment the path is only
// read.
func (c *removedScriptCheck) textPathMayRun(text []byte, quoting removedTextQuoting, match []int, depth int) (mayRun bool, through int) {
	start, end := match[4], match[5]
	home := match[2] >= 0
	if home {
		start = match[2]
	}
	if !quoting.comment(start) {
		if !quoting.startsWord(text, start) {
			return true, 0
		}
		if !quoting.endsWord(text, start, end) {
			whole, closing, ok := quoting.quotedPath(text, start, c.home)
			if !ok || c.pathMayRun(whole, depth) {
				return true, 0
			}
			if _, err := os.Stat(whole); err == nil {
				through = closing
			}
		}
	}
	path := string(text[match[4]:match[5]])
	targets := []string{path}
	if parts := strings.FieldsFunc(path, func(r rune) bool { return r == ':' || r == ',' || r == '=' }); len(parts) > 1 {
		targets = append(targets, parts...)
	}
	for i, target := range targets {
		switch {
		case home && (i == 0 || i == 1):
			target = filepath.Join(c.home, target)
		case !strings.HasPrefix(target, "/"):
			continue
		}
		if c.pathMayRun(target, depth) {
			return true, 0
		}
	}
	return false, through
}

// removedTextQuoting is how a shell reads the quotes in a wrapper's text:
// for each byte, the quote it is in (' or ", the quote marks included), '#'
// in a comment (from a # that starts a word outside quotes to the end of
// the line) or '\\' for a byte a backslash escapes, else 0; and for each
// opening quote mark, where its string ends (-1: it does not).
type removedTextQuoting struct {
	state  []byte
	closes map[int]int
}

func newRemovedTextQuoting(text []byte) removedTextQuoting {
	q := removedTextQuoting{state: make([]byte, len(text)), closes: map[int]int{}}
	var quote byte
	open := -1
	for i := 0; i < len(text); i++ {
		ch := text[i]
		switch {
		case quote == 0 && ch == '#' && (i == 0 || q.state[i-1] == 0 && removedTextBreak(text[i-1])):
			for ; i < len(text) && text[i] != '\n'; i++ {
				q.state[i] = '#'
			}
		case quote != '\'' && ch == '\\' && i+1 < len(text):
			q.state[i] = quote
			i++
			q.state[i] = '\\'
		case quote == 0 && (ch == '\'' || ch == '"'):
			quote, open = ch, i
			q.state[i] = ch
			q.closes[i] = -1
		case quote != 0 && ch == quote:
			q.state[i] = quote
			q.closes[open] = i
			quote = 0
		default:
			q.state[i] = quote
		}
	}
	return q
}

// removedTextBreak reports whether a shell word ends before ch.
func removedTextBreak(ch byte) bool {
	return strings.IndexByte(" \t\r\n;&|()<>`", ch) >= 0
}

func (q removedTextQuoting) comment(i int) bool { return q.state[i] == '#' }

// delimiter reports whether text[i] is a quote mark that opens or closes a
// string (not one inside the other kind of quotes, nor an escaped one).
func (q removedTextQuoting) delimiter(text []byte, i int) bool {
	return (text[i] == '\'' || text[i] == '"') && q.state[i] == text[i]
}

// startsWord reports whether a path at start starts a word: what comes
// before it (past its quote marks, and the slashes of a URL or a doubled
// slash) is the start of the text, a blank, a shell break or one of = : , @
// ! [ { that comes before a path in an option, a list or a document.
func (q removedTextQuoting) startsWord(text []byte, start int) bool {
	i := start - 1
	for i >= 0 && text[i] == '/' && q.state[i] != '\\' {
		i--
	}
	for i >= 0 && q.delimiter(text, i) {
		i--
	}
	if i < 0 {
		return true
	}
	return q.state[i] != '\\' && (removedTextBreak(text[i]) || strings.IndexByte("=:,@![{", text[i]) >= 0)
}

// endsWord reports whether a path that ends at end (and starts at start)
// ends its word: what comes after it (past its trailing slashes and its
// closing quote marks) is the end of the text, a shell break, or, after a
// closing quote, one of , ] } : as in a list or a document. Inside a quoted
// string a blank or a shell break ends it too ("run /x y"), but not when the
// path starts the string: then the string is the path.
func (q removedTextQuoting) endsWord(text []byte, start, end int) bool {
	i := end
	for i < len(text) && text[i] == '/' {
		i++
	}
	closed := false
	for i < len(text) && q.delimiter(text, i) {
		i++
		closed = true
	}
	switch {
	case i >= len(text):
		return true
	case q.state[i] == '\\':
		return false
	case q.state[i] != 0:
		_, startsString := q.closes[start-1]
		return !closed && !startsString && removedTextBreak(text[i])
	case text[i] == '\\':
		return false
	}
	return removedTextBreak(text[i]) || closed && strings.IndexByte(",]}:", text[i]) >= 0
}

// quotedPath returns the whole quoted string a path at start opens
// ("/tmp/audit dir/relay") and where it ends, when the check can read it: a
// leading $HOME, ${HOME} or ~ is the user's home, it holds no other $, no `
// and no backslash, and no text is joined to it after its closing quote.
func (q removedTextQuoting) quotedPath(text []byte, start int, home string) (string, int, bool) {
	open := start - 1
	if open < 0 {
		return "", 0, false
	}
	closing, ok := q.closes[open]
	if !ok || closing < 0 {
		return "", 0, false
	}
	whole := string(text[open+1 : closing])
	if strings.ContainsAny(whole, "`\\") {
		return "", 0, false
	}
	for _, prefix := range []string{"$HOME/", "${HOME}/", "~/"} {
		if strings.HasPrefix(whole, prefix) {
			whole = filepath.Join(home, whole[len(prefix)-1:])
			break
		}
	}
	if strings.Contains(whole, "$") || !filepath.IsAbs(whole) {
		return "", 0, false
	}
	if next := closing + 1; next < len(text) && !removedTextBreak(text[next]) && strings.IndexByte(",]}:", text[next]) < 0 {
		return "", 0, false
	}
	return filepath.Clean(whole), closing, true
}

// scriptOnPath reports whether a directory a command may be found in holds
// the script: the gateway's PATH, ~/bin, ~/.local/bin, /usr/local/bin and
// /opt/homebrew/bin. A directory it cannot list counts as holding it.
func (c *removedScriptCheck) scriptOnPath() bool {
	if c.onPath != nil {
		return *c.onPath
	}
	dirs := append(filepath.SplitList(os.Getenv("PATH")),
		filepath.Join(c.home, "bin"), filepath.Join(c.home, ".local", "bin"), "/usr/local/bin", "/opt/homebrew/bin")
	found := false
	for _, dir := range uniqueNonEmptyStrings(dirs) {
		if info, err := os.Stat(dir); err != nil || !info.IsDir() || !filepath.IsAbs(dir) {
			continue
		}
		if c.holdsScript(dir) {
			found = true
			break
		}
	}
	c.onPath = &found
	return found
}

// holdsScript reports whether dir holds the script under any name; a
// directory it cannot list counts as holding it.
func (c *removedScriptCheck) holdsScript(dir string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) > removedScriptCheckDirEntries {
		return true
	}
	for _, entry := range entries {
		if info, err := os.Stat(filepath.Join(dir, entry.Name())); err == nil && os.SameFile(info, c.script) {
			return true
		}
	}
	return false
}

// addHookScript plans DefenseClaw's hook script: a script exactly as setup
// wrote it (its digest in the hook contract lock) becomes the disabled
// tombstone, so an OpenHands conversation that loaded the hook before
// teardown keeps working. A script DefenseClaw cannot prove it wrote (it
// changed, there is no digest, or it is a link or not a regular file), or one
// a hooks file in checked may still run once the cleanup is done, is left for
// the user with those hooks files, and so is everything else: a tombstone
// exits 0, so a hook that still ran it would allow everything with no
// warning.
func (c removedOpenHandsConnector) addHookScript(p *removedCleanupPlan, opts SetupOpts, checked []string) error {
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
	}
	mayRun := c.hooksThatMayRunScript(p, opts, checked, script, info)
	for _, hooks := range mayRun {
		if hooks.restored {
			p.leave(hooks.path, "the copy DefenseClaw saved before its setup, which the cleanup puts back, has a hook that may run "+script+" through a link, a wrapper or another path",
				"remove the hook entries whose command runs "+script+", and every hook that runs it through a link or a wrapper")
			continue
		}
		p.leave(hooks.path, "DefenseClaw cannot prove that none of its hooks runs "+script+" through a link, a wrapper or another path",
			"remove every hook that runs "+script+", directly or through a link or a wrapper")
	}
	entry, err := LoadHookContractLockEntryForMode(opts.DataDir, c.name, opts.ManagedEnterprise)
	if err != nil {
		p.leave(script, fmt.Sprintf("DefenseClaw cannot read its record of the script: %v", err), step)
		return nil
	}
	switch want := entry.HookScriptDigests[removedOpenHandsHookScript]; {
	case want == "":
		p.leave(script, "DefenseClaw has no record of writing it", step)
	case !strings.EqualFold(strings.TrimPrefix(want, "sha256:"), sha256Hex(data)):
		p.leave(script, "it changed after DefenseClaw wrote it", step)
	case len(mayRun) > 0:
		p.leave(script, "an OpenHands hooks file DefenseClaw cannot check may still run it", step)
	default:
		p.files = append(p.files, removedFile{
			path: script, data: data, mode: info.Mode().Perm(),
			restore: []byte(disabledHookTombstone("OpenHands")), restoreMode: 0o700,
		})
	}
	return nil
}

// removedOpenHandsTombstone reports whether data is the disabled tombstone an
// OpenHands teardown wrote: "OpenHands" in 1.0.4, "openhands" before.
func removedOpenHandsTombstone(data []byte) bool {
	return string(data) == disabledHookTombstone("OpenHands") || string(data) == disabledHookTombstone(removedOpenHandsID)
}

// Teardown puts back the hooks.json an older release's setup found and turns
// DefenseClaw's hook script into the disabled tombstone, when each is exactly
// as setup left it (see the file comment).
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
