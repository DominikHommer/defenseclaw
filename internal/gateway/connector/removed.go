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
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
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
	if home := strings.TrimSpace(opts.ConfigHome); home != "" && filepath.IsAbs(home) {
		paths = append(paths, filepath.Join(filepath.Clean(home), "hooks.json"))
	} else {
		paths = append(paths, homePath(".openhands", "hooks.json"))
	}
	if entry, err := LoadHookContractLockEntryForMode(opts.DataDir, c.name, opts.ManagedEnterprise); err == nil {
		for _, path := range entry.Locations.HookConfigPaths {
			if filepath.IsAbs(path) && filepath.Base(path) == "hooks.json" {
				paths = append(paths, filepath.Clean(path))
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
// other word is a plain option (whose value is plain or an absolute path), a
// number or an absolute path. A command found on
// PATH, a relative path or any shell syntax may run anything, so it may run
// the script. A path in the command may run the script when it names
// DefenseClaw or the script, is the script (through links or as a hard link),
// is a directory that holds the script or names DefenseClaw, or is a file
// whose bytes name either. A text file (a wrapper) may also run it through
// the paths it names, checked the same way a few levels deep, and through
// what the check cannot follow: a relative path or cd, a variable or a
// command substitution in a path, or a command found on PATH while a PATH
// directory holds the script.
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
	// removedOption is an option word the check can rule out: a plain
	// name, then = and a value that is plain or an absolute path (group 1).
	removedOption = regexp.MustCompile(`^--?[A-Za-z0-9][A-Za-z0-9_.-]*(?:=([A-Za-z0-9_.:,@%+-]*|/[A-Za-z0-9_./:,@%+ -]*))?$`)
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
			return key != "matcher" && key != "type" && c.commandMayRun(v)
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
	if strings.Trim(command, " \t0123456789") == "" {
		// Blank, or a number (a timeout written as a string).
		return false
	}
	words, ok := removedPlainWords(command)
	if !ok || len(words) == 0 {
		return true
	}
	for i, word := range words {
		if c.names([]byte(word)) {
			return true
		}
		path := word
		if i > 0 {
			switch {
			case strings.HasPrefix(word, "-"):
				// An option is a plain name, with a plain or absolute
				// value; anything else (-c code, say) may run anything.
				match := removedOption.FindStringSubmatch(word)
				if match == nil {
					return true
				}
				if !strings.HasPrefix(match[1], "/") {
					continue
				}
				path = match[1]
			case strings.Trim(word, "0123456789") == "":
				continue
			}
		}
		if !filepath.IsAbs(path) || c.pathMayRun(path, 0) {
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
	binary := false
	chunk := make([]byte, 64<<10)
	for {
		n, err := file.Read(chunk)
		if n > 0 {
			binary = binary || bytes.IndexByte(chunk[:n], 0) >= 0
			if !binary && len(text) <= removedScriptCheckTextLimit {
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
	if binary {
		return false
	}
	if len(text) > removedScriptCheckTextLimit || removedTextRelative.Match(text) || c.scriptOnPath() {
		return true
	}
	for _, match := range removedTextVariable.FindAllSubmatch(text, -1) {
		if string(match[1]) != "HOME" {
			return true
		}
	}
	for _, match := range removedTextPath.FindAllSubmatch(text, -1) {
		target := string(match[2])
		if len(match[1]) > 0 {
			target = filepath.Join(c.home, target)
		}
		if depth+1 >= removedScriptCheckDepth || c.pathMayRun(target, depth+1) {
			return true
		}
	}
	return false
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
// lock says setup wrote. All of them are checked, whichever is given: they are
// only read, and one that still names the module keeps every file in place.
func (c removedOmnigentConnector) configPaths(opts SetupOpts) []string {
	var paths []string
	if home := strings.TrimSpace(opts.ConfigHome); home != "" && filepath.IsAbs(home) {
		paths = append(paths, filepath.Join(filepath.Clean(home), "config.yaml"))
	}
	paths = append(paths, removedOmnigentExplicitConfig())
	if home := strings.TrimSpace(os.Getenv("OMNIGENT_CONFIG_HOME")); home != "" && filepath.IsAbs(home) {
		paths = append(paths, filepath.Join(filepath.Clean(home), "config.yaml"))
	}
	paths = append(paths, homePath(".omnigent", "config.yaml"))
	if entry, err := LoadHookContractLockEntryForMode(opts.DataDir, c.name, opts.ManagedEnterprise); err == nil {
		for _, path := range entry.Locations.HookConfigPaths {
			switch strings.ToLower(filepath.Ext(path)) {
			case ".yaml", ".yml":
				if filepath.IsAbs(path) {
					paths = append(paths, filepath.Clean(path))
				}
			}
		}
	}
	return uniqueNonEmptyStrings(paths)
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
