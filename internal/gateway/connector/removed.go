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
// backup record). Such a file is put back the way setup found it, or removed
// when setup created it. Any other file that still names DefenseClaw (the
// user changed it, there is no record, or it cannot be read) is left byte for
// byte, and then nothing at all is changed: the steps to finish by hand are
// recorded, which status and doctor show, and printed once. Nothing is parsed
// and written back.

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
	if err := atomicWriteFile(path, append(data, '\n'), 0o600); err != nil {
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
	// ownedFile: the whole file is DefenseClaw's (the policy module, its
	// .pth file). When the copy setup found holds DefenseClaw's entry too
	// (an earlier setup, GAP-1926), such a file is removed; the agent's own
	// config is left for the user instead.
	ownedFile bool
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
		names, err := kind.names(record.PristineBytes)
		switch {
		case (err != nil || names) && kind.ownedFile:
		case err != nil || names:
			p.leave(path, "the copy DefenseClaw saved before its setup names DefenseClaw too", kind.step)
			return path, nil
		default:
			file.restore = record.PristineBytes
			if file.restore == nil {
				file.restore = []byte{}
			}
			file.restoreMode = os.FileMode(record.Mode)
			if file.restoreMode == 0 {
				file.restoreMode = 0o600
			}
		}
	}
	p.files = append(p.files, file)
	return path, nil
}

// addUnrecorded plans a file no backup record names: it is left for the user
// when it still names DefenseClaw.
func (p *removedCleanupPlan) addUnrecorded(path string, kind removedFileKind) error {
	data, info, err := readRemovedFile(path)
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
func (p *removedCleanupPlan) apply() error {
	for i, file := range p.files {
		if err := file.apply(); err != nil {
			if rollbackErr := p.rollback(i); rollbackErr != nil {
				return errors.Join(err, rollbackErr)
			}
			return fmt.Errorf("%w; nothing was changed", err)
		}
	}
	return nil
}

func (f removedFile) apply() error {
	data, info, err := readRemovedFile(f.path)
	if err != nil {
		return fmt.Errorf("read %s: %w", f.path, err)
	}
	if info == nil || !bytes.Equal(data, f.data) {
		return fmt.Errorf("%s changed during cleanup", f.path)
	}
	if f.restore == nil {
		if err := os.Remove(f.path); err != nil {
			return fmt.Errorf("remove %s: %w", f.path, err)
		}
		return nil
	}
	if err := atomicWriteFile(f.path, f.restore, f.restoreMode); err != nil {
		return newManagedRestoreError(f.path, err)
	}
	return nil
}

// rollback puts back the first n files as the plan read them.
func (p *removedCleanupPlan) rollback(n int) error {
	var errs []error
	for i := n - 1; i >= 0; i-- {
		file := p.files[i]
		if err := atomicWriteFile(file.path, file.data, file.mode); err != nil {
			errs = append(errs, fmt.Errorf("could not put back %s: %w", file.path, err))
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
// maintenance passes, else the user-global default.
func (removedOpenHandsConnector) hooksPaths(opts SetupOpts) []string {
	if home := strings.TrimSpace(opts.ConfigHome); home != "" && filepath.IsAbs(home) {
		return []string{filepath.Join(filepath.Clean(home), "hooks.json")}
	}
	return []string{homePath(".openhands", "hooks.json")}
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
	return p, nil
}

// Teardown puts back the hooks.json an older release's setup found when the
// file is exactly as setup left it (see the file comment). Once no hooks file
// runs DefenseClaw's hook script, that script becomes the disabled tombstone,
// so an OpenHands conversation that loaded it before teardown keeps working.
// While a hooks file still runs it, the script stays as it is.
func (c removedOpenHandsConnector) Teardown(_ context.Context, opts SetupOpts) error {
	return c.teardown(opts, c.plan, []string{"config"}, func() error {
		script := c.hookScript(opts)
		if _, err := os.Lstat(script); err == nil {
			if err := writeDisabledHookTombstone(opts, removedOpenHandsHookScript, "OpenHands"); err != nil {
				return fmt.Errorf("disabled hook tombstone: %w", err)
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect %s: %w", script, err)
		}
		record := filepath.Join(opts.DataDir, "hooks", hookConfigSidecarName+"."+c.name)
		if err := os.Remove(record); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove %s: %w", record, err)
		}
		return nil
	})
}

// VerifyClean fails while a hooks file is still as DefenseClaw wrote it, or
// still runs DefenseClaw's hook script without a recorded manual step.
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

// configPaths are the OmniGent config.yaml files an older release may have
// patched besides the one its setup backup names: the explicit config home
// native maintenance passes, else OMNIGENT_CONFIG_HOME and ~/.omnigent.
func (removedOmnigentConnector) configPaths(opts SetupOpts) []string {
	if home := strings.TrimSpace(opts.ConfigHome); home != "" && filepath.IsAbs(home) {
		return []string{filepath.Join(filepath.Clean(home), "config.yaml")}
	}
	var paths []string
	if home := strings.TrimSpace(os.Getenv("OMNIGENT_CONFIG_HOME")); home != "" && filepath.IsAbs(home) {
		paths = append(paths, filepath.Join(filepath.Clean(home), "config.yaml"))
	}
	return uniqueNonEmptyStrings(append(paths, homePath(".omnigent", "config.yaml")))
}

var removedOmnigentConfigKind = removedFileKind{
	names: removedOmnigentConfigNames,
	step: "remove " + removedOmnigentModuleName + " from policy_modules, and the policy whose handler starts with " +
		removedOmnigentModuleName + ".",
}

// The policy module lives in DefenseClaw's hook directory under DefenseClaw's
// name, so any bytes there are DefenseClaw's module.
var removedOmnigentModuleKind = removedFileKind{
	names:     func([]byte) (bool, error) { return true, nil },
	ownedFile: true,
	step:      "delete it once config.yaml no longer names " + removedOmnigentModuleName,
}

func removedOmnigentImportPathKind(hookDir string) removedFileKind {
	return removedFileKind{
		names: func(data []byte) (bool, error) {
			for _, line := range strings.Split(string(data), "\n") {
				if entry := strings.TrimSpace(line); entry != "" && sameManagedTargetPath(entry, hookDir) {
					return true, nil
				}
			}
			return false, nil
		},
		ownedFile: true,
		step:      "delete the line " + hookDir + " once config.yaml no longer names " + removedOmnigentModuleName,
	}
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
	if _, err := p.addRecorded(opts.DataDir, c.name, "pth", removedOmnigentImportPathKind(filepath.Dir(own))); err != nil {
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

// Teardown puts back config.yaml and the .pth file the way an older
// release's setup found them, and removes its policy module, when each is
// exactly as setup left it (see the file comment).
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
