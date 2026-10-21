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
// teardown-only connectors remove exactly what that release wrote, so the
// upgrade (gateway boot), `defenseclaw uninstall` and native Windows Setup
// leave the agent working without DefenseClaw. Delete this file in 1.1.

import (
	"context"
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

// --- OpenHands ---

type removedOpenHandsConnector struct{ removedConnectorBase }

func (removedOpenHandsConnector) hookScript(opts SetupOpts) string {
	return filepath.Join(opts.DataDir, "hooks", removedOpenHandsHookScript)
}

// hooksPaths are the hooks.json files an older release may have written:
// the one its setup backup names (a pinned workspace too), the explicit
// config home native maintenance passes, and the user-global default.
func (c removedOpenHandsConnector) hooksPaths(opts SetupOpts) []string {
	var paths []string
	if home := strings.TrimSpace(opts.ConfigHome); home != "" && filepath.IsAbs(home) {
		paths = append(paths, filepath.Join(filepath.Clean(home), "hooks.json"))
	} else {
		paths = append(paths, homePath(".openhands", "hooks.json"))
	}
	paths = append([]string{managedFileBackupTargetPath(opts.DataDir, c.name, "config", "")}, paths...)
	return uniqueNonEmptyStrings(paths)
}

// Teardown restores the hooks.json an older release backed up when it is
// unchanged since then, and in every case removes DefenseClaw's hook entries
// (a backup taken after a rollback holds them too, GAP-1926). Hooks from
// other tools stay. The hook script becomes the disabled tombstone, so an
// OpenHands conversation that loaded it before teardown keeps working.
func (c removedOpenHandsConnector) Teardown(_ context.Context, opts SetupOpts) error {
	if strings.TrimSpace(opts.DataDir) == "" {
		return errors.New("openhands cleanup: empty data directory")
	}
	script := c.hookScript(opts)
	var errs []error
	backupTarget := managedFileBackupTargetPath(opts.DataDir, c.name, "config", "")
	if backupTarget != "" {
		if _, err := restoreManagedFileBackupIfUnchanged(opts.DataDir, c.name, "config", backupTarget); err != nil {
			errs = append(errs, fmt.Errorf("openhands cleanup: %s", restoreBackupFailure(err)))
		}
	}
	for _, path := range c.hooksPaths(opts) {
		if err := removeRemovedOpenHandsHooks(path, script); err != nil {
			errs = append(errs, fmt.Errorf("openhands cleanup %s: %w", path, err))
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	if err := c.VerifyClean(opts); err != nil {
		return err
	}
	discardManagedFileBackup(opts.DataDir, c.name, "config")
	if _, err := os.Lstat(script); err == nil {
		if err := writeDisabledHookTombstone(opts, removedOpenHandsHookScript, "OpenHands"); err != nil {
			return fmt.Errorf("openhands cleanup: disabled hook tombstone: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("openhands cleanup: inspect %s: %w", script, err)
	}
	record := filepath.Join(opts.DataDir, "hooks", hookConfigSidecarName+"."+c.name)
	if err := os.Remove(record); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("openhands cleanup: remove %s: %w", record, err)
	}
	return c.removeCredentials(opts.DataDir)
}

// VerifyClean fails while an OpenHands hooks file still runs DefenseClaw's
// hook script.
func (c removedOpenHandsConnector) VerifyClean(opts SetupOpts) error {
	script := c.hookScript(opts)
	for _, path := range c.hooksPaths(opts) {
		if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
			continue
		}
		cfg, err := readJSONObject(path)
		if err != nil {
			return fmt.Errorf("openhands cleanup could not read %s: %w", path, err)
		}
		if containsHookScript(cfg, script) {
			return fmt.Errorf("openhands cleanup incomplete: %s still runs %s", path, script)
		}
	}
	return nil
}

// removeRemovedOpenHandsHooks removes DefenseClaw's command hooks from an
// OpenHands hooks.json ({"pre_tool_use": [{"matcher": "*", "hooks": [...]}],
// ...}) and the matcher groups that held only them. A missing file stays
// missing; a file without DefenseClaw's hooks is not rewritten.
func removeRemovedOpenHandsHooks(path, hookScript string) error {
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	cfg, err := readJSONObject(path)
	if err != nil {
		return err
	}
	if !containsHookScript(cfg, hookScript) {
		return nil
	}
	pruned, _ := removeHookScriptReferences(cfg, hookScript).(map[string]interface{})
	if pruned == nil {
		pruned = map[string]interface{}{}
	}
	pruneEmptiedMatcherGroups(cfg, pruned)
	return writeJSONObject(path, pruned)
}

// pruneEmptiedMatcherGroups removes a matcher group whose hook list the
// cleanup emptied, and an event whose groups all went. Groups that were
// already empty, and groups with other fields, are the operator's and stay.
func pruneEmptiedMatcherGroups(before, after map[string]interface{}) {
	for event, raw := range after {
		groups, ok := raw.([]interface{})
		oldGroups, oldOK := before[event].([]interface{})
		if !ok || !oldOK {
			continue
		}
		remaining := make([]interface{}, 0, len(groups))
		for i, item := range groups {
			group, groupOK := item.(map[string]interface{})
			if groupOK && i < len(oldGroups) {
				if oldGroup, ok := oldGroups[i].(map[string]interface{}); ok {
					oldHooks, oldOK := oldGroup["hooks"].([]interface{})
					newHooks, newOK := group["hooks"].([]interface{})
					if oldOK && newOK && len(oldHooks) > 0 && len(newHooks) == 0 && matcherOnlyHookGroup(group) {
						continue
					}
				}
			}
			remaining = append(remaining, item)
		}
		if len(oldGroups) > 0 && len(remaining) == 0 {
			delete(after, event)
		} else {
			after[event] = remaining
		}
	}
}

func matcherOnlyHookGroup(group map[string]interface{}) bool {
	if _, ok := group["matcher"]; !ok {
		return false
	}
	for key := range group {
		if key != "matcher" && key != "hooks" {
			return false
		}
	}
	return true
}

// --- OmniGent ---

type removedOmnigentConnector struct{ removedConnectorBase }

func (removedOmnigentConnector) modulePath(opts SetupOpts) string {
	return filepath.Join(opts.DataDir, "hooks", removedOmnigentModuleName+".py")
}

// configPaths are the OmniGent config.yaml files an older release may have
// patched: the one its setup backup names, the explicit config home native
// maintenance passes (else OMNIGENT_CONFIG_HOME), and ~/.omnigent.
func (c removedOmnigentConnector) configPaths(opts SetupOpts) []string {
	paths := []string{managedFileBackupTargetPath(opts.DataDir, c.name, "config", "")}
	if home := strings.TrimSpace(opts.ConfigHome); home != "" && filepath.IsAbs(home) {
		return uniqueNonEmptyStrings(append(paths, filepath.Join(filepath.Clean(home), "config.yaml")))
	}
	if home := strings.TrimSpace(os.Getenv("OMNIGENT_CONFIG_HOME")); home != "" && filepath.IsAbs(home) {
		paths = append(paths, filepath.Join(filepath.Clean(home), "config.yaml"))
	}
	return uniqueNonEmptyStrings(append(paths, homePath(".omnigent", "config.yaml")))
}

// Teardown restores config.yaml and the .pth file an older release backed up
// when they are unchanged since then. Otherwise it removes only DefenseClaw's
// policy entries from config.yaml and only the line naming DefenseClaw's hook
// directory from the .pth file. The policy module goes last, only once every
// config.yaml is clean, and only when its bytes are provably DefenseClaw's
// (inspectModule); a module the user changed stays and is reported, because
// nothing loads it once config.yaml and the .pth file no longer name it.
func (c removedOmnigentConnector) Teardown(_ context.Context, opts SetupOpts) error {
	if strings.TrimSpace(opts.DataDir) == "" {
		return errors.New("omnigent cleanup: empty data directory")
	}
	moduleDir := filepath.Dir(c.modulePath(opts))
	var errs []error
	for _, logical := range []string{"config", "pth"} {
		path := managedFileBackupTargetPath(opts.DataDir, c.name, logical, "")
		if path == "" {
			continue
		}
		if _, err := restoreManagedFileBackupIfUnchanged(opts.DataDir, c.name, logical, path); err != nil {
			errs = append(errs, fmt.Errorf("omnigent cleanup %s: %s", logical, restoreBackupFailure(err)))
			continue
		}
		if logical == "pth" {
			if err := removeRemovedOmnigentImportPath(path, moduleDir); err != nil {
				errs = append(errs, fmt.Errorf("omnigent cleanup: %w", err))
			}
		}
	}
	for _, path := range c.configPaths(opts) {
		if err := removeRemovedOmnigentConfigEntries(path); err != nil {
			errs = append(errs, fmt.Errorf("omnigent cleanup %s: %w", path, err))
		}
	}
	if len(errs) > 0 {
		// The module stays while a config.yaml may still name it: OmniGent
		// fails to start when a policy it loads cannot be imported.
		return errors.Join(errs...)
	}
	if err := c.removeModule(opts); err != nil {
		return fmt.Errorf("omnigent cleanup: %w", err)
	}
	if err := c.VerifyClean(opts); err != nil {
		return err
	}
	// The module record stays while a module the user changed is kept, so
	// the next run still knows those bytes are not DefenseClaw's.
	for _, logical := range []string{"config", "pth"} {
		discardManagedFileBackup(opts.DataDir, c.name, logical)
	}
	return c.removeCredentials(opts.DataDir)
}

// VerifyClean fails while an OmniGent config still loads DefenseClaw's
// policy (by the rule cleanup removes it), DefenseClaw's own policy module
// remains, or the recorded .pth file still puts DefenseClaw's hook directory
// on OmniGent's import path. A policy, module or import line that belongs to
// someone else is not DefenseClaw's state and does not fail it.
func (c removedOmnigentConnector) VerifyClean(opts SetupOpts) error {
	for _, path := range c.configPaths(opts) {
		loads, err := removedOmnigentConfigLoadsPolicy(path)
		if err != nil {
			return fmt.Errorf("omnigent cleanup could not read %s: %w", path, err)
		}
		if loads {
			return fmt.Errorf("omnigent cleanup incomplete: %s still loads DefenseClaw's policy", path)
		}
	}
	module, err := c.inspectModule(opts)
	if err != nil {
		return fmt.Errorf("omnigent cleanup: %w", err)
	}
	if module.owned {
		return fmt.Errorf("omnigent cleanup incomplete: %s remains", module.path)
	}
	if pth := managedFileBackupTargetPath(opts.DataDir, c.name, "pth", ""); pth != "" {
		names, err := removedOmnigentImportPathNamesHooks(pth, filepath.Dir(c.modulePath(opts)))
		if err != nil {
			return fmt.Errorf("omnigent cleanup: %w", err)
		}
		if names {
			return fmt.Errorf("omnigent cleanup incomplete: %s still names DefenseClaw's hook directory", pth)
		}
	}
	return nil
}

// removedOmnigentPolicyMarker is the first line of every policy module an
// older release rendered (0.8.x and 1.0.x).
const removedOmnigentPolicyMarker = "# defenseclaw-managed-policy v1"

// removedConnectorNotices receives what a removed connector's teardown keeps
// on purpose because it holds the user's changes.
var removedConnectorNotices io.Writer = os.Stderr

// removedOmnigentModule is the policy module teardown found.
type removedOmnigentModule struct {
	path   string
	record *managedFileBackup
	data   []byte
	exists bool
	// owned: the current bytes are DefenseClaw's, so teardown may remove
	// them (or put back the file setup replaced).
	owned bool
	// pristine: the file is the one setup found before it wrote the
	// module, so it was never DefenseClaw's.
	pristine bool
}

// inspectModule finds the policy module and decides whose bytes it holds.
// They are DefenseClaw's when they are what the backup record says setup
// last wrote, or, when no write was recorded, when the file is in
// DefenseClaw's own hook directory and starts with the rendered module's
// marker. A module that changed after the recorded write holds the user's
// edits and is not DefenseClaw's.
func (c removedOmnigentConnector) inspectModule(opts SetupOpts) (removedOmnigentModule, error) {
	own := c.modulePath(opts)
	module := removedOmnigentModule{path: own}
	recordPath := managedFileBackupPath(opts.DataDir, c.name, "module")
	record, err := loadManagedFileBackupPath(recordPath)
	switch {
	case err == nil:
		path, err := validateManagedFileBackupTarget(record, c.name, "module", record.Path)
		if err != nil {
			return module, fmt.Errorf("module backup %s: %w", recordPath, err)
		}
		module.path, module.record = path, &record
	case !errors.Is(err, os.ErrNotExist):
		return module, fmt.Errorf("module backup %s: %w", recordPath, err)
	}
	data, info, err := readManagedTarget(module.path)
	if err != nil || info == nil {
		return module, err
	}
	module.data, module.exists = data, true
	sum := sha256Hex(data)
	rendered := sameManagedTargetPath(module.path, own) && removedOmnigentRenderedModule(data)
	switch {
	case module.record != nil && module.record.PostSHA256 != "":
		switch {
		case sum == module.record.PostSHA256:
			module.owned = true
		case module.record.Existed && sum == module.record.PristineSHA256:
			// The file setup found is back. It is DefenseClaw's only
			// when it is itself an older rendering in the hook directory.
			module.pristine, module.owned = true, rendered
		}
	case module.record != nil && module.record.Existed && sum == module.record.PristineSHA256:
		module.pristine, module.owned = true, rendered
	default:
		// No recorded write to compare against.
		module.owned = rendered
	}
	return module, nil
}

func removedOmnigentRenderedModule(data []byte) bool {
	first, _, _ := strings.Cut(string(data), "\n")
	return strings.TrimSpace(first) == removedOmnigentPolicyMarker
}

// removeModule removes DefenseClaw's policy module, or puts back the file
// setup replaced when that file was not itself DefenseClaw's. A module the
// user changed is kept, with its record, and reported.
func (c removedOmnigentConnector) removeModule(opts SetupOpts) error {
	module, err := c.inspectModule(opts)
	if err != nil {
		return err
	}
	switch {
	case !module.exists:
	case module.owned:
		if r := module.record; r != nil && r.Existed && !module.pristine && !removedOmnigentRenderedModule(r.PristineBytes) {
			mode := os.FileMode(r.Mode)
			if mode == 0 {
				mode = 0o600
			}
			if err := atomicWriteFile(module.path, r.PristineBytes, mode); err != nil {
				return newManagedRestoreError(module.path, err)
			}
		} else if err := os.Remove(module.path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove %s: %w", module.path, err)
		}
	case module.pristine:
		// The user's own file, as setup found it: nothing to keep a record for.
	case module.record == nil:
		// Not DefenseClaw's rendering and no record of a DefenseClaw write:
		// a file DefenseClaw never wrote (or the user's module that an
		// earlier teardown put back) is left alone.
		return nil
	default:
		fmt.Fprintf(removedConnectorNotices,
			"[omnigent] kept %s: it changed after DefenseClaw wrote it, so it may hold your edits. OmniGent no longer loads it; delete it if you do not need it.\n",
			module.path)
		return nil
	}
	discardManagedFileBackup(opts.DataDir, c.name, "module")
	return nil
}

// removeRemovedOmnigentImportPath removes the line naming DefenseClaw's hook
// directory from a .pth file an older release wrote. Other lines are the
// user's and stay; a file left without entries is removed.
func removeRemovedOmnigentImportPath(path, hookDir string) error {
	data, info, err := readManagedTarget(path)
	if err != nil || info == nil {
		return err
	}
	var kept []string
	removed, entries := false, false
	for _, line := range strings.SplitAfter(string(data), "\n") {
		if removedOmnigentImportLine(line, hookDir) {
			removed = true
			continue
		}
		kept = append(kept, line)
		entries = entries || strings.TrimSpace(line) != ""
	}
	if !removed {
		return nil
	}
	if !entries {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove %s: %w", path, err)
		}
		return nil
	}
	return atomicWriteFile(path, []byte(strings.Join(kept, "")), info.Mode().Perm())
}

// removedOmnigentImportPathNamesHooks reports whether a .pth file still puts
// DefenseClaw's hook directory on the import path.
func removedOmnigentImportPathNamesHooks(path, hookDir string) (bool, error) {
	data, info, err := readManagedTarget(path)
	if err != nil || info == nil {
		return false, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if removedOmnigentImportLine(line, hookDir) {
			return true, nil
		}
	}
	return false, nil
}

func removedOmnigentImportLine(line, hookDir string) bool {
	entry := strings.TrimSpace(line)
	return entry != "" && sameManagedTargetPath(entry, hookDir)
}

// removedOmnigentConfigLoadsPolicy reports whether an OmniGent config still
// names DefenseClaw's module or policy, by the rule cleanup removes them:
// the parsed policy_modules entry, and a policy whose handler is in
// DefenseClaw's module, followed through YAML aliases and merge keys.
// Comments, other modules and another tool's policy under DefenseClaw's old
// key do not count.
func removedOmnigentConfigLoadsPolicy(path string) (bool, error) {
	document, err := readRemovedOmnigentConfig(path)
	if err != nil || document == nil {
		return false, err
	}
	return removedOmnigentDocumentLoadsPolicy(document), nil
}

// removedOmnigentDocumentLoadsPolicy applies both readings of a parsed
// config: the decoded value OmniGent's YAML loader would see (aliases and
// merge keys resolved), and the node rule cleanup uses, which also sees every
// copy of a duplicated key. It consumes document.
func removedOmnigentDocumentLoadsPolicy(document *yaml.Node) bool {
	var value interface{}
	if err := document.Decode(&value); err == nil && removedOmnigentValueLoadsPolicy(value) {
		return true
	}
	return pruneRemovedOmnigentConfig(document.Content[0])
}

// removeRemovedOmnigentConfigEntries removes DefenseClaw's module from
// policy_modules and every policy whose handler is in DefenseClaw's module
// from policies; every other key and entry stays. An alias left naming a
// removed anchor is replaced by a copy of what it named, and the result must
// parse and no longer load DefenseClaw's policy before it replaces the file.
func removeRemovedOmnigentConfigEntries(path string) error {
	document, err := readRemovedOmnigentConfig(path)
	if err != nil || document == nil {
		return err
	}
	var before interface{}
	decodable := document.Decode(&before) == nil
	if !pruneRemovedOmnigentConfig(document.Content[0]) {
		if decodable && removedOmnigentValueLoadsPolicy(before) {
			return fmt.Errorf("%s %s", path, removedOmnigentUneditable)
		}
		return nil
	}
	if err := expandDanglingYAMLAliases(document); err != nil {
		return fmt.Errorf("%s: %w; remove DefenseClaw's entries by hand", path, err)
	}
	updated, err := yaml.Marshal(document)
	if err != nil {
		return err
	}
	var check yaml.Node
	if err := yaml.Unmarshal(updated, &check); err != nil {
		return fmt.Errorf("%s: the cleaned config would not parse (%v); remove DefenseClaw's entries by hand", path, err)
	}
	if len(check.Content) != 1 || check.Content[0].Kind != yaml.MappingNode {
		return fmt.Errorf("%s: the cleaned config would not be a mapping; remove DefenseClaw's entries by hand", path)
	}
	var after interface{}
	if decodable {
		if err := check.Decode(&after); err != nil {
			return fmt.Errorf("%s: the cleaned config would not load (%v); remove DefenseClaw's entries by hand", path, err)
		}
	}
	if removedOmnigentDocumentLoadsPolicy(&check) {
		return fmt.Errorf("%s %s", path, removedOmnigentUneditable)
	}
	return atomicWriteFile(path, updated, 0o600)
}

const removedOmnigentUneditable = "still loads DefenseClaw's policy through YAML cleanup cannot edit safely (a merge key); remove DefenseClaw's entries by hand"

// readRemovedOmnigentConfig parses an OmniGent config that mentions
// DefenseClaw's module into a document whose only child is the top-level
// mapping. A missing or empty file, or one that never names the module
// (every entry an older release wrote does), returns nil: there is nothing of
// DefenseClaw's in it, even if another tool's YAML does not parse.
func readRemovedOmnigentConfig(path string) (*yaml.Node, error) {
	data, err := readHookConfigFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !strings.Contains(string(data), removedOmnigentModuleName) {
		return nil, nil
	}
	var document yaml.Node
	if err := yaml.Unmarshal(data, &document); err != nil {
		return nil, fmt.Errorf("parse YAML %s: %w", path, err)
	}
	if len(document.Content) == 0 {
		return nil, nil
	}
	if len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return nil, fmt.Errorf("parse YAML %s: expected a mapping", path)
	}
	return &document, nil
}

// pruneRemovedOmnigentConfig removes DefenseClaw's entries from a parsed
// config mapping and reports whether there were any. Every matching key is
// handled, so a duplicate key cannot hide one, and values are followed
// through YAML aliases: a list or policies mapping that is an alias is
// edited where its anchor is.
func pruneRemovedOmnigentConfig(root *yaml.Node) bool {
	changed := false
	for i := 0; i+1 < len(root.Content); i += 2 {
		key, value := resolveYAMLAlias(root.Content[i]), resolveYAMLAlias(root.Content[i+1])
		if key == nil || value == nil {
			continue
		}
		drop := false
		switch key.Value {
		case "policy_modules":
			switch value.Kind {
			case yaml.ScalarNode:
				drop = removedOmnigentModuleEntry(value)
			case yaml.SequenceNode:
				kept := value.Content[:0]
				removed := false
				for _, module := range value.Content {
					if removedOmnigentModuleEntry(module) {
						removed = true
						continue
					}
					kept = append(kept, module)
				}
				value.Content = kept
				if removed {
					changed = true
					drop = len(kept) == 0
				}
			}
		case "policies":
			if value.Kind != yaml.MappingNode {
				continue
			}
			before := len(value.Content)
			for j := 0; j+1 < len(value.Content); j += 2 {
				if removedOmnigentOwnedPolicy(value.Content[j+1]) {
					value.Content = append(value.Content[:j], value.Content[j+2:]...)
					j -= 2
				}
			}
			if len(value.Content) != before {
				changed = true
				drop = len(value.Content) == 0
			}
		}
		if drop {
			root.Content = append(root.Content[:i], root.Content[i+2:]...)
			i -= 2
			changed = true
		}
	}
	return changed
}

// removedOmnigentModuleEntry reports whether a policy_modules entry, followed
// through an alias, names DefenseClaw's module.
func removedOmnigentModuleEntry(node *yaml.Node) bool {
	node = resolveYAMLAlias(node)
	return node != nil && node.Kind == yaml.ScalarNode && node.Value == removedOmnigentModuleName
}

// removedOmnigentOwnedPolicy reports whether a policy entry's handler is in
// DefenseClaw's module (older releases wrote
// defenseclaw_guardrail: {handler: defenseclaw_omnigent_policy.defenseclaw_policy}).
// The policy's key does not decide it: another tool's handler under that key
// is that tool's, and DefenseClaw's handler under another key still loads
// DefenseClaw's module. The entry and its handler are followed through
// aliases; an entry without its own handler takes the first one its merge
// keys (<<) bring in, as a YAML loader does.
func removedOmnigentOwnedPolicy(entry *yaml.Node) bool {
	handlers := removedOmnigentPolicyHandlers(entry, 0)
	for _, handler := range handlers {
		if strings.HasPrefix(strings.TrimSpace(handler), removedOmnigentModuleName+".") {
			return true
		}
	}
	return false
}

// removedOmnigentPolicyHandlers returns the handler values a policy mapping
// sets itself (every copy of a duplicated key), or else the handlers of the
// first merge source that sets one.
func removedOmnigentPolicyHandlers(entry *yaml.Node, depth int) []string {
	entry = resolveYAMLAlias(entry)
	if entry == nil || entry.Kind != yaml.MappingNode || depth > maxYAMLAliasDepth {
		return nil
	}
	var handlers []string
	var merges []*yaml.Node
	own := false
	for k := 0; k+1 < len(entry.Content); k += 2 {
		key, value := resolveYAMLAlias(entry.Content[k]), resolveYAMLAlias(entry.Content[k+1])
		if key == nil || value == nil || key.Kind != yaml.ScalarNode {
			continue
		}
		switch {
		case key.ShortTag() == "!!merge":
			if value.Kind == yaml.SequenceNode {
				merges = append(merges, value.Content...)
			} else {
				merges = append(merges, value)
			}
		case key.Value == "handler":
			own = true
			if value.Kind == yaml.ScalarNode {
				handlers = append(handlers, value.Value)
			}
		}
	}
	if own {
		return handlers
	}
	for _, source := range merges {
		if inherited := removedOmnigentPolicyHandlers(source, depth+1); len(inherited) > 0 {
			return inherited
		}
	}
	return nil
}

// removedOmnigentValueLoadsPolicy reports whether a decoded config (aliases
// and merge keys already resolved) names DefenseClaw's module in
// policy_modules or a policy handler in it.
func removedOmnigentValueLoadsPolicy(value interface{}) bool {
	root := yamlStringKeyed(value)
	switch modules := root["policy_modules"].(type) {
	case string:
		if modules == removedOmnigentModuleName {
			return true
		}
	case []interface{}:
		for _, module := range modules {
			if name, ok := module.(string); ok && name == removedOmnigentModuleName {
				return true
			}
		}
	}
	for _, policy := range yamlStringKeyed(root["policies"]) {
		handler, ok := yamlStringKeyed(policy)["handler"].(string)
		if ok && strings.HasPrefix(strings.TrimSpace(handler), removedOmnigentModuleName+".") {
			return true
		}
	}
	return false
}

// yamlStringKeyed returns a decoded YAML mapping by its string keys, or nil.
func yamlStringKeyed(value interface{}) map[string]interface{} {
	switch m := value.(type) {
	case map[string]interface{}:
		return m
	case map[interface{}]interface{}:
		out := make(map[string]interface{}, len(m))
		for key, item := range m {
			if name, ok := key.(string); ok {
				out[name] = item
			}
		}
		return out
	}
	return nil
}

// maxYAMLAliasDepth bounds alias and merge chains (a YAML alias may name a
// node that holds itself).
const maxYAMLAliasDepth = 64

// resolveYAMLAlias follows aliases to the node they name.
func resolveYAMLAlias(node *yaml.Node) *yaml.Node {
	for depth := 0; node != nil && node.Kind == yaml.AliasNode; depth++ {
		if depth > maxYAMLAliasDepth {
			return nil
		}
		node = node.Alias
	}
	return node
}

// expandDanglingYAMLAliases replaces each alias whose anchor was removed
// from document by a copy of the node it named, so the marshaled YAML
// defines every alias it uses. Copies drop their anchors; an alias inside a
// copy is expanded the same way on the next pass.
func expandDanglingYAMLAliases(document *yaml.Node) error {
	for pass := 0; pass < maxYAMLAliasDepth; pass++ {
		present := map[*yaml.Node]bool{}
		var mark func(*yaml.Node)
		mark = func(node *yaml.Node) {
			if node == nil || present[node] {
				return
			}
			present[node] = true
			if node.Kind != yaml.AliasNode {
				for _, child := range node.Content {
					mark(child)
				}
			}
		}
		mark(document)
		expanded := false
		var expand func(*yaml.Node)
		expand = func(node *yaml.Node) {
			if node == nil {
				return
			}
			if node.Kind != yaml.AliasNode {
				for _, child := range node.Content {
					expand(child)
				}
				return
			}
			if node.Alias == nil || present[node.Alias] {
				return
			}
			replacement := copyYAMLNodeWithoutAnchors(node.Alias)
			replacement.HeadComment, replacement.LineComment, replacement.FootComment = node.HeadComment, node.LineComment, node.FootComment
			*node = *replacement
			expanded = true
		}
		expand(document)
		if !expanded {
			return nil
		}
	}
	return errors.New("YAML aliases left by the cleanup do not resolve")
}

// copyYAMLNodeWithoutAnchors deep-copies node without its anchors; aliases
// inside it are copied as aliases.
func copyYAMLNodeWithoutAnchors(node *yaml.Node) *yaml.Node {
	out := *node
	out.Anchor = ""
	if node.Kind == yaml.AliasNode {
		return &out
	}
	out.Content = make([]*yaml.Node, len(node.Content))
	for i, child := range node.Content {
		out.Content[i] = copyYAMLNodeWithoutAnchors(child)
	}
	return &out
}
