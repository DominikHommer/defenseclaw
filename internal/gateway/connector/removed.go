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
	removedOmnigentHandler     = removedOmnigentModuleName + ".defenseclaw_policy"
	removedOmnigentPolicyKey   = "defenseclaw_guardrail"
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

// Teardown restores each file an older release backed up (config.yaml, the
// policy module and the .pth file that put it on OmniGent's import path)
// when it is unchanged since then. Otherwise it removes only DefenseClaw's
// policy entries from config.yaml and deletes the module and a .pth file
// that names DefenseClaw's hook directory.
func (c removedOmnigentConnector) Teardown(_ context.Context, opts SetupOpts) error {
	if strings.TrimSpace(opts.DataDir) == "" {
		return errors.New("omnigent cleanup: empty data directory")
	}
	moduleDir := filepath.Dir(c.modulePath(opts))
	var errs []error
	for _, logical := range []string{"config", "module", "pth"} {
		fallback := ""
		if logical == "module" {
			fallback = c.modulePath(opts)
		}
		path := managedFileBackupTargetPath(opts.DataDir, c.name, logical, fallback)
		if path == "" {
			continue
		}
		restored, err := restoreManagedFileBackupIfUnchanged(opts.DataDir, c.name, logical, path)
		if err != nil {
			errs = append(errs, fmt.Errorf("omnigent cleanup %s: %s", logical, restoreBackupFailure(err)))
			continue
		}
		if restored {
			continue
		}
		switch logical {
		case "module":
			if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				errs = append(errs, fmt.Errorf("omnigent cleanup: remove %s: %w", path, err))
			}
		case "pth":
			data, info, err := readManagedTarget(path)
			if err != nil {
				errs = append(errs, fmt.Errorf("omnigent cleanup: inspect %s: %w", path, err))
			} else if info != nil && filepath.Clean(strings.TrimSpace(string(data))) == filepath.Clean(moduleDir) {
				if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
					errs = append(errs, fmt.Errorf("omnigent cleanup: remove %s: %w", path, err))
				}
			}
		}
	}
	for _, path := range c.configPaths(opts) {
		if err := removeRemovedOmnigentConfigEntries(path); err != nil {
			errs = append(errs, fmt.Errorf("omnigent cleanup %s: %w", path, err))
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	if err := c.VerifyClean(opts); err != nil {
		return err
	}
	for _, logical := range []string{"config", "module", "pth"} {
		discardManagedFileBackup(opts.DataDir, c.name, logical)
	}
	return c.removeCredentials(opts.DataDir)
}

// VerifyClean fails while an OmniGent config still loads DefenseClaw's
// policy, or the policy module or its import-path file remains.
func (c removedOmnigentConnector) VerifyClean(opts SetupOpts) error {
	for _, path := range c.configPaths(opts) {
		data, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("omnigent cleanup could not read %s: %w", path, err)
		}
		if strings.Contains(string(data), removedOmnigentModuleName) || strings.Contains(string(data), removedOmnigentPolicyKey) {
			return fmt.Errorf("omnigent cleanup incomplete: %s still loads DefenseClaw's policy", path)
		}
	}
	paths := []string{c.modulePath(opts)}
	for _, logical := range []string{"module", "pth"} {
		if backup, err := loadManagedFileBackupPath(managedFileBackupPath(opts.DataDir, c.name, logical)); err == nil &&
			!backup.Existed {
			paths = append(paths, backup.Path)
		}
	}
	for _, path := range uniqueNonEmptyStrings(paths) {
		if _, err := os.Lstat(path); err == nil {
			return fmt.Errorf("omnigent cleanup incomplete: %s remains", path)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

// removeRemovedOmnigentConfigEntries removes DefenseClaw's module from
// policy_modules and its policy (only when the handler is DefenseClaw's)
// from policies; every other key and entry stays.
func removeRemovedOmnigentConfigEntries(path string) error {
	data, err := readHookConfigFile(path)
	if os.IsNotExist(err) || (err == nil && len(strings.TrimSpace(string(data))) == 0) {
		return nil
	}
	if err != nil {
		return err
	}
	var document yaml.Node
	if err := yaml.Unmarshal(data, &document); err != nil {
		return fmt.Errorf("parse YAML %s: %w", path, err)
	}
	if len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return fmt.Errorf("parse YAML %s: expected a mapping", path)
	}
	root := document.Content[0]
	changed := false
	for i := 0; i+1 < len(root.Content); i += 2 {
		key, value := root.Content[i], root.Content[i+1]
		switch key.Value {
		case "policy_modules":
			if value.Kind == yaml.ScalarNode && value.Value == removedOmnigentModuleName {
				root.Content = append(root.Content[:i], root.Content[i+2:]...)
				i -= 2
				changed = true
				continue
			}
			if value.Kind != yaml.SequenceNode {
				continue
			}
			kept := value.Content[:0]
			removed := false
			for _, module := range value.Content {
				if module.Kind == yaml.ScalarNode && module.Value == removedOmnigentModuleName {
					removed = true
					continue
				}
				kept = append(kept, module)
			}
			value.Content = kept
			if removed {
				changed = true
				if len(kept) == 0 {
					root.Content = append(root.Content[:i], root.Content[i+2:]...)
					i -= 2
				}
			}
		case "policies":
			if value.Kind != yaml.MappingNode {
				continue
			}
			removed := false
			for j := 0; j+1 < len(value.Content); j += 2 {
				if value.Content[j].Value != removedOmnigentPolicyKey || value.Content[j+1].Kind != yaml.MappingNode {
					continue
				}
				entry := value.Content[j+1]
				owned := false
				for k := 0; k+1 < len(entry.Content); k += 2 {
					owned = owned || (entry.Content[k].Value == "handler" && entry.Content[k+1].Value == removedOmnigentHandler)
				}
				if owned {
					value.Content = append(value.Content[:j], value.Content[j+2:]...)
					removed = true
				}
				break
			}
			if removed {
				changed = true
				if len(value.Content) == 0 {
					root.Content = append(root.Content[:i], root.Content[i+2:]...)
					i -= 2
				}
			}
		}
	}
	if !changed {
		return nil
	}
	updated, err := yaml.Marshal(&document)
	if err != nil {
		return err
	}
	return atomicWriteFile(path, updated, 0o600)
}
