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
// (#1182). A host an older release set up still runs their hook script or
// imports their policy module. The teardown of these teardown-only
// connectors does exactly two things:
//
//  1. It replaces the hook script an older release wrote for the connector
//     (OpenHands' openhands-hook.sh, OmniGent's policy module), proven by its
//     DefenseClaw marker, with a static deny stub, in one atomic rename. A
//     stub an older teardown left that allowed every call is replaced the
//     same way. The stub blocks every call and says that support was
//     removed in 1.0.4 and how to remove the hook.
//  2. It revokes the DefenseClaw tokens issued for the connector.
//
// Nothing else is touched: agent config files (hooks.json, config.yaml),
// import paths (.pth), runtime records (.hookcfg), backups, the hook
// contract lock and every other connector's files stay as they are.
// RemovedConnectorLeftovers lists what is left, with the steps to remove it
// by hand; status, doctor and every uninstall form show that list. Delete
// this file in 1.1.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const (
	removedOpenHandsID         = "openhands"
	removedOpenHandsHookScript = "openhands-hook.sh"
	removedOmnigentID          = "omnigent"
	removedOmnigentModuleName  = "defenseclaw_omnigent_policy"
	removedOmnigentPolicyKey   = "defenseclaw_guardrail"
	// removedScriptReadLimit bounds the read of a hook script: anything
	// larger is not one DefenseClaw wrote.
	removedScriptReadLimit = 1 << 20
	// removedMarkerLines is how many leading lines may hold the marker.
	removedMarkerLines = 3
)

// removedOpenHandsDenyReason is the reason the OpenHands stub gives with every
// block. It holds no $, !, backslash or single quote, so every shell prints it
// as it is.
const removedOpenHandsDenyReason = "DefenseClaw blocked this call: OpenHands support was removed in DefenseClaw 1.0.4. " +
	"To use OpenHands without DefenseClaw, remove every hook that runs " + removedOpenHandsHookScript +
	" from your OpenHands hooks.json (~/.openhands/hooks.json, or .openhands/hooks.json in a workspace), then restart OpenHands."

// removedOpenHandsTombstone is the hook script an OpenHands teardown leaves.
// OpenHands blocks a call on exit status 2 and shows the deny reason. The
// stub runs no program: sh -p reads no startup file (ENV, BASH_ENV), and the
// body is only echo and exit.
const removedOpenHandsTombstone = "#!/bin/sh -p\n" +
	"# defenseclaw-managed-hook v0 (disabled tombstone)\n" +
	"# OpenHands support was removed in DefenseClaw 1.0.4. This hook blocks every\n" +
	"# call. Remove the hooks that run it from your OpenHands hooks.json.\n" +
	"echo '{\"decision\":\"deny\",\"reason\":\"" + removedOpenHandsDenyReason + "\"}'\n" +
	"exit 2\n"

// removedOmnigentDenyReason is the reason the OmniGent stub gives.
const removedOmnigentDenyReason = "DefenseClaw blocked this action: OmniGent support was removed in DefenseClaw 1.0.4. " +
	"To use OmniGent without DefenseClaw, remove " + removedOmnigentModuleName + " from policy_modules and the " +
	removedOmnigentPolicyKey + " policy from your OmniGent config.yaml, then restart OmniGent."

// removedOmnigentTombstone is the policy module an OmniGent teardown leaves.
// OmniGent imports it in process, so it is Python with no import: it denies
// every request with the reason.
const removedOmnigentTombstone = "# defenseclaw-managed-policy v0 (disabled tombstone)\n" +
	"\"\"\"OmniGent support was removed in DefenseClaw 1.0.4.\n\n" +
	"This policy module denies every OmniGent request. Remove " + removedOmnigentModuleName + " from\n" +
	"policy_modules and the " + removedOmnigentPolicyKey + " policy from your OmniGent config.yaml,\n" +
	"then restart OmniGent.\n\"\"\"\n\n" +
	"_REASON = \"" + removedOmnigentDenyReason + "\"\n\n\n" +
	"def defenseclaw_policy(event):\n" +
	"    return {\"result\": \"DENY\", \"reason\": _REASON}\n\n\n" +
	"POLICY_REGISTRY = [\n" +
	"    {\n" +
	"        \"handler\": \"" + removedOmnigentModuleName + ".defenseclaw_policy\",\n" +
	"        \"kind\": \"callable\",\n" +
	"        \"name\": \"DefenseClaw Guardrail (removed)\",\n" +
	"        \"description\": \"Deny every request: DefenseClaw 1.0.4 removed OmniGent support.\",\n" +
	"    }\n" +
	"]\n"

// removedOnlyConnector is the teardown-only connector of a removed connector.
type removedOnlyConnector struct {
	name, label string
	// script is the hook script or policy module an older setup wrote under
	// <data>/hooks; marker starts one of its first lines.
	script, marker string
	tombstone      string
	mode           os.FileMode
	// configNeedles are what an agent config that still runs or imports the
	// script contains.
	configNeedles []string
	configStep    string
}

var (
	removedOpenHands = removedOnlyConnector{
		name: removedOpenHandsID, label: "OpenHands",
		script: removedOpenHandsHookScript, marker: "# defenseclaw-managed-hook v",
		tombstone: removedOpenHandsTombstone, mode: 0o700,
		// Windows registered the native launcher, not the script.
		configNeedles: []string{removedOpenHandsHookScript, "--connector openhands"},
		configStep:    "remove every hook whose command runs " + removedOpenHandsHookScript + " (or defenseclaw-hook --connector openhands) from this file, then restart OpenHands",
	}
	removedOmnigent = removedOnlyConnector{
		name: removedOmnigentID, label: "OmniGent",
		script: removedOmnigentModuleName + ".py", marker: "# defenseclaw-managed-policy v",
		tombstone: removedOmnigentTombstone, mode: 0o600,
		configNeedles: []string{removedOmnigentModuleName},
		configStep: "remove " + removedOmnigentModuleName + " from policy_modules and the " + removedOmnigentPolicyKey +
			" policy (handler " + removedOmnigentModuleName + ".defenseclaw_policy) from this file, then restart OmniGent",
	}
)

// removedConnector returns the teardown-only connector for a removed
// connector ID, or false.
func removedConnector(name string) (Connector, bool) {
	c, ok := removedConnectorFor(name)
	if !ok {
		return nil, false
	}
	return c, true
}

func removedConnectorFor(name string) (removedOnlyConnector, bool) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case removedOpenHandsID, "open-hands", "open_hands":
		return removedOpenHands, true
	case removedOmnigentID:
		return removedOmnigent, true
	}
	return removedOnlyConnector{}, false
}

// IsRemovedConnector reports whether name is a connector 1.0.4 removed
// (OpenHands, OmniGent). until 1.1.
func IsRemovedConnector(name string) bool {
	_, ok := removedConnectorFor(name)
	return ok
}

func (c removedOnlyConnector) Name() string { return c.name }

func (c removedOnlyConnector) Description() string {
	return c.label + " connector was removed in DefenseClaw 1.0.4; teardown only"
}

func (c removedOnlyConnector) ToolInspectionMode() ToolInspectionMode { return ToolModePreExecution }

func (c removedOnlyConnector) SubprocessPolicy() SubprocessPolicy { return SubprocessNone }

func (c removedOnlyConnector) Setup(context.Context, SetupOpts) error {
	return fmt.Errorf("connector %q was removed in DefenseClaw 1.0.4; choose a supported connector", c.name)
}

func (c removedOnlyConnector) Authenticate(*http.Request) bool { return false }

func (c removedOnlyConnector) Route(*http.Request, []byte) (*ConnectorSignals, error) {
	return nil, fmt.Errorf("connector %q was removed", c.name)
}

func (c removedOnlyConnector) SetCredentials(string, string) {}

func (c removedOnlyConnector) scriptPath(dataDir string) string {
	return filepath.Join(dataDir, "hooks", c.script)
}

// removedScriptState is what is at a removed connector's script path.
type removedScriptState int

const (
	removedScriptAbsent removedScriptState = iota
	// removedScriptStub is the deny stub this release writes.
	removedScriptStub
	// removedScriptOwned is a script an older release wrote (its marker is
	// there): the working hook or an older stub. Teardown replaces it.
	removedScriptOwned
	// removedScriptForeign is anything else: no marker, a link, a folder,
	// another kind of file. Teardown never changes it.
	removedScriptForeign
)

func (c removedOnlyConnector) scriptState(path string) (removedScriptState, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return removedScriptAbsent, nil
	}
	if err != nil {
		return 0, err
	}
	if !info.Mode().IsRegular() || info.Size() > removedScriptReadLimit {
		return removedScriptForeign, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, removedScriptReadLimit+1))
	if err != nil {
		return 0, err
	}
	switch {
	case string(data) == c.tombstone:
		return removedScriptStub, nil
	case len(data) <= removedScriptReadLimit && removedHasMarker(data, c.marker):
		return removedScriptOwned, nil
	}
	return removedScriptForeign, nil
}

// removedHasMarker reports whether one of the first lines of data starts with
// marker.
func removedHasMarker(data []byte, marker string) bool {
	lines := bytes.SplitN(data, []byte("\n"), removedMarkerLines+1)
	if len(lines) > removedMarkerLines {
		lines = lines[:removedMarkerLines]
	}
	for _, line := range lines {
		if bytes.HasPrefix(bytes.TrimSpace(line), []byte(marker)) {
			return true
		}
	}
	return false
}

// Teardown replaces the script with the deny stub and revokes the tokens; see
// the file comment.
func (c removedOnlyConnector) Teardown(_ context.Context, opts SetupOpts) error {
	if strings.TrimSpace(opts.DataDir) == "" {
		return fmt.Errorf("%s teardown: empty data directory", c.name)
	}
	// The stub goes first: while the old hook still runs, its tokens stay
	// with it, so a failed write changes nothing. A token that cannot be
	// revoked after it leaves the stub in place; the next start tries again.
	if err := c.replaceScript(opts.DataDir); err != nil {
		return fmt.Errorf("%w; nothing was changed, and the next start tries again", err)
	}
	return c.revokeTokens(opts.DataDir)
}

// replaceScript writes the deny stub over a script an older release wrote, in
// one atomic rename that replaces the file itself, never a link's target.
func (c removedOnlyConnector) replaceScript(dataDir string) error {
	path := c.scriptPath(dataDir)
	state, err := c.scriptState(path)
	if err != nil {
		return fmt.Errorf("%s teardown: read %s: %w", c.name, path, err)
	}
	if state != removedScriptOwned {
		return nil
	}
	if err := atomicWriteFileNoFollow(path, []byte(c.tombstone), c.mode); err != nil {
		return fmt.Errorf("%s teardown: replace %s with the stub that blocks every call: %w", c.name, path, err)
	}
	return nil
}

func (c removedOnlyConnector) otlpTokenPath(dataDir string) string {
	return filepath.Join(dataDir, "hooks", otlpPathTokenFileName(OTLPPathTokenScope(c.name)))
}

// revokeTokens removes the connector's hook API and OTLP tokens. Nothing in
// 1.0.4 accepts them.
func (c removedOnlyConnector) revokeTokens(dataDir string) error {
	var errs []error
	if c.hookTokenPresent(dataDir) {
		if err := RemoveHookAPIToken(dataDir, c.name); err != nil {
			errs = append(errs, fmt.Errorf("%s teardown: revoke the hook token: %w", c.name, err))
		}
	}
	token := c.otlpTokenPath(dataDir)
	for _, path := range []string{token, token + ".tmp"} {
		if err := removeOwnedOTLPPathTokenFile(path); err != nil {
			errs = append(errs, fmt.Errorf("%s teardown: revoke %s: %w", c.name, path, err))
		}
	}
	return errors.Join(errs...)
}

// hookTokenPresent reports whether the hook token or its temporary file may
// be there (true when the path cannot be built or read).
func (c removedOnlyConnector) hookTokenPresent(dataDir string) bool {
	path, err := HookAPITokenFilePath(dataDir, c.name)
	if err != nil {
		return true
	}
	for _, candidate := range []string{path, path + ".tmp"} {
		if _, err := os.Lstat(candidate); !errors.Is(err, os.ErrNotExist) {
			return true
		}
	}
	return false
}

func (c removedOnlyConnector) tokenPaths(dataDir string) []string {
	var paths []string
	if path, err := HookAPITokenFilePath(dataDir, c.name); err == nil {
		paths = append(paths, path)
	}
	return append(paths, c.otlpTokenPath(dataDir))
}

// VerifyClean fails while the script is still one an older release wrote or
// a token is still there: what Teardown changes. What it leaves is listed by
// RemovedConnectorLeftovers, not reported here.
func (c removedOnlyConnector) VerifyClean(opts SetupOpts) error {
	path := c.scriptPath(opts.DataDir)
	state, err := c.scriptState(path)
	if err != nil {
		return fmt.Errorf("%s cleanup: read %s: %w", c.name, path, err)
	}
	if state == removedScriptOwned {
		return fmt.Errorf("%s cleanup incomplete: %s is still the hook script an older DefenseClaw wrote", c.name, path)
	}
	for _, token := range c.tokenPaths(opts.DataDir) {
		if _, err := os.Lstat(token); err == nil {
			return fmt.Errorf("%s cleanup incomplete: token %s is still there", c.name, token)
		}
	}
	return nil
}

// RemovedLeftover is one thing a removed connector's teardown leaves for the
// user: what it is and how to remove it by hand.
type RemovedLeftover struct {
	Path string `json:"path"`
	What string `json:"what"`
	Step string `json:"step"`
}

// RemovedConnectorLeftovers lists what is left of a removed connector on this
// host, with the manual steps; false when name is not a removed connector.
// It only reads.
func RemovedConnectorLeftovers(name string, opts SetupOpts) ([]RemovedLeftover, bool) {
	c, ok := removedConnectorFor(name)
	if !ok {
		return nil, false
	}
	return c.leftovers(opts), true
}

func (c removedOnlyConnector) leftovers(opts SetupOpts) []RemovedLeftover {
	var out []RemovedLeftover
	add := func(path, what, step string) {
		out = append(out, RemovedLeftover{Path: path, What: what, Step: step})
	}
	for _, path := range c.configPaths(opts) {
		data, err := readRemovedConfig(path)
		switch {
		case errors.Is(err, os.ErrNotExist):
		case err != nil:
			add(path, fmt.Sprintf("could not be read (%v)", err), "check it by hand: "+c.configStep)
		case c.configNames(data):
			add(path, c.configWhat(), c.configStep)
		}
	}
	if strings.TrimSpace(opts.DataDir) == "" {
		return out
	}
	if c.name == removedOmnigentID {
		if pth := managedFileBackupTargetPath(opts.DataDir, c.name, "pth", ""); pth != "" {
			if _, err := os.Lstat(pth); err == nil {
				add(pth, "adds DefenseClaw's hook folder to OmniGent's Python import path",
					"delete this file once no OmniGent config.yaml names "+removedOmnigentModuleName)
			}
		}
	}
	script := c.scriptPath(opts.DataDir)
	state, err := c.scriptState(script)
	switch {
	case err != nil:
		add(script, fmt.Sprintf("could not be read (%v)", err), "delete it once nothing above runs it")
	case state == removedScriptStub:
		add(script, "the stub that blocks every "+c.label+" call", "delete it once nothing above runs it")
	case state == removedScriptOwned:
		add(script, "still the hook script an older DefenseClaw wrote", "run defenseclaw-gateway connector teardown --connector "+c.name)
	case state == removedScriptForeign:
		add(script, "not changed: it is not a file DefenseClaw wrote (no DefenseClaw marker, or a link)",
			"remove what runs it, then delete it if it is not yours")
	}
	if c.name == removedOpenHandsID {
		record := filepath.Join(opts.DataDir, "hooks", hookConfigSidecarName+"."+c.name)
		if _, err := os.Lstat(record); err == nil {
			add(record, "the runtime settings of the removed hook; DefenseClaw no longer reads it", "delete it")
		}
	}
	backups := filepath.Join(opts.DataDir, "connector_backups", c.name)
	if _, err := os.Lstat(backups); err == nil {
		add(backups, "the copies of your files DefenseClaw saved before its setup changed them (pristine_bytes, base64)",
			"copy back what you need, then delete this folder")
	}
	for _, token := range c.tokenPaths(opts.DataDir) {
		if _, err := os.Lstat(token); err == nil {
			add(token, "a DefenseClaw token for the removed connector", "run defenseclaw-gateway connector teardown --connector "+c.name)
		}
	}
	return out
}

func (c removedOnlyConnector) configWhat() string {
	if c.name == removedOmnigentID {
		return "OmniGent still imports DefenseClaw's policy module from here; it denies every request"
	}
	return "OpenHands still runs DefenseClaw's hook from here; it blocks every call"
}

func (c removedOnlyConnector) configNames(data []byte) bool {
	for _, needle := range c.configNeedles {
		if bytes.Contains(data, []byte(needle)) {
			return true
		}
	}
	return false
}

// configPaths are the agent config files an older setup may have changed:
// the one its backup record names, the ones the hook contract lock names,
// the explicit config home, the agent's default, and for OmniGent the files
// OMNIGENT_CONFIG and OMNIGENT_CONFIG_HOME select.
func (c removedOnlyConnector) configPaths(opts SetupOpts) []string {
	file, defaultDir := "hooks.json", ".openhands"
	if c.name == removedOmnigentID {
		file, defaultDir = "config.yaml", ".omnigent"
	}
	var paths []string
	if strings.TrimSpace(opts.DataDir) != "" {
		paths = append(paths, managedFileBackupTargetPath(opts.DataDir, c.name, "config", ""))
		if entry, err := LoadHookContractLockEntryForMode(opts.DataDir, c.name, opts.ManagedEnterprise); err == nil {
			for _, path := range entry.Locations.HookConfigPaths {
				if strings.EqualFold(filepath.Base(path), file) {
					paths = append(paths, removedAbsolute(path))
				}
			}
		}
	}
	if home := strings.TrimSpace(opts.ConfigHome); home != "" {
		paths = append(paths, filepath.Join(removedAbsolute(home), file))
	} else {
		paths = append(paths, homePath(defaultDir, file))
	}
	if c.name == removedOmnigentID {
		paths = append(paths, removedAbsolute(os.Getenv("OMNIGENT_CONFIG")))
		if home := strings.TrimSpace(os.Getenv("OMNIGENT_CONFIG_HOME")); home != "" {
			paths = append(paths, filepath.Join(removedAbsolute(home), file))
		}
	}
	var unique []string
	for _, path := range uniqueNonEmptyStrings(paths) {
		seen := false
		for _, kept := range unique {
			if sameManagedTargetPath(kept, path) {
				seen = true
				break
			}
		}
		if !seen {
			unique = append(unique, path)
		}
	}
	return unique
}

// removedAbsolute resolves ~ and a relative path the way an older setup
// read it ("" stays "").
func removedAbsolute(value string) string {
	value = strings.TrimSpace(value)
	switch {
	case value == "":
		return ""
	case value == "~":
		return homePath()
	case strings.HasPrefix(value, "~/") || strings.HasPrefix(value, `~\`):
		return filepath.Join(homePath(), value[2:])
	}
	if absolute, err := filepath.Abs(value); err == nil {
		return absolute
	}
	return filepath.Clean(value)
}

// readRemovedConfig reads an agent config through links, as the agent does,
// up to a bound.
func readRemovedConfig(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	return io.ReadAll(io.LimitReader(file, 16<<20))
}

// FormatRemovedLeftovers renders leftovers as the lines status, uninstall and
// teardown print ("" for none).
func FormatRemovedLeftovers(name string, leftovers []RemovedLeftover) string {
	if len(leftovers) == 0 {
		return ""
	}
	label := name
	if c, ok := removedConnectorFor(name); ok {
		label = c.label
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s support was removed in DefenseClaw 1.0.4. Left for you to remove by hand:\n", label)
	for _, item := range leftovers {
		fmt.Fprintf(&b, "  - %s: %s. To remove: %s.\n", item.Path, item.What, item.Step)
	}
	return b.String()
}
