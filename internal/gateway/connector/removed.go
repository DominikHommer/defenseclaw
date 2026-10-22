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
//     same way. The stub blocks every call and says that support was removed
//     in 1.0.4 and how to remove the hook.
//  2. It revokes the DefenseClaw tokens issued for the connector, but only
//     once nothing but the stub is left at the script path. An old hook that
//     still runs (a file with more than one name, a hard link; a link, or a
//     file DefenseClaw cannot prove it wrote) keeps its tokens: without them
//     the old hook allows every call in fail mode open, with them it reaches
//     the retired gateway route, which blocks every call. The teardown then
//     fails with the step that resolves it by hand (removedOnlyConnector.
//     hookLeft), and the next start tries again.
//
// Nothing else is touched: agent config files (hooks.json, config.yaml),
// import paths (.pth), runtime records (.hookcfg), backups, the hook
// contract lock and every other connector's files stay as they are.
// RemovedConnectorLeftovers lists what is left, with the steps to remove it
// by hand; status, doctor and every uninstall form show that list. The
// gateway keeps the old hook routes, which block every call
// (gateway/retired_connector_hook.go). Delete this file in 1.1.

import (
	"bytes"
	"context"
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
	removedOmnigentPolicyKey   = "defenseclaw_guardrail"
	// removedScriptReadLimit bounds the read of a hook script: anything
	// larger is not one DefenseClaw wrote.
	removedScriptReadLimit = 1 << 20
	// removedMarkerLines is how many leading lines may hold the marker.
	removedMarkerLines = 3
	// removedConfigReadLimit bounds the read of an agent config; a larger
	// one cannot be checked and is listed for a check by hand.
	removedConfigReadLimit = 16 << 20
)

// RemovedConnectorForHookPath returns the removed connector whose gateway
// hook route path is: the route every 0.8.10 to 1.0.3 OpenHands hook and
// OmniGent policy module posts to. until 1.1.
func RemovedConnectorForHookPath(path string) (string, bool) {
	switch path {
	case "/api/v1/" + removedOpenHandsID + "/hook":
		return removedOpenHandsID, true
	case "/api/v1/" + removedOmnigentID + "/hook":
		return removedOmnigentID, true
	}
	return "", false
}

// RemovedConnectorDenyReason is the reason DefenseClaw gives when it blocks
// a call of a removed connector: the stub's, and the retired gateway
// route's. until 1.1.
func RemovedConnectorDenyReason(name string) (string, bool) {
	c, ok := removedConnectorFor(name)
	if !ok {
		return "", false
	}
	if c.name == removedOmnigentID {
		return removedOmnigentDenyReason, true
	}
	return removedOpenHandsDenyReason, true
}

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
	configStep     string
}

// removedOpenHandsLauncherFlag is how a Windows hooks.json command names the
// OpenHands connector of the native launcher (defenseclaw-hook --connector
// openhands).
var removedOpenHandsLauncherFlag = regexp.MustCompile(`(?i)--connector(?:\s*=\s*|\s+)["']?open[-_]?hands\b`)

var (
	removedOpenHands = removedOnlyConnector{
		name: removedOpenHandsID, label: "OpenHands",
		script: removedOpenHandsHookScript, marker: "# defenseclaw-managed-hook v",
		tombstone: removedOpenHandsTombstone, mode: 0o700,
		configStep: "remove every hook whose command runs " + removedOpenHandsHookScript + " (or defenseclaw-hook --connector openhands) from this file, then restart OpenHands",
	}
	removedOmnigent = removedOnlyConnector{
		name: removedOmnigentID, label: "OmniGent",
		script: removedOmnigentModuleName + ".py", marker: "# defenseclaw-managed-policy v",
		tombstone: removedOmnigentTombstone, mode: 0o600,
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

// scriptStateAndLinks is scriptState and, for a regular file, how many names
// (hard links) the file has.
func (c removedOnlyConnector) scriptStateAndLinks(path string) (removedScriptState, uint32, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return removedScriptAbsent, 0, nil
	}
	if err != nil {
		return 0, 0, err
	}
	if !info.Mode().IsRegular() || info.Size() > removedScriptReadLimit {
		return removedScriptForeign, 0, nil
	}
	file, err := os.OpenFile(path, os.O_RDONLY|otlpOpenNoFollow(), 0)
	if err != nil {
		return 0, 0, err
	}
	defer file.Close()
	links, err := atomicTransformBoundLinkCountPlatform(file)
	if err != nil {
		return 0, 0, err
	}
	data, err := io.ReadAll(io.LimitReader(file, removedScriptReadLimit+1))
	if err != nil {
		return 0, 0, err
	}
	return c.classifyScript(data), links, nil
}

func (c removedOnlyConnector) classifyScript(data []byte) removedScriptState {
	switch {
	case string(data) == c.tombstone:
		return removedScriptStub
	case len(data) <= removedScriptReadLimit && removedHasMarker(data, c.marker):
		return removedScriptOwned
	}
	return removedScriptForeign
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
	if err := c.hookLeft(opts.DataDir); err != nil {
		return fmt.Errorf("%s teardown: %w; its tokens were kept, so the old hook still reaches the gateway, which blocks every call", c.name, err)
	}
	return c.revokeTokens(opts.DataDir)
}

// replaceScript writes the deny stub over a script an older release wrote, in
// one atomic rename that replaces the file itself, never a link's target. A
// file with more than one name is left as it is: the rename would give only
// this name the stub, and a later run would then revoke the tokens of the old
// hook under its other names (hookLeft keeps them).
func (c removedOnlyConnector) replaceScript(dataDir string) error {
	path := c.scriptPath(dataDir)
	state, links, err := c.scriptStateAndLinks(path)
	if err != nil {
		return fmt.Errorf("%s teardown: read %s: %w", c.name, path, err)
	}
	if state != removedScriptOwned || links > 1 {
		return nil
	}
	if err := atomicWriteFileNoFollow(path, []byte(c.tombstone), c.mode); err != nil {
		return fmt.Errorf("%s teardown: replace %s with the stub that blocks every call: %w", c.name, path, err)
	}
	return nil
}

// hookLeft returns why an old hook may still run at the script path, with
// the step that resolves it by hand; nil when the path holds the stub (under
// every name) or nothing. While it fails, the tokens stay and VerifyClean
// fails.
func (c removedOnlyConnector) hookLeft(dataDir string) error {
	path := c.scriptPath(dataDir)
	state, links, err := c.scriptStateAndLinks(path)
	switch {
	case err != nil:
		return fmt.Errorf("read %s: %w", path, err)
	case state == removedScriptAbsent || state == removedScriptStub:
		return nil
	case state == removedScriptOwned && links > 1:
		return fmt.Errorf("%s is the hook script an older DefenseClaw wrote and has %d names (hard links), so it was not changed. To finish: %s",
			path, links, c.hardLinkStep(path))
	case state == removedScriptOwned:
		return fmt.Errorf("%s is still the hook script an older DefenseClaw wrote", path)
	}
	return fmt.Errorf("%s was not changed: DefenseClaw cannot prove it wrote it (a link, no DefenseClaw marker in its first %d lines, or not a regular file), and it may still run the old hook. To finish: %s",
		path, removedMarkerLines, c.foreignStep())
}

// hardLinkStep is the manual step for a script with more than one name.
func (c removedOnlyConnector) hardLinkStep(path string) string {
	list := "find / -xdev -samefile " + path + " lists them"
	if runtime.GOOS == "windows" {
		list = "fsutil hardlink list " + path + " lists them"
	}
	return "delete every other name of this file (" + list + "), then run " + c.teardownCommand() + ", which writes the stub and revokes the tokens"
}

// foreignStep is the manual step for a script path DefenseClaw cannot prove
// it wrote.
func (c removedOnlyConnector) foreignStep() string {
	return "if it is not yours, delete it; if it is, move it out of DefenseClaw's hooks folder; then run " +
		c.teardownCommand() + ", which revokes the tokens"
}

func (c removedOnlyConnector) teardownCommand() string {
	return "defenseclaw-gateway connector teardown --connector " + c.name
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

// VerifyClean fails while an old hook may still run at the script path
// (hookLeft) or a token is still there: what Teardown changes. What it
// leaves is listed by RemovedConnectorLeftovers, not reported here.
func (c removedOnlyConnector) VerifyClean(opts SetupOpts) error {
	if err := c.hookLeft(opts.DataDir); err != nil {
		return fmt.Errorf("%s cleanup incomplete: %w", c.name, err)
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
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			add(path, fmt.Sprintf("could not be read (%v)", err), "check it by hand: "+c.configStep)
			continue
		}
		names, checkErr := c.configNames(data)
		switch {
		case names:
			add(path, c.configWhat(), c.configStep)
		case checkErr != nil:
			add(path, fmt.Sprintf("could not be checked (%v), so it may still name DefenseClaw's hook", checkErr), "check it by hand: "+c.configStep)
		}
	}
	if strings.TrimSpace(opts.DataDir) == "" {
		return out
	}
	if c.name == removedOmnigentID {
		if pth := managedFileBackupTargetPath(opts.DataDir, c.name, "pth", ""); pth != "" {
			if item, ok := removedPthLeftover(pth, filepath.Join(opts.DataDir, "hooks")); ok {
				out = append(out, item)
			}
		}
	}
	script := c.scriptPath(opts.DataDir)
	state, links, err := c.scriptStateAndLinks(script)
	tokenStep := c.teardownCommand()
	switch {
	case err != nil:
		add(script, fmt.Sprintf("could not be read (%v)", err), "delete it once nothing above runs it")
	case state == removedScriptStub:
		add(script, "the stub that blocks every "+c.label+" call", "delete it once nothing above runs it")
	case state == removedScriptOwned && links > 1:
		add(script, fmt.Sprintf("still the hook script an older DefenseClaw wrote, with %d names (hard links); teardown leaves it and its tokens, so every name still reaches the gateway, which blocks every call", links),
			c.hardLinkStep(script))
		tokenStep = "follow the step for " + script + " first"
	case state == removedScriptOwned:
		add(script, "still the hook script an older DefenseClaw wrote", c.teardownCommand())
	case state == removedScriptForeign:
		add(script, "not changed: DefenseClaw cannot prove it wrote it (a link, no DefenseClaw marker in its first lines, or not a regular file); teardown keeps its tokens, so an old hook here still reaches the gateway, which blocks every call",
			c.foreignStep())
		tokenStep = "follow the step for " + script + " first"
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
			add(token, "a DefenseClaw token for the removed connector", tokenStep)
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

// configNames reports whether an agent config still runs or imports the
// script. It checks the bytes and the decoded values (JSON for hooks.json,
// YAML for config.yaml), so a name written with escapes is found too. The
// error says why a file that does not name it could not be checked: too
// large, or not JSON or YAML.
func (c removedOnlyConnector) configNames(data []byte) (bool, error) {
	if c.textNames(string(data)) {
		return true, nil
	}
	if len(data) > removedConfigReadLimit {
		return false, fmt.Errorf("it is larger than %d MiB", removedConfigReadLimit>>20)
	}
	body := bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	if len(bytes.TrimSpace(body)) == 0 {
		return false, nil
	}
	var doc any
	if c.name == removedOpenHandsID {
		if err := json.Unmarshal(body, &doc); err != nil {
			return false, fmt.Errorf("it is not JSON: %w", err)
		}
	} else if err := yaml.Unmarshal(body, &doc); err != nil {
		return false, fmt.Errorf("it is not YAML: %w", err)
	}
	return removedValueNames(doc, c.textNames), nil
}

// textNames reports whether one config text (a command, a module name)
// names the script: OpenHands' hook script or the native launcher's
// OpenHands connector, OmniGent's policy module.
func (c removedOnlyConnector) textNames(text string) bool {
	lower := strings.ToLower(text)
	if c.name == removedOmnigentID {
		return strings.Contains(lower, removedOmnigentModuleName)
	}
	return strings.Contains(lower, removedOpenHandsHookScript) || removedOpenHandsLauncherFlag.MatchString(text)
}

// removedValueNames reports whether a string or key anywhere in a decoded
// JSON or YAML value names the script.
func removedValueNames(value any, names func(string) bool) bool {
	switch v := value.(type) {
	case string:
		return names(v)
	case []any:
		for _, item := range v {
			if removedValueNames(item, names) {
				return true
			}
		}
	case map[string]any:
		for key, item := range v {
			if names(key) || removedValueNames(item, names) {
				return true
			}
		}
	case map[any]any:
		for key, item := range v {
			if names(fmt.Sprint(key)) || removedValueNames(item, names) {
				return true
			}
		}
	}
	return false
}

// removedPthLeftover lists OmniGent's import-path file when it still holds
// DefenseClaw's line (the hook folder), with a step that takes out only that
// line when the file holds other import paths too.
func removedPthLeftover(pth, hooks string) (RemovedLeftover, bool) {
	data, err := readRemovedConfig(pth)
	if errors.Is(err, os.ErrNotExist) {
		return RemovedLeftover{}, false
	}
	lineStep := "remove only the line " + hooks + " (DefenseClaw's hook folder) from this file, and keep every other line, once no OmniGent config.yaml names " + removedOmnigentModuleName
	if err != nil || len(data) > removedConfigReadLimit {
		if err == nil {
			err = fmt.Errorf("it is larger than %d MiB", removedConfigReadLimit>>20)
		}
		return RemovedLeftover{Path: pth, What: fmt.Sprintf("could not be read (%v)", err), Step: "check it by hand: " + lineStep}, true
	}
	own, other := false, false
	for _, line := range strings.Split(string(bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "" || strings.HasPrefix(line, "#"):
		case sameManagedTargetPath(line, hooks):
			own = true
		default:
			other = true
		}
	}
	switch {
	case !own:
		return RemovedLeftover{}, false
	case other:
		return RemovedLeftover{Path: pth, What: "adds DefenseClaw's hook folder to OmniGent's Python import path; it holds other import paths too", Step: lineStep}, true
	}
	return RemovedLeftover{Path: pth, What: "adds DefenseClaw's hook folder to OmniGent's Python import path; it holds nothing else",
		Step: "delete this file once no OmniGent config.yaml names " + removedOmnigentModuleName}, true
}

// configPaths are the agent config files an older setup may have changed:
// the one its backup record names, the ones the hook contract lock names,
// the explicit config home and the agent's default (both), and for OmniGent
// the files OMNIGENT_CONFIG and OMNIGENT_CONFIG_HOME select.
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
	// The agent may read its default config as well as the explicit one.
	if home := strings.TrimSpace(opts.ConfigHome); home != "" {
		paths = append(paths, filepath.Join(removedAbsolute(home), file))
	}
	paths = append(paths, homePath(defaultDir, file))
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
// up to one byte past removedConfigReadLimit (more is a file too large to
// check).
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
	return io.ReadAll(io.LimitReader(file, removedConfigReadLimit+1))
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
