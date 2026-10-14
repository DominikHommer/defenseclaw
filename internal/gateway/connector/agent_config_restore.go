// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Hermes (~/.hermes/config.yaml) and Devin (~/.config/devin/config.json)
// keep the account's own settings (model, provider, permissions, MCP servers)
// in the same file as the hooks DefenseClaw registers. An edited file keeps
// them: setup replaces DefenseClaw's hooks only. A file that went missing was
// recreated with DefenseClaw's hooks alone, so the account's settings were
// gone while verify read ok (GAP-0564). DefenseClaw now keeps a copy of the
// file as it last verified (the last known good copy, beside the connector's
// managed backup record) and puts it back, else the file as it was before
// DefenseClaw's first setup, before it registers its hooks again. With
// neither, the hooks are restored alone and a notice records that the
// account's settings could not be put back; the enterprise status and verify
// report it until the account has settings in the file again.
//
// Linux and macOS only: the Windows managed runtime's rollback removes only
// the names it knows in connector_backups\<connector> and refuses any other.

// Where a missing agent config was put back from.
const (
	// AgentConfigFromLastGood is the copy taken when the file last verified.
	AgentConfigFromLastGood = "last_good"
	// AgentConfigFromPristine is the file as DefenseClaw's first setup found it.
	AgentConfigFromPristine = "pristine"
	// AgentConfigHooksOnly is no copy: DefenseClaw's hooks were restored alone.
	AgentConfigHooksOnly = "hooks_only"
)

const agentConfigCopyVersion = 1

// agentConfigKeepsCopy is false where no copy is kept (a seam for tests).
var agentConfigKeepsCopy = runtime.GOOS != "windows"

// agentConfigSpec is a connector whose hook config is the agent's own
// settings file.
type agentConfigSpec struct {
	connector string
	// logical is the connector's managed backup logical name for the file.
	logical string
	label   string
	path    func(SetupOpts) string
	// keys returns the top-level keys of a document the agent reads
	// (false: not one).
	keys func([]byte) ([]string, bool)
}

func agentConfigSpecFor(connectorName string) (agentConfigSpec, bool) {
	switch strings.ToLower(strings.TrimSpace(connectorName)) {
	case "hermes":
		return agentConfigSpec{connector: "hermes", logical: "config.yaml", label: "Hermes config", path: hermesConfigPath, keys: yamlTopKeys}, true
	case "devin":
		return agentConfigSpec{connector: "devin", logical: "config", label: "Devin config", path: devinHooksPath, keys: jsoncTopKeys}, true
	}
	return agentConfigSpec{}, false
}

// agentConfigCopy is the last known good copy of an agent config file.
type agentConfigCopy struct {
	Version int    `json:"version"`
	Path    string `json:"path"`
	SHA256  string `json:"sha256"`
	Bytes   []byte `json:"bytes"`
	SavedAt string `json:"saved_at"`
}

// agentConfigNotice records how setup recreated a missing agent config.
type agentConfigNotice struct {
	Version int    `json:"version"`
	Path    string `json:"path"`
	Source  string `json:"source"`
	// CopiedAt is when the copy put back was taken.
	CopiedAt string `json:"copied_at,omitempty"`
	// SettingsLost is set when DefenseClaw saw settings of the account in the
	// file (before its first setup, or in a copy that no longer reads) and
	// could not put them back.
	SettingsLost bool   `json:"settings_lost,omitempty"`
	At           string `json:"at"`
}

// The copy and the notice sit beside the managed backup record. Their names
// do not end in .json, which the backup records' walk reads.
func (s agentConfigSpec) copyPath(dataDir string) string {
	record := managedFileBackupPath(dataDir, s.connector, s.logical)
	return strings.TrimSuffix(record, ".json") + ".last-good"
}

func (s agentConfigSpec) noticePath(dataDir string) string {
	record := managedFileBackupPath(dataDir, s.connector, s.logical)
	return strings.TrimSuffix(record, ".json") + ".restore-notice"
}

// agentConfigMaxBytes bounds the files read and kept.
const agentConfigMaxBytes = 1 << 20

func yamlTopKeys(data []byte) ([]string, bool) {
	if len(data) > agentConfigMaxBytes {
		return nil, false
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, true
	}
	var doc map[string]interface{}
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, false
	}
	return agentConfigTopKeys(doc), true
}

func jsoncTopKeys(data []byte) ([]string, bool) {
	if len(data) > agentConfigMaxBytes {
		return nil, false
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, true
	}
	normalized, err := normalizeCopilotJSONC(data)
	if err != nil {
		return nil, false
	}
	var doc map[string]interface{}
	decoder := json.NewDecoder(bytes.NewReader(normalized))
	decoder.UseNumber()
	if err := decoder.Decode(&doc); err != nil || doc == nil {
		return nil, false
	}
	return agentConfigTopKeys(doc), true
}

func agentConfigTopKeys(doc map[string]interface{}) []string {
	keys := make([]string, 0, len(doc))
	for key := range doc {
		keys = append(keys, key)
	}
	return keys
}

// hasSettings reports whether a file holds anything but DefenseClaw's hooks
// field.
func (s agentConfigSpec) hasSettings(data []byte) bool {
	keys, ok := s.keys(data)
	if !ok {
		return true // not a document setup wrote: the account's own
	}
	for _, key := range keys {
		if key != "hooks" {
			return true
		}
	}
	return false
}

func (s agentConfigSpec) readCopy(dataDir, configPath string) (agentConfigCopy, bool) {
	data, info, err := readManagedTarget(s.copyPath(dataDir))
	if err != nil || info == nil || !info.Mode().IsRegular() || len(data) > 4*agentConfigMaxBytes {
		return agentConfigCopy{}, false
	}
	var copy agentConfigCopy
	if json.Unmarshal(data, &copy) != nil || copy.Version != agentConfigCopyVersion ||
		!sameManagedTargetPath(copy.Path, configPath) || copy.SHA256 != sha256Hex(copy.Bytes) {
		return agentConfigCopy{}, false
	}
	if _, ok := s.keys(copy.Bytes); !ok {
		return agentConfigCopy{}, false
	}
	return copy, true
}

// recordCopy keeps the agent config as it is now as the last known good
// copy. A missing or unparseable file is not kept.
func (s agentConfigSpec) recordCopy(dataDir, configPath string) error {
	if !agentConfigKeepsCopy {
		return nil
	}
	data, info, err := readManagedTarget(configPath)
	if err != nil || info == nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return nil
	}
	if _, ok := s.keys(data); !ok {
		return nil
	}
	if existing, ok := s.readCopy(dataDir, configPath); ok && bytes.Equal(existing.Bytes, data) {
		return nil
	}
	body, err := json.Marshal(agentConfigCopy{
		Version: agentConfigCopyVersion,
		Path:    configPath,
		SHA256:  sha256Hex(data),
		Bytes:   data,
		SavedAt: time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		return err
	}
	path := s.copyPath(dataDir)
	if err := ensureManagedBackupDirRestricted(filepath.Dir(path)); err != nil {
		return err
	}
	return atomicWriteFile(path, append(body, '\n'), 0o600)
}

// seedMissing puts back an agent config that went missing after DefenseClaw
// managed it, before setup registers the hooks in it again: the last known
// good copy, else the file as DefenseClaw's first setup found it. A first
// setup (no managed backup record) or a file that is there changes nothing.
// It returns where the file came from ("" when it did nothing).
func (s agentConfigSpec) seedMissing(dataDir, configPath string) (string, error) {
	if !agentConfigKeepsCopy {
		return "", nil
	}
	if _, err := os.Lstat(configPath); err == nil || !errors.Is(err, os.ErrNotExist) {
		return "", nil // there, a dangling link or unreadable: not a missing file
	}
	backup, err := loadManagedFileBackupPath(managedFileBackupPath(dataDir, s.connector, s.logical))
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	if _, err := validateManagedFileBackupTarget(backup, s.connector, s.logical, configPath); err != nil {
		return "", err
	}
	notice := agentConfigNotice{Version: agentConfigCopyVersion, Path: configPath, Source: AgentConfigHooksOnly,
		At: time.Now().UTC().Format(time.RFC3339)}
	var seed []byte
	mode := os.FileMode(0o600)
	if copy, ok := s.readCopy(dataDir, configPath); ok {
		seed, notice.Source, notice.CopiedAt = copy.Bytes, AgentConfigFromLastGood, copy.SavedAt
	} else if _, ok := s.keys(backup.PristineBytes); backup.Existed && ok && len(bytes.TrimSpace(backup.PristineBytes)) > 0 {
		seed, notice.Source, notice.CopiedAt = backup.PristineBytes, AgentConfigFromPristine, backup.CapturedAt
		if perm := os.FileMode(backup.Mode).Perm(); perm != 0 {
			mode = perm
		}
	}
	if seed == nil {
		// DefenseClaw saw settings it cannot put back: a file before its
		// first setup, or a copy that is there but no longer reads.
		_, copyErr := os.Lstat(s.copyPath(dataDir))
		notice.SettingsLost = (backup.Existed && len(bytes.TrimSpace(backup.PristineBytes)) > 0) || copyErr == nil
	} else if err := atomicWriteFile(configPath, seed, mode); err != nil {
		return "", fmt.Errorf("put back %s %s: %w", s.label, configPath, err)
	}
	if err := s.writeNotice(dataDir, notice); err != nil {
		return notice.Source, err
	}
	return notice.Source, nil
}

func (s agentConfigSpec) writeNotice(dataDir string, notice agentConfigNotice) error {
	body, err := json.Marshal(notice)
	if err != nil {
		return err
	}
	path := s.noticePath(dataDir)
	if err := ensureManagedBackupDirRestricted(filepath.Dir(path)); err != nil {
		return err
	}
	return atomicWriteFile(path, append(body, '\n'), 0o600)
}

func (s agentConfigSpec) readNotice(dataDir string) (agentConfigNotice, bool) {
	data, info, err := readManagedTarget(s.noticePath(dataDir))
	if err != nil || info == nil || len(data) > 64<<10 {
		return agentConfigNotice{}, false
	}
	var notice agentConfigNotice
	if json.Unmarshal(data, &notice) != nil || notice.Version != agentConfigCopyVersion {
		return agentConfigNotice{}, false
	}
	return notice, true
}

// removeCopies removes the last known good copy and the notice (teardown:
// they hold the account's settings and describe a file DefenseClaw no longer
// manages).
func (s agentConfigSpec) removeCopies(dataDir string) error {
	var errs []error
	for _, path := range []string{s.copyPath(dataDir), s.noticePath(dataDir)} {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// seedMissingAgentConfig and recordAgentConfigCopy are setup's: no-ops for
// a connector without an agent config spec.
func seedMissingAgentConfig(connectorName, dataDir, configPath string) error {
	if spec, ok := agentConfigSpecFor(connectorName); ok {
		_, err := spec.seedMissing(dataDir, configPath)
		return err
	}
	return nil
}

func recordAgentConfigCopy(connectorName, dataDir, configPath string) {
	if spec, ok := agentConfigSpecFor(connectorName); ok {
		_ = spec.recordCopy(dataDir, configPath) // best effort: the next verify keeps it too
	}
}

// AgentConfigNotices is what the standalone guardian reports for an
// account's agent config (Hermes, Devin) after setup (since: the setup's
// start) or after a verify that passed (since zero, refresh): a file put back
// from a copy at or after since, or recreated with DefenseClaw's hooks alone,
// and, until the account has settings in it again, one recreated without the
// settings DefenseClaw saw. After a verify that passed the file is kept as
// the last known good copy, and a notice that no longer applies is removed.
// Linux and macOS; nothing for other connectors or elsewhere.
func AgentConfigNotices(connectorName string, opts SetupOpts, since time.Time, refresh bool) []string {
	spec, ok := agentConfigSpecFor(connectorName)
	if !ok || !agentConfigKeepsCopy {
		return nil
	}
	configPath := spec.path(opts)
	if strings.TrimSpace(configPath) == "" {
		return nil
	}
	var notices []string
	if notice, ok := spec.readNotice(opts.DataDir); ok && sameManagedTargetPath(notice.Path, configPath) {
		at, _ := time.Parse(time.RFC3339, notice.At)
		data, info, _ := readManagedTarget(configPath)
		settingsBack := info != nil && spec.hasSettings(data)
		switch {
		case notice.SettingsLost && !settingsBack:
			notices = append(notices, fmt.Sprintf("%s %s went missing and DefenseClaw had no copy of it to put back, so it holds DefenseClaw's hooks only: the account's own settings in it must be entered again (since %s)", spec.label, configPath, notice.At))
		case since.IsZero() || at.Before(since.Add(-time.Second)):
			// Reported by the setup that recreated the file.
		case notice.Source == AgentConfigHooksOnly:
			notices = append(notices, fmt.Sprintf("%s %s went missing and DefenseClaw had no copy of it, so it was recreated with DefenseClaw's hooks only: if the account had settings in it, they must be entered again", spec.label, configPath))
		default:
			notices = append(notices, fmt.Sprintf("%s %s went missing; DefenseClaw put back its copy of %s with the account's settings, and changes made after that copy are not in it", spec.label, configPath, notice.CopiedAt))
		}
		if refresh && (!notice.SettingsLost || settingsBack) {
			_ = os.Remove(spec.noticePath(opts.DataDir))
		}
	}
	if refresh {
		_ = spec.recordCopy(opts.DataDir, configPath)
	}
	return notices
}
