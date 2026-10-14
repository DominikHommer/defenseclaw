// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/openshell/image"
)

const (
	sampleImageOwner = "aaaaaaaaaaaaaaaa"
	otherImageOwner  = "bbbbbbbbbbbbbbbb"
	imageListFormat  = "{{.Repository}}:{{.Tag}}\t{{.ID}}"
)

type testDockerImage struct {
	tag, id string
	labels  map[string]string
	rmError string
}

// The fake applies each Docker label filter; a missing or wrong filter lets
// another account's image into the reply and makes the assertions fail.
type imageDockerRunner struct {
	other   Runner
	images  map[string]*testDockerImage
	calls   [][]string
	onImage func([]string)
	listErr string
}

func (d *imageDockerRunner) Run(ctx context.Context, name string, args ...string) (CommandResult, error) {
	if filepath.Base(name) != "docker" || len(args) < 2 || args[0] != "image" {
		return d.other.Run(ctx, name, args...)
	}
	d.calls = append(d.calls, append([]string(nil), args...))
	if d.onImage != nil {
		d.onImage(args)
	}
	switch args[1] {
	case "ls":
		if d.listErr != "" {
			return CommandResult{Stderr: []byte(d.listErr), ExitCode: 1}, errors.New("Docker list failed")
		}
		filters := map[string]string{}
		for i := 2; i < len(args); i++ {
			if args[i] == "--filter" && i+1 < len(args) {
				key, value, ok := strings.Cut(strings.TrimPrefix(args[i+1], "label="), "=")
				if ok {
					filters[key] = value
				}
				i++
			}
		}
		if filters[image.LabelSandboxImage] != "1" || filters[image.LabelOwner] == "" || !containsSequence(args, "--no-trunc", "--format", imageListFormat) {
			return CommandResult{ExitCode: 1}, errors.New("wrong Docker image list command")
		}
		var tags []string
		for tag := range d.images {
			tags = append(tags, tag)
		}
		sort.Strings(tags)
		var out strings.Builder
		for _, tag := range tags {
			img := d.images[tag]
			match := true
			for key, value := range filters {
				if img.labels[key] != value {
					match = false
				}
			}
			if match {
				fmt.Fprintf(&out, "%s\t%s\n", tag, img.id)
			}
		}
		return CommandResult{Stdout: []byte(out.String())}, nil
	case "inspect":
		if !containsSequence(args, "--format", "{{json .}}") {
			return CommandResult{ExitCode: 1}, errors.New("wrong Docker inspect command")
		}
		img := d.images[args[len(args)-1]]
		if img == nil {
			return CommandResult{Stderr: []byte("No such image"), ExitCode: 1}, errors.New("missing image")
		}
		data, _ := json.Marshal(struct {
			ID     string `json:"Id"`
			Config struct {
				Labels map[string]string `json:"Labels"`
			} `json:"Config"`
		}{ID: img.id, Config: struct {
			Labels map[string]string `json:"Labels"`
		}{Labels: img.labels}})
		return CommandResult{Stdout: data}, nil
	case "rm":
		if len(args) != 3 {
			return CommandResult{ExitCode: 1}, errors.New("image rm needs one tag and no force flag")
		}
		img := d.images[args[2]]
		if img == nil {
			return CommandResult{Stderr: []byte("No such image"), ExitCode: 1}, errors.New("missing image")
		}
		if img.rmError != "" {
			return CommandResult{Stderr: []byte(img.rmError), ExitCode: 1}, errors.New("image in use")
		}
		delete(d.images, args[2])
		return CommandResult{}, nil
	}
	return CommandResult{ExitCode: 1}, errors.New("unexpected Docker image command")
}

func containsSequence(have []string, want ...string) bool {
	for i := 0; i+len(want) <= len(have); i++ {
		if reflect.DeepEqual(have[i:i+len(want)], want) {
			return true
		}
	}
	return false
}

func imageTestHost(t *testing.T, goos string) (*osHost, *imageDockerRunner) {
	t.Helper()
	h := newOSHost(t, goos)
	requireOK(t, h.ensure(sandboxConfig(t, goos, true, setupVMSettings)))
	writeHostFile(t, h.testHost, "/usr/bin/docker", "fake Docker CLI\n")
	d := &imageDockerRunner{other: h.env.Runner, images: map[string]*testDockerImage{}}
	h.env.Runner = d
	return h, d
}

func writeImageStore(t *testing.T, h *osHost, a SandboxAccount, owner string, overlay, alias, run string) string {
	t.Helper()
	writeHostFile(t, h.testHost, filepath.Join(a.Home, h.env.daemonStateRel(), "state.json"), "{}")
	doc := map[string]any{"version": 1, "owner": owner}
	if overlay != "" {
		doc["images"] = []map[string]any{{"tag": overlay}}
	}
	if alias != "" || run != "" {
		var runs []map[string]any
		if alias != "" {
			runs = append(runs, map[string]any{"tag": alias, "alias": true})
		}
		if run != "" {
			runs = append(runs, map[string]any{"tag": run})
		}
		doc["run_images"] = runs
	}
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(a.Home, userSandboxDataRel, "images.json")
	writeHostFile(t, h.testHost, path, string(data))
	return path
}

func (d *imageDockerRunner) add(tag, owner string, uid int, idDigit string, run bool) {
	labels := map[string]string{image.LabelSandboxImage: "1", image.LabelOwner: owner, image.LabelUID: strconv.Itoa(uid)}
	if run {
		labels[image.LabelRunImage] = "1"
	}
	d.images[tag] = &testDockerImage{tag: tag, id: "sha256:" + strings.Repeat(idDigit, 64), labels: labels}
}

func (d *imageDockerRunner) removals() []string {
	var out []string
	for _, call := range d.calls {
		if len(call) >= 2 && call[1] == "rm" {
			out = append(out, call[2])
		}
	}
	return out
}

func TestSandboxPurgeRemovesOnlyAccountImagesInDependencyOrder(t *testing.T) {
	h, docker := imageTestHost(t, "linux")
	overlay := "defenseclaw/sandbox:sample-u1000"
	alias := "defenseclaw.invalid/sandbox:sample-u1000"
	run := "defenseclaw.invalid/sandbox-run:sample-u1000"
	store := writeImageStore(t, h, h.alice, sampleImageOwner, overlay, alias, run)
	docker.add(overlay, sampleImageOwner, h.alice.UID, "a", false)
	docker.add(alias, sampleImageOwner, h.alice.UID, "a", false)
	docker.add(run, sampleImageOwner, h.alice.UID, "b", true)
	docker.add("defenseclaw/sandbox:other-owner", otherImageOwner, h.alice.UID, "c", false)
	docker.add("defenseclaw/sandbox:other-uid", sampleImageOwner, h.alice.UID+1, "d", false)
	docker.images["ordinary/base:latest"] = &testDockerImage{tag: "ordinary/base:latest", id: "sha256:" + strings.Repeat("e", 64), labels: map[string]string{}}
	docker.onImage = func(args []string) {
		if args[1] == "ls" {
			if !reflect.DeepEqual(h.ops.events, []string{"teardown alice", "stop alice"}) {
				t.Errorf("Docker list ran before teardown and unit stop: %v", h.ops.events)
			}
			if _, err := os.Stat(h.env.P(store)); err != nil {
				t.Errorf("image store was removed before Docker list: %v", err)
			}
		}
	}
	r := h.run(Options{Action: ActionUninstall, Purge: true})
	requireOK(t, r)
	if got, want := docker.removals(), []string{run, alias, overlay}; !reflect.DeepEqual(got, want) {
		t.Errorf("image rm order = %v, want %v", got, want)
	}
	for _, tag := range []string{"defenseclaw/sandbox:other-owner", "defenseclaw/sandbox:other-uid", "ordinary/base:latest"} {
		if docker.images[tag] == nil {
			t.Errorf("foreign or other-account image %s was removed", tag)
		}
	}
	if !containsLine(r.Changes, "removed 3 DefenseClaw sandbox images of user alice") || h.exists(store) {
		t.Errorf("purge changes = %v; image store still present = %v", r.Changes, h.exists(store))
	}
	if warning := messagesOf(r.Warnings, codeSandboxUserState); !strings.Contains(warning, "account uid label did not match") {
		t.Errorf("the forged-owner image was not reported: %s", warning)
	}
}

func TestSandboxPurgeKeepsAccountOwnersSeparate(t *testing.T) {
	h, docker := imageTestHost(t, "linux")
	other := SandboxAccount{Name: "sample-other", UID: h.alice.UID, GID: h.alice.GID, Home: "/home/sample-other"}
	if err := os.MkdirAll(h.env.P(other.Home), 0o755); err != nil {
		t.Fatal(err)
	}
	first := "defenseclaw/sandbox:first-u1000"
	second := "defenseclaw/sandbox:second-u1000"
	writeImageStore(t, h, h.alice, sampleImageOwner, first, "", "")
	writeImageStore(t, h, other, otherImageOwner, second, "", "")
	docker.add(first, sampleImageOwner, h.alice.UID, "a", false)
	docker.add(second, otherImageOwner, other.UID, "b", false)
	// Use the lifecycle's per-account loop directly: the host fixture cannot
	// chown a second home, while production's account enumerator deduplicates
	// real accounts by their distinct uid.
	l := &lifecycle{env: h.env, result: enterprisestatus.New(ActionUninstall, "", "linux", "1.0.2"), opts: Options{Purge: true}}
	l.teardownOpenShell(context.Background(), []SandboxAccount{h.alice, other})
	if got, want := docker.removals(), []string{first, second}; !reflect.DeepEqual(got, want) {
		t.Errorf("image removals = %v, want one per owner: %v", got, want)
	}
	if !containsLine(l.result.Changes, "removed 1 DefenseClaw sandbox images of user alice") ||
		!containsLine(l.result.Changes, "removed 1 DefenseClaw sandbox images of user sample-other") {
		t.Errorf("changes = %v", l.result.Changes)
	}
}

func TestSandboxPurgeReportsAnImageItCannotRemoveAndStillPurges(t *testing.T) {
	h, docker := imageTestHost(t, "linux")
	stuck := []string{"defenseclaw/sandbox:stuck-one-u1000", "defenseclaw/sandbox:stuck-two-u1000"}
	removed := "defenseclaw/sandbox:removed-u1000"
	store := writeImageStore(t, h, h.alice, sampleImageOwner, stuck[0], "", "")
	docker.add(stuck[0], sampleImageOwner, h.alice.UID, "a", false)
	docker.add(stuck[1], sampleImageOwner, h.alice.UID, "c", false)
	docker.add(removed, sampleImageOwner, h.alice.UID, "b", false)
	for _, tag := range stuck {
		docker.images[tag].rmError = "Error response from daemon: conflict: image is being used by a running container\nsecond error line"
	}
	r := h.run(Options{Action: ActionUninstall, Purge: true})
	requireOK(t, r)
	if docker.images[stuck[0]] == nil || docker.images[stuck[1]] == nil || docker.images[removed] != nil || h.exists(store) {
		t.Errorf("purge did not keep the stuck image, remove the other, and purge files")
	}
	for _, tag := range stuck {
		var matching int
		for _, warning := range r.Warnings {
			if strings.Contains(warning.Message, tag) {
				matching++
				for _, want := range []string{"alice", "being used", "docker image rm " + tag, "(" + docker.images[tag].id[7:19] + ")"} {
					if !strings.Contains(warning.Message, want) {
						t.Errorf("warning %q lacks %q", warning.Message, want)
					}
				}
				if strings.Contains(warning.Message, "second error line") {
					t.Errorf("warning includes more than Docker's first error line: %s", warning.Message)
				}
			}
		}
		if matching != 1 {
			t.Errorf("want exactly one leftover warning for %s, got %d: %+v", tag, matching, r.Warnings)
		}
	}
	jsonResult, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, tag := range stuck {
		if !strings.Contains(string(jsonResult), tag) || !strings.Contains(string(jsonResult), "docker image rm "+tag) {
			t.Errorf("JSON result misses %s: %s", tag, jsonResult)
		}
	}
}

func TestSandboxImageCleanupGuardsAndDockerUnavailable(t *testing.T) {
	for _, tc := range []struct {
		name     string
		prepare  func(*testing.T, *osHost) string
		wantWarn string
	}{
		{name: "no image store", prepare: func(t *testing.T, h *osHost) string {
			return ""
		}},
		{name: "invalid owner", prepare: func(t *testing.T, h *osHost) string {
			path := writeImageStore(t, h, h.alice, "not-an-owner", "", "", "")
			return path
		}, wantWarn: "no valid 16-hex owner"},
		{name: "symlinked store", prepare: func(t *testing.T, h *osHost) string {
			path := writeImageStore(t, h, h.alice, sampleImageOwner, "", "", "")
			if err := os.Rename(h.env.P(path), h.env.P(path+".target")); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("images.json.target", h.env.P(path)); err != nil {
				t.Fatal(err)
			}
			return path
		}, wantWarn: "could not safely read"},
		{name: "symlinked parent", prepare: func(t *testing.T, h *osHost) string {
			path := writeImageStore(t, h, h.alice, sampleImageOwner, "", "", "")
			parent := filepath.Dir(h.env.P(path))
			if err := os.Rename(parent, parent+".target"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Base(parent)+".target", parent); err != nil {
				t.Fatal(err)
			}
			return path
		}, wantWarn: "could not safely read"},
		{name: "own installation", prepare: func(t *testing.T, h *osHost) string {
			path := writeImageStore(t, h, h.alice, sampleImageOwner, "", "", "")
			writeHostFile(t, h.testHost, filepath.Join(h.alice.Home, ".defenseclaw/config.yaml"), "own install\n")
			return path
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, docker := imageTestHost(t, "linux")
			path := tc.prepare(t, h)
			before := ""
			if path != "" {
				data, err := os.ReadFile(h.env.P(path))
				if err == nil {
					before = string(data)
				}
			}
			r := enterprisestatus.New(ActionUninstall, "", "linux", "1.0.2")
			if path == "" && h.exists(filepath.Join(h.alice.Home, userSandboxDataRel, "images.json")) {
				t.Fatal("no-store fixture already has an image store")
			}
			(&lifecycle{env: h.env, result: r}).purgeAccountSandboxImages(context.Background(), h.alice)
			if len(docker.calls) != 0 {
				t.Errorf("unexpected Docker calls: %v", docker.calls)
			}
			if path != "" {
				data, err := os.ReadFile(h.env.P(path))
				if err == nil && string(data) != before {
					t.Errorf("cleanup changed the image store")
				}
			}
			if path == "" && h.exists(filepath.Join(h.alice.Home, userSandboxDataRel, "images.json")) {
				t.Error("cleanup created an image store")
			}
			if tc.wantWarn != "" && !strings.Contains(messagesOf(r.Warnings, codeSandboxUserState), tc.wantWarn) {
				t.Errorf("warnings = %+v, want %q", r.Warnings, tc.wantWarn)
			}
		})
	}
	t.Run("Docker is missing", func(t *testing.T) {
		h, docker := imageTestHost(t, "linux")
		store := writeImageStore(t, h, h.alice, sampleImageOwner, "", "", "")
		if err := os.Remove(h.env.P("/usr/bin/docker")); err != nil {
			t.Fatal(err)
		}
		r := h.run(Options{Action: ActionUninstall, Purge: true})
		requireOK(t, r)
		if len(docker.calls) != 0 || !strings.Contains(messagesOf(r.Warnings, codeSandboxUserState), "Docker CLI is missing") ||
			!strings.Contains(messagesOf(r.Warnings, codeSandboxUserState), "docker image ls --filter") || h.exists(store) {
			t.Errorf("calls = %v, warnings = %+v", docker.calls, r.Warnings)
		}
	})
	t.Run("Docker is not running", func(t *testing.T) {
		h, docker := imageTestHost(t, "linux")
		store := writeImageStore(t, h, h.alice, sampleImageOwner, "", "", "")
		docker.listErr = "Cannot connect to the Docker daemon"
		r := h.run(Options{Action: ActionUninstall, Purge: true})
		requireOK(t, r)
		if !strings.Contains(messagesOf(r.Warnings, codeSandboxUserState), docker.listErr) || len(docker.removals()) != 0 || h.exists(store) {
			t.Errorf("removals = %v, warnings = %+v", docker.removals(), r.Warnings)
		}
	})
}

func TestSandboxImageStoreRefusesForeignOwnerAndOversizeFile(t *testing.T) {
	h, _ := imageTestHost(t, "linux")
	path := writeImageStore(t, h, h.alice, sampleImageOwner, "", "", "")
	f, err := os.Open(h.env.P(path))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	st := info.Sys().(*syscall.Stat_t)
	if _, err := readSandboxImageStoreFile(f, h.alice.UID+1, uint64(st.Dev), st.Ino); err == nil || !strings.Contains(err.Error(), "not a regular file owned") {
		t.Errorf("foreign-owned store error = %v", err)
	}
	large := strings.Repeat("x", imageStoreMaxBytes+1)
	if err := os.WriteFile(h.env.P(path), []byte(large), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readSandboxImageStoreFile(f, h.alice.UID, uint64(st.Dev), st.Ino); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Errorf("oversize store error = %v", err)
	}
}

func TestSandboxImageCleanupNonPurgeAndDarwinDoNotUseRootDocker(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h, docker := imageTestHost(t, goos)
			tag := "defenseclaw/sandbox:kept-u1000"
			writeImageStore(t, h, h.alice, sampleImageOwner, tag, "", "")
			docker.add(tag, sampleImageOwner, h.alice.UID, "a", false)
			r := h.run(Options{Action: ActionUninstall, Purge: goos == "darwin"})
			requireOK(t, r)
			if len(docker.calls) != 0 || docker.images[tag] == nil {
				t.Errorf("%s issued image calls %v or removed the kept image", goos, docker.calls)
			}
		})
	}
}
