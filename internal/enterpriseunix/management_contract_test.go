// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package enterpriseunix

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v5"

	"github.com/defenseclaw/defenseclaw/internal/enterprisebundle"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// The management agent contract (packaging/mdm/contract/management-agent.md)
// publishes a JSON Schema for every document a management agent reads. These
// tests drive real lifecycle runs on the fake host and validate the results
// and the public receipt files against those schemas. The CLI prints these
// results unchanged with --json.

const managementContractDir = "../../packaging/mdm/contract"

// pendingContractItems are contract items whose code is not in this tree
// yet; a check that needs one skips. Delete an entry when its change lands.
var pendingContractItems = map[string]string{
	"receipt_id": "bundle.receipt_id in the apply and status results",
}

func requireContractItem(t *testing.T, item string) {
	t.Helper()
	if what, pending := pendingContractItems[item]; pending {
		t.Skipf("contract item %s is not in this tree yet (%s)", item, what)
	}
}

type contractSchemas map[string]*jsonschema.Schema

// compileManagementContract compiles every schema of the contract folder
// under its $id, so the cross-file $refs resolve without a network loader.
func compileManagementContract(t *testing.T) contractSchemas {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(filepath.FromSlash(managementContractDir), "*.schema.json"))
	if err != nil || len(paths) == 0 {
		t.Fatalf("contract schemas: %v (%d found)", err, len(paths))
	}
	compiler := jsonschema.NewCompiler()
	compiler.Draft = jsonschema.Draft2020
	compiler.AssertFormat = true
	ids := map[string]string{}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var head struct {
			ID string `json:"$id"`
		}
		if err := json.Unmarshal(data, &head); err != nil || head.ID == "" {
			t.Fatalf("%s: no $id (%v)", path, err)
		}
		if err := compiler.AddResource(head.ID, bytes.NewReader(data)); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		ids[filepath.Base(path)] = head.ID
	}
	schemas := contractSchemas{}
	for name, id := range ids {
		schema, err := compiler.Compile(id)
		if err != nil {
			t.Fatalf("compile %s: %v", name, err)
		}
		schemas[name] = schema
	}
	return schemas
}

// validate requires document to be exactly one JSON value that schema name
// accepts, and returns it decoded.
func (c contractSchemas) validate(t *testing.T, name string, document []byte) map[string]any {
	t.Helper()
	schema, ok := c[name]
	if !ok {
		t.Fatalf("no contract schema %s", name)
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		t.Fatalf("%s: not JSON: %v\n%s", name, err, document)
	}
	if decoder.More() {
		t.Fatalf("%s: more than one JSON document:\n%s", name, document)
	}
	if err := schema.Validate(value); err != nil {
		t.Fatalf("%s rejects a real result: %v\n%s", name, err, document)
	}
	object, _ := value.(map[string]any)
	return object
}

func (c contractSchemas) validateResult(t *testing.T, name string, result *enterprisestatus.Result) map[string]any {
	t.Helper()
	document, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	return c.validate(t, name, document)
}

// TestManagementContractBundleApplyResults validates the apply results a
// management agent acts on (confirmed, already_applied, refused), the device
// status after them and the public receipt files.
func TestManagementContractBundleApplyResults(t *testing.T) {
	schemas := compileManagementContract(t)
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			b := newBundleHost(t, goos)
			v1, v2, _ := bundleConfigs(b.testHost)
			b.mapPromotedBundleOwners(1)
			first := b.apply(b.dir(1, v1))
			requireOK(t, first)
			schemas.validateResult(t, "lifecycle-result.schema.json", first)
			b.mapPromotedBundleOwners(2)
			path := b.dir(2, v2)

			applied := b.apply(path)
			requireOK(t, applied)
			doc := schemas.validateResult(t, "lifecycle-result.schema.json", applied)
			if applied.Bundle == nil || applied.Bundle.State != enterprisebundle.StateConfirmed || applied.Bundle.BundleID != bundleID(2) {
				t.Fatalf("apply did not confirm: %+v", applied.Bundle)
			}

			store := b.env.bundleStore()
			events, err := filepath.Glob(filepath.Join(store.PublicReceiptEventsDir(), "*.json"))
			if err != nil || len(events) != 2 {
				t.Fatalf("receipt events %v (%v)", events, err)
			}
			receiptID := ""
			for _, file := range append(events, store.PublicReceiptPath()) {
				raw, err := os.ReadFile(file)
				if err != nil {
					t.Fatal(err)
				}
				receipt := schemas.validate(t, "bundle-receipt.schema.json", raw)
				if receipt["state"] != "confirmed" {
					t.Fatalf("%s: %s", file, raw)
				}
				if receipt["bundle_id"] == bundleID(2) {
					receiptID, _ = receipt["receipt_id"].(string)
				}
			}
			t.Run("receipt_id of a fresh apply", func(t *testing.T) {
				requireContractItem(t, "receipt_id")
				if got := doc["bundle"].(map[string]any)["receipt_id"]; got != receiptID {
					t.Fatalf("bundle.receipt_id = %v, want the receipt written, %s", got, receiptID)
				}
			})

			// The same bytes again: a success no-op that writes no receipt
			// and reports the confirmed receipt.
			again := b.apply(path)
			requireOK(t, again)
			doc = schemas.validateResult(t, "lifecycle-result.schema.json", again)
			if !again.Noop || again.NoopReason != "already_applied" {
				t.Fatalf("repeated delivery: noop=%v reason=%q", again.Noop, again.NoopReason)
			}
			t.Run("receipt_id of already_applied", func(t *testing.T) {
				requireContractItem(t, "receipt_id")
				if got := doc["bundle"].(map[string]any)["receipt_id"]; got != receiptID {
					t.Fatalf("bundle.receipt_id = %v, want the current confirmed receipt, %s", got, receiptID)
				}
			})

			// Other bytes at the same version: refused, final.
			refused := b.apply(b.dir(2, v1))
			requireError(t, refused, string(enterprisebundle.CodeVersionNotNewer))
			schemas.validateResult(t, "lifecycle-result.schema.json", refused)
			if refused.ExitCode != enterprisestatus.UnixExitFailure {
				t.Fatalf("refusal exit %d", refused.ExitCode)
			}

			status := b.run(Options{Action: ActionStatus})
			requireOK(t, status)
			schemas.validateResult(t, "lifecycle-result.schema.json", status)
			if status.Bundle == nil || status.Bundle.BundleID != bundleID(2) || status.Bundle.State != enterprisebundle.StateConfirmed {
				t.Fatalf("status bundle block = %+v", status.Bundle)
			}
		})
	}
}

// TestManagementContractSecretAndBusyResults validates what Linux and macOS
// `enterprise secret set` print (lifecycle result v2 through
// secret-result.schema.json) and the busy result an agent retries.
func TestManagementContractSecretAndBusyResults(t *testing.T) {
	schemas := compileManagementContract(t)
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			const value = "contract-test-credential-value"

			stored := h.run(Options{Action: ActionEnsure, Reason: "secret", Mutate: func(ctx context.Context) error {
				return h.env.WriteSecret(ctx, "ai-defense-api-key", []byte(value))
			}})
			requireOK(t, stored)
			document, err := json.Marshal(stored)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(document, []byte(value)) {
				t.Fatalf("the credential value is in the result: %s", document)
			}
			schemas.validate(t, "secret-result.schema.json", document)

			failed := h.run(Options{Action: ActionEnsure, Reason: "secret", Mutate: func(context.Context) error {
				return errors.New("the credential could not be written")
			}})
			requireError(t, failed, codeChange)
			schemas.validateResult(t, "secret-result.schema.json", failed)

			states, err := h.env.SecretStatus()
			if err != nil {
				t.Fatal(err)
			}
			listing, err := json.Marshal(map[string]any{"schema_version": 1, "secrets": states})
			if err != nil {
				t.Fatal(err)
			}
			schemas.validate(t, "secret-result.schema.json", listing)

			held, err := h.env.acquireLock(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			defer held.release()
			h.env.LockTimeout = 50 * time.Millisecond
			for _, action := range []string{ActionEnsure, ActionStatus} {
				busy := h.run(Options{Action: action})
				requireError(t, busy, codeBusy)
				if busy.ExitCode != enterprisestatus.UnixExitBusy {
					t.Fatalf("%s busy exit %d, want %d", action, busy.ExitCode, enterprisestatus.UnixExitBusy)
				}
				schemas.validateResult(t, "lifecycle-result.schema.json", busy)
			}
		})
	}
}
