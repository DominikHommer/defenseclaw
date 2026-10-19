// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package manager

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
	"github.com/defenseclaw/defenseclaw/internal/openshell/profiles"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/sandboxruntime"
)

const nativeInputAgentSecret = "synthetic-agent-key-not-the-judge"
const nativeInputJudgeSecret = "synthetic-inspection-key-not-the-agent"

type nativeInputPolicyTelemetry struct {
	nopTelemetry
	events []audit.SandboxPolicyEvent
}

func (r *nativeInputPolicyTelemetry) RecordSandboxPolicy(_ context.Context, event audit.SandboxPolicyEvent) error {
	r.events = append(r.events, event)
	return nil
}

func nativeInputForTest(t *testing.T, edit func(*config.Config, *sandboxapi.LLMCredential, *sandboxapi.RunIntent)) (*NativeLaunchInput, error) {
	t.Helper()
	f := nativeTransaction(t)
	cfg := f.m.config()
	cfg.Sandbox.LLM = config.OpenShellLLMAuto
	cfg.LLM.Model, cfg.LLM.APIKey = "openai/synthetic-inspector", nativeInputJudgeSecret
	request := &sandboxapi.LLMCredential{Profile: profiles.AnthropicID,
		Credentials: map[string]string{"ANTHROPIC_API_KEY": nativeInputAgentSecret}}
	intent := &sandboxapi.RunIntent{Mode: "headless", Prompt: "synthetic private prompt", Args: []string{"--model", "synthetic-agent-model"}}
	if edit != nil {
		edit(cfg, request, intent)
	}
	spec, ok := harness.Get("claudecode")
	if !ok {
		t.Fatal("fixed harness is missing")
	}
	mode, err := selectedNativeLLM(spec, request)
	if err != nil {
		return nil, err
	}
	admitted := f.b.info.Harnesses["claudecode"].Identity
	run, policy, _, err := f.m.opts.Native.resolve(packs.Flags{Harness: "claudecode", Copy: true, Safe: true,
		NoMCP: true, SelectedLLM: &mode}, sandboxruntime.PolicyOptions{Harness: admitted, Offline: false})
	if err != nil {
		return nil, err
	}
	identity := sandboxruntime.SessionIdentity{Owner: "synthetic-owner", ID: strings.Repeat("b", 32),
		Name: "native-input", Runtime: f.b.info.Identity}
	input, err := newNativeLaunchInput(run, policy, identity, admitted, spec, intent, request)
	if err != nil {
		return nil, err
	}
	if request.Credentials != nil {
		request.Credentials["ANTHROPIC_API_KEY"] = "mutated-caller-map"
	}
	if len(intent.Args) > 1 {
		intent.Args[1] = "mutated-caller-model"
	}
	intent.Prompt = "mutated-caller-prompt"
	return input, nil
}

func TestNativeLaunchInputOwnsAndRedactsAgentSelection(t *testing.T) {
	input, err := nativeInputForTest(t, nil)
	nativeMust(t, err)
	intent := input.Intent()
	if intent == nil || intent.Prompt != "synthetic private prompt" || intent.Args[1] != "synthetic-agent-model" {
		t.Fatal("caller mutation changed the owned intent")
	}
	intent.Args[1], intent.Prompt = "mutated-producer-model", "mutated-producer-prompt"
	if again := input.Intent(); again.Args[1] != "synthetic-agent-model" || again.Prompt != "synthetic private prompt" {
		t.Fatal("producer mutation changed the owned intent")
	}
	plan, err := input.PlanModel([]string{"/synthetic/held-agent"})
	nativeMust(t, err)
	if plan == nil || plan.ProfileID() != profiles.AnthropicID || plan.Model() != "synthetic-agent-model" ||
		plan.ModelSelection() != (sandboxruntime.ModelSelection{Kind: sandboxruntime.ModelSelectionExplicit, Name: "synthetic-agent-model"}) ||
		plan.Selection().LLM != config.OpenShellLLMAnthropic || plan.Selection().Offline ||
		!slices.Contains(plan.Hosts(), "api.anthropic.com") {
		t.Fatal("agent profile/model was replaced with inspector or sandbox policy profile")
	}
	hosts := plan.Hosts()
	hosts[0] = "mutated.example"
	if slices.Contains(plan.Hosts(), "mutated.example") {
		t.Fatal("host endpoint inspection aliases the plan")
	}
	for attempt := 0; attempt < 2; attempt++ {
		nativeMust(t, plan.WithHostCredentials(func(values map[string]string) error {
			if len(values) != 1 || values["ANTHROPIC_API_KEY"] != nativeInputAgentSecret {
				t.Fatal("agent credentials were aliased, replaced or supplemented by the judge")
			}
			values["ANTHROPIC_API_KEY"] = "mutated-consumer-key"
			values["OPENAI_API_KEY"] = nativeInputJudgeSecret
			return nil
		}))
	}
	for _, value := range []any{input, *input, plan, *plan} {
		if raw, err := json.Marshal(value); err == nil || len(raw) != 0 {
			t.Fatal("host launch/model authority was serialized")
		}
		text := fmt.Sprintf("%v %+v %#v %s %q %x", value, value, value, value, value, value)
		for _, private := range []string{nativeInputAgentSecret, nativeInputJudgeSecret, "synthetic private prompt", "synthetic-agent-model"} {
			if strings.Contains(text, private) {
				t.Fatal("formatting disclosed private launch/model data")
			}
		}
	}
	if raw, err := input.MarshalText(); err == nil || len(raw) != 0 {
		t.Fatal("host launch input was text serialized")
	}
	if raw, err := plan.MarshalText(); err == nil || len(raw) != 0 {
		t.Fatal("host model plan was text serialized")
	}
	foreign := input.identity
	foreign.ID = strings.Repeat("c", 32)
	if input.ValidateFor(input.run, input.policy, foreign, input.harness) == nil ||
		plan.ValidateFor(input.run, input.policy, foreign, input.harness) == nil {
		t.Fatal("model input crossed owned sessions")
	}
	if input.ValidateFor(&sandboxruntime.HostResolvedRun{}, input.policy, input.identity, input.harness) == nil ||
		plan.ValidateFor(input.run, &sandboxruntime.ExecutionPolicy{}, input.identity, input.harness) == nil {
		t.Fatal("model input crossed resolved policy authority")
	}
	foreignHarness := input.harness
	foreignHarness.Version += "-foreign"
	if input.ValidateFor(input.run, input.policy, input.identity, foreignHarness) == nil ||
		plan.ValidateFor(input.run, input.policy, input.identity, foreignHarness) == nil {
		t.Fatal("model input crossed admitted harness bytes")
	}
	t.Run("agent chooses when Claude profile has no default", func(t *testing.T) {
		choice, err := nativeInputForTest(t, func(_ *config.Config, _ *sandboxapi.LLMCredential, intent *sandboxapi.RunIntent) {
			intent.Args = nil
		})
		nativeMust(t, err)
		chosen, err := choice.PlanModel([]string{"/synthetic/held-agent"})
		nativeMust(t, err)
		if chosen == nil || chosen.Model() != "" ||
			chosen.ModelSelection() != (sandboxruntime.ModelSelection{Kind: sandboxruntime.ModelSelectionAgentSelected}) ||
			chosen.Selection().LLM != config.OpenShellLLMAnthropic || chosen.ProfileID() != profiles.AnthropicID {
			t.Fatal("default Claude command lost its fixed provider/profile or invented a model pin")
		}
	})
	t.Run("profile default remains distinct", func(t *testing.T) {
		spec, _ := harness.Get("claudecode")
		chosen, err := nativeModelSelection(spec, profiles.ClaudeBedrockMantleID, nil)
		nativeMust(t, err)
		if chosen.Kind != sandboxruntime.ModelSelectionProfileDefault || chosen.Name != harness.ClaudeCodeMantleDefaultModel {
			t.Fatal("harness profile default was treated as agent-selected")
		}
	})
	t.Run("duplicate explicit flags keep harness last-wins", func(t *testing.T) {
		spec, _ := harness.Get("claudecode")
		chosen, err := nativeModelSelection(spec, profiles.AnthropicID, []string{"--model=a", "--model", "b"})
		nativeMust(t, err)
		if chosen.Kind != sandboxruntime.ModelSelectionExplicit || chosen.Name != "b" {
			t.Fatal("native model selection changed the harness's duplicate-flag semantics")
		}
		chosen, err = nativeModelSelection(spec, profiles.AnthropicID, []string{"--", "--model=ignored"})
		nativeMust(t, err)
		if chosen.Kind != sandboxruntime.ModelSelectionAgentSelected {
			t.Fatal("model flag after argument terminator acquired authority")
		}
	})
}

func TestNativeLaunchInputRejectsUnboundModelPlan(t *testing.T) {
	cases := []struct {
		name  string
		edit  func(*config.Config, *sandboxapi.LLMCredential, *sandboxapi.RunIntent)
		paths []string
	}{
		{name: "missing-agent-key", edit: func(_ *config.Config, request *sandboxapi.LLMCredential, _ *sandboxapi.RunIntent) {
			request.Credentials = nil
		}},
		{name: "foreign-credential", edit: func(_ *config.Config, request *sandboxapi.LLMCredential, _ *sandboxapi.RunIntent) {
			request.Credentials["OPENAI_API_KEY"] = nativeInputJudgeSecret
		}},
		{name: "wrong-harness-profile", edit: func(_ *config.Config, request *sandboxapi.LLMCredential, _ *sandboxapi.RunIntent) {
			request.Profile = profiles.OpenAIID
		}},
		{name: "empty-explicit-model", edit: func(_ *config.Config, _ *sandboxapi.LLMCredential, intent *sandboxapi.RunIntent) {
			intent.Args = []string{"--model="}
		}},
		{name: "missing-explicit-model-value", edit: func(_ *config.Config, _ *sandboxapi.LLMCredential, intent *sandboxapi.RunIntent) {
			intent.Args = []string{"--model"}
		}},
		{name: "duplicate-last-empty", edit: func(_ *config.Config, _ *sandboxapi.LLMCredential, intent *sandboxapi.RunIntent) {
			intent.Args = []string{"--model=a", "--model="}
		}},
		{name: "flag-as-model-value", edit: func(_ *config.Config, _ *sandboxapi.LLMCredential, intent *sandboxapi.RunIntent) {
			intent.Args = []string{"--model", "--output-format"}
		}},
		{name: "no-held-network-realpaths", paths: []string{}},
		{name: "arbitrary-realpath-glob", paths: []string{"/synthetic/*"}},
		{name: "admin-credential-refusal", edit: func(cfg *config.Config, _ *sandboxapi.LLMCredential, _ *sandboxapi.RunIntent) {
			cfg.Sandbox.Admin.AllowedCredentials = []string{config.OpenShellCredentialsNone}
		}},
		{name: "admin-endpoint-refusal", edit: func(cfg *config.Config, _ *sandboxapi.LLMCredential, _ *sandboxapi.RunIntent) {
			cfg.Sandbox.Admin.EgressBlock = []string{"api.anthropic.com"}
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			input, err := nativeInputForTest(t, test.edit)
			if err == nil {
				paths := test.paths
				if paths == nil {
					paths = []string{"/synthetic/held-agent"}
				}
				var plan *NativeModelPlan
				plan, err = input.PlanModel(paths)
				if err == nil || plan != nil {
					t.Fatal("invalid agent association obtained host credentials")
				}
				if input.planned.Load() {
					t.Fatal("failed model planning enabled prepared admission")
				}
			}
			if err == nil {
				t.Fatal("invalid model input was admitted")
			}
			if strings.Contains(fmt.Sprint(err), nativeInputAgentSecret) || strings.Contains(fmt.Sprint(err), nativeInputJudgeSecret) {
				t.Fatal("model refusal disclosed credentials")
			}
		})
	}
	input, err := nativeInputForTest(t, nil)
	nativeMust(t, err)
	input.mode = config.OpenShellLLMOpenAI
	if _, err := input.PlanModel([]string{"/synthetic/held-agent"}); err == nil {
		t.Fatal("selected provider mode changed after resolution")
	}
}

func TestNativeCreateQualifiedModelInputAndSecretIsolation(t *testing.T) {
	for _, mode := range []string{"qualified", "missing-capability", "skipped-plan", "wrong-profile", "wrong-offline", "wrong-session", "admin-denied"} {
		t.Run(mode, func(t *testing.T) {
			f := nativeTransaction(t)
			telemetry := &nativeInputPolicyTelemetry{}
			f.m.tel = newTelemetryGuard(telemetry, f.m.host, f.m.logf, f.m.now)
			cfg := f.m.config()
			cfg.Sandbox.LLM = config.OpenShellLLMAuto
			cfg.LLM.Model, cfg.LLM.APIKey = "openai/synthetic-inspector", nativeInputJudgeSecret
			if mode == "admin-denied" {
				cfg.Sandbox.Admin.AllowedCredentials = []string{config.OpenShellCredentialsNone}
			}
			caps := []sandboxruntime.Capability{sandboxruntime.BrokerEgress, sandboxruntime.HostCredentials, sandboxruntime.ExecutableCredentialBinding}
			if mode == "missing-capability" {
				caps = caps[:2]
			}
			f.b.info.Supported = append(f.b.info.Supported, caps...)
			verification := f.b.info.Harnesses["claudecode"]
			verification.Supported = append(verification.Supported, caps...)
			f.b.info.Harnesses["claudecode"] = verification
			f.request.LLM = &sandboxapi.LLMCredential{Profile: profiles.AnthropicID,
				Credentials: map[string]string{"ANTHROPIC_API_KEY": nativeInputAgentSecret}}
			f.request.RunIntent = &sandboxapi.RunIntent{Mode: "headless", Prompt: "synthetic prompt", Args: []string{"--model", "synthetic-agent-model"}}
			previousResolve := f.m.opts.Native.resolve
			f.m.opts.Native.resolve = func(flags packs.Flags, options sandboxruntime.PolicyOptions) (*sandboxruntime.HostResolvedRun, *sandboxruntime.ExecutionPolicy, []packs.Violation, error) {
				// This callback runs after Create must have owned caller data.
				f.request.LLM.Credentials["ANTHROPIC_API_KEY"] = "late-caller-mutation"
				return previousResolve(flags, options)
			}
			called := false
			f.m.opts.Native.prepare = func(ctx context.Context, run *sandboxruntime.HostResolvedRun, policy *sandboxruntime.ExecutionPolicy,
				identity sandboxruntime.SessionIdentity, input *NativeLaunchInput,
			) (sandboxruntime.Spec, sandboxruntime.PreparedProcess, sandboxruntime.PolicyReceipt, error) {
				called = true
				nativeMust(t, input.ValidateFor(run, policy, identity, verification.Identity))
				if input.Offline() || input.Intent().Args[1] != "synthetic-agent-model" {
					t.Fatal("qualified producer lost its selected model input")
				}
				if mode != "skipped-plan" {
					plan, err := input.PlanModel([]string{"/synthetic/held-agent"})
					nativeMust(t, err)
					nativeMust(t, plan.WithHostCredentials(func(values map[string]string) error {
						if len(values) != 1 || values["ANTHROPIC_API_KEY"] != nativeInputAgentSecret {
							t.Fatal("producer received mutable caller data or a judge credential")
						}
						return nil
					}))
				}
				spec := sandboxruntime.Spec{Identity: identity, Harness: "claudecode", HarnessIdentity: verification.Identity,
					Offline: false, CredentialProfile: profiles.AnthropicID, GuestWorkspace: "/work",
					Command: []string{"/synthetic/held-agent", "--model", "synthetic-agent-model"}}
				switch mode {
				case "wrong-profile":
					spec.CredentialProfile = profiles.OpenAIID
				case "wrong-offline":
					spec.Offline = true
				case "wrong-session":
					spec.Identity.ID = strings.Repeat("f", 32)
				}
				raw, err := json.Marshal(spec)
				nativeMust(t, err)
				if strings.Contains(string(raw), nativeInputAgentSecret) || strings.Contains(string(raw), nativeInputJudgeSecret) {
					t.Fatal("host credentials entered guest Spec")
				}
				process, receipt, err := f.b.Prepare(ctx, policy, spec)
				return spec, process, receipt, err
			}
			view, err := f.m.Create(t.Context(), f.request)
			if mode == "qualified" {
				if err != nil || view == nil || !called || f.b.launches != 1 {
					t.Fatalf("qualified synthetic model producer failed: called=%v launches=%d error=%v", called, f.b.launches, err)
				}
				_, err = f.m.Delete(t.Context(), f.request.Name, sandboxapi.DeleteRequest{})
				nativeMust(t, err)
			} else {
				if err == nil || view != nil || f.b.launches != 0 {
					t.Fatal("unqualified or mismatched model producer launched")
				}
				if (mode == "missing-capability" || mode == "admin-denied") && called {
					t.Fatal("model refusal reached producer before qualification/credential checks")
				}
			}
			if mode == "admin-denied" {
				if !sandboxapi.IsCode(err, sandboxapi.CodeAdminViolation) || len(telemetry.events) != 1 {
					t.Fatal("credential floor refusal did not record exactly one admin violation")
				}
				event := telemetry.events[0]
				if event.Sandbox.Name != f.request.Name || event.Operation != audit.SandboxPolicyApply ||
					event.Origin != "api" || event.Target != "credentials" || event.Reason != policyReasonAdminRefused || !event.NoChange {
					t.Fatal("credential floor refusal recorded the wrong policy decision")
				}
			} else if len(telemetry.events) != 0 {
				t.Fatal("non-admin model result recorded an admin refusal")
			}
			if cfg.Sandbox.LLM != config.OpenShellLLMAuto || cfg.LLM.APIKey != nativeInputJudgeSecret {
				t.Fatal("native planning mutated source defaults or judge association")
			}
		})
	}
}
