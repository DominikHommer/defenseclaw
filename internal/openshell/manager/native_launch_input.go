// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package manager

import (
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"
	"sync/atomic"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell/harness"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/triage"
	"github.com/defenseclaw/defenseclaw/internal/sandboxruntime"
)

// NativeLaunchInput is an owned host-only input for one producer invocation.
// It carries client intent as data, never executable or policy authority.
// Model credentials are accessible only after PlanModel validates the selected
// agent profile against this exact resolution and the producer's held assets.
// Neither the gateway judge configuration nor ambient credentials are consulted.
type NativeLaunchInput struct {
	run      *sandboxruntime.HostResolvedRun
	policy   *sandboxruntime.ExecutionPolicy
	identity sandboxruntime.SessionIdentity
	harness  sandboxruntime.HarnessIdentity
	spec     *harness.Spec
	intent   *sandboxapi.RunIntent
	request  *sandboxapi.LLMCredential
	mode     string
	model    string
	planned  *atomic.Bool
}

func nativeInputRefusal() error {
	return sandboxapi.Errorf(sandboxapi.CodePolicyRejected, "native launch input does not match its owned model policy")
}

// ownLLMCredential owns the map before any host callback can observe the request.
// It changes no legacy credential selection or validation behavior.
func ownLLMCredential(request *sandboxapi.LLMCredential) *sandboxapi.LLMCredential {
	if request == nil {
		return nil
	}
	owned := *request
	owned.Credentials = maps.Clone(request.Credentials)
	return &owned
}

// selectedNativeLLM accepts only an actual profile in this harness's roster.
// The existing provider classifier is used only after that acceptance, and its
// result must be a concrete existing sandbox LLM mode. A vendor profile without
// such a mode remains unsupported rather than being guessed into another mode.
func selectedNativeLLM(spec *harness.Spec, request *sandboxapi.LLMCredential) (string, error) {
	if request == nil {
		return config.OpenShellLLMNone, nil
	}
	if spec == nil {
		return "", nativeInputRefusal()
	}
	if _, err := spec.CredentialProfile(strings.TrimSpace(request.Profile), request.BedrockRegion); err != nil {
		return "", sandboxapi.Errorf(sandboxapi.CodeInvalid, "native agent credential profile is unsupported")
	}
	mode := credentialProvider(request.Profile)
	if mode == config.OpenShellLLMNone || mode == config.OpenShellLLMAuto ||
		!slices.Contains(config.OpenShellLLMChoices, mode) {
		return "", sandboxapi.Errorf(sandboxapi.CodeInvalid, "native agent credential profile has no supported model mode")
	}
	return mode, nil
}

func newNativeLaunchInput(run *sandboxruntime.HostResolvedRun, policy *sandboxruntime.ExecutionPolicy,
	identity sandboxruntime.SessionIdentity, admitted sandboxruntime.HarnessIdentity, spec *harness.Spec,
	intent *sandboxapi.RunIntent, request *sandboxapi.LLMCredential,
) (*NativeLaunchInput, error) {
	ownedIntent, err := sandboxapi.OwnRunIntent(intent)
	if err != nil {
		return nil, err
	}
	request = ownLLMCredential(request)
	mode, err := selectedNativeLLM(spec, request)
	if err != nil {
		return nil, err
	}
	input := &NativeLaunchInput{run: run, policy: policy, identity: identity, harness: admitted,
		spec: spec, intent: ownedIntent, request: request, mode: mode, planned: &atomic.Bool{}}
	if err := input.ValidateFor(run, policy, identity, admitted); err != nil {
		return nil, err
	}
	if request != nil {
		var args []string
		if ownedIntent != nil {
			args = ownedIntent.Args
		}
		input.model, _, _ = spec.Model(strings.TrimSpace(request.Profile), args)
		if len(input.model) == 0 || len(input.model) > 256 || !utf8.ValidString(input.model) ||
			strings.TrimSpace(input.model) != input.model ||
			strings.ContainsFunc(input.model, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
			return nil, sandboxapi.Errorf(sandboxapi.CodeInvalid, "native agent model must be selected explicitly or by its provider profile")
		}
	}
	return input, nil
}

// ValidateFor refuses reuse under another session, policy, resolution or harness.
// The identity tuples are not reconstructed from a JSON projection.
func (input *NativeLaunchInput) ValidateFor(run *sandboxruntime.HostResolvedRun, policy *sandboxruntime.ExecutionPolicy,
	identity sandboxruntime.SessionIdentity, admitted sandboxruntime.HarnessIdentity,
) error {
	if input == nil || input.run == nil || input.policy == nil || input.spec == nil || input.planned == nil ||
		input.run != run || input.policy != policy || input.harness != admitted ||
		sandboxruntime.ValidateOwnedSession(input.identity, identity) != nil || admitted.Validate() != nil {
		return nativeInputRefusal()
	}
	selection, ok := policy.ModelBrokerPolicy()
	if !ok || selection.Harness != input.spec.Name || selection.HarnessIdentity != admitted ||
		selection.LLM != input.mode || selection.Offline != (input.request == nil) {
		return nativeInputRefusal()
	}
	if _, _, err := run.PlanningPolicy(); err != nil {
		return nativeInputRefusal()
	}
	if input.request != nil {
		for _, capability := range []sandboxruntime.Capability{sandboxruntime.BrokerEgress,
			sandboxruntime.HostCredentials, sandboxruntime.ExecutableCredentialBinding} {
			if !slices.Contains(policy.RequiredCapabilities(), capability) {
				return nativeInputRefusal()
			}
		}
	}
	return nil
}

// Intent returns a fresh copy. Mutating it cannot change this invocation.
func (input *NativeLaunchInput) Intent() *sandboxapi.RunIntent {
	if input == nil || input.intent == nil {
		return nil
	}
	owned := *input.intent
	owned.Args = slices.Clone(input.intent.Args)
	return &owned
}

func (input *NativeLaunchInput) Offline() bool {
	return input != nil && input.request == nil
}

// PlanModel validates the exact existing provider schema using the trusted
// producer's admitted in-image network realpaths. No synthetic binary path may
// stand in for held assets. These paths are planning metadata, never proof of
// executable credential binding; the backend still needs that independently
// qualified mechanism. It creates no provider, endpoint or native process.
// Its result must stay in the host broker; credentials never enter Spec or Env.
func (input *NativeLaunchInput) PlanModel(heldNetworkRealpaths []string) (*NativeModelPlan, error) {
	if input == nil || input.ValidateFor(input.run, input.policy, input.identity, input.harness) != nil {
		return nil, nativeInputRefusal()
	}
	if input.request == nil {
		return nil, nil
	}
	effective, _, err := input.run.PlanningPolicy()
	if err != nil {
		return nil, nativeInputRefusal()
	}
	if refusal := credentialsRefusal(effective.Floor(), input.request.Profile, false); refusal != nil {
		return nil, nativeInputRefusal()
	}
	plan, err := planLLM(input.spec, input.request, slices.Clone(heldNetworkRealpaths))
	if err != nil {
		return nil, nativeInputRefusal()
	}
	hosts := make([]string, 0, len(plan.profile.Spec.Endpoints))
	for _, endpoint := range plan.profile.Spec.Endpoints {
		if err := modelEndpointRefusal(effective, triage.NormalizeHost(endpoint.Host)); err != nil {
			return nil, nativeInputRefusal()
		}
		hosts = append(hosts, endpoint.Host)
	}
	selection, ok := input.policy.ModelBrokerPolicy()
	if !ok {
		return nil, nativeInputRefusal()
	}
	result := &NativeModelPlan{run: input.run, policy: input.policy, identity: input.identity,
		harness: input.harness, selection: selection, profile: plan.profile.Template,
		model: input.model, hosts: hosts, credentials: maps.Clone(plan.credentials)}
	input.planned.Store(true)
	return result, nil
}

func (input *NativeLaunchInput) validatePrepared(spec sandboxruntime.Spec) error {
	if input == nil || spec.Offline != input.Offline() {
		return nativeInputRefusal()
	}
	if input.request == nil {
		if spec.CredentialProfile != "" {
			return nativeInputRefusal()
		}
		return nil
	}
	if !input.planned.Load() || spec.CredentialProfile != strings.TrimSpace(input.request.Profile) {
		return nativeInputRefusal()
	}
	return nil
}

// NativeModelPlan is the host-only result of validating an agent's explicit
// credential association. It is not a customer credential store, a judge
// configuration or a backend activation. All returned collections are copies.
type NativeModelPlan struct {
	run         *sandboxruntime.HostResolvedRun
	policy      *sandboxruntime.ExecutionPolicy
	identity    sandboxruntime.SessionIdentity
	harness     sandboxruntime.HarnessIdentity
	selection   sandboxruntime.ModelBrokerPolicy
	profile     string
	model       string
	hosts       []string
	credentials map[string]string
}

func (plan *NativeModelPlan) ValidateFor(run *sandboxruntime.HostResolvedRun, policy *sandboxruntime.ExecutionPolicy,
	identity sandboxruntime.SessionIdentity, admitted sandboxruntime.HarnessIdentity,
) error {
	if plan == nil || plan.run == nil || plan.policy == nil || plan.run != run || plan.policy != policy || plan.harness != admitted ||
		sandboxruntime.ValidateOwnedSession(plan.identity, identity) != nil {
		return nativeInputRefusal()
	}
	selection, ok := policy.ModelBrokerPolicy()
	if !ok || selection != plan.selection || selection.Offline || selection.HarnessIdentity != admitted {
		return nativeInputRefusal()
	}
	return nil
}

func (plan *NativeModelPlan) Selection() sandboxruntime.ModelBrokerPolicy {
	if plan == nil {
		return sandboxruntime.ModelBrokerPolicy{}
	}
	return plan.selection
}

func (plan *NativeModelPlan) ProfileID() string {
	if plan == nil {
		return ""
	}
	return plan.profile
}

func (plan *NativeModelPlan) Model() string {
	if plan == nil {
		return ""
	}
	return plan.model
}

func (plan *NativeModelPlan) Hosts() []string {
	if plan == nil {
		return nil
	}
	return slices.Clone(plan.hosts)
}

// WithHostCredentials exposes a copy only to the trusted host producer/broker.
// The callback must not log, serialize, persist or copy these values to a guest.
// This method performs no ambient lookup and supplies no default credential.
func (plan *NativeModelPlan) WithHostCredentials(use func(map[string]string) error) error {
	if plan == nil || use == nil ||
		plan.ValidateFor(plan.run, plan.policy, plan.identity, plan.harness) != nil {
		return nativeInputRefusal()
	}
	return use(maps.Clone(plan.credentials))
}

func (NativeLaunchInput) MarshalJSON() ([]byte, error) { return nil, nativeInputRefusal() }
func (*NativeLaunchInput) UnmarshalJSON([]byte) error  { return nativeInputRefusal() }
func (NativeLaunchInput) MarshalText() ([]byte, error) { return nil, nativeInputRefusal() }
func (*NativeLaunchInput) UnmarshalText([]byte) error  { return nativeInputRefusal() }
func (NativeLaunchInput) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "[host native launch input]")
}
func (NativeModelPlan) MarshalJSON() ([]byte, error) { return nil, nativeInputRefusal() }
func (*NativeModelPlan) UnmarshalJSON([]byte) error  { return nativeInputRefusal() }
func (NativeModelPlan) MarshalText() ([]byte, error) { return nil, nativeInputRefusal() }
func (*NativeModelPlan) UnmarshalText([]byte) error  { return nativeInputRefusal() }
func (NativeModelPlan) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "[host native model plan]")
}
