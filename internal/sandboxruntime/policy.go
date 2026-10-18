// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package sandboxruntime

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// PolicyOptions are explicit execution requirements, not runtime enablement.
// Offline tightens all network access. The strict profile alone is not offline:
// it still permits separately authorized provider and hook broker endpoints.
type PolicyOptions struct {
	Harness   HarnessIdentity        `json:"harness_identity"`
	Authority PolicyAuthorityBinding `json:"authority"`
	Terminal  bool                   `json:"terminal"`
	Offline   bool                   `json:"offline"`
}

// PolicyAuthorityBinding identifies the host-owned broker/host-fact snapshot.
// The caller must mint/rotate this nonsecret identity or increment Generation
// whenever that authority changes, including facts absent from inspection JSON.
// It is custody metadata, not a session identity or credential authorization.
type PolicyAuthorityBinding struct {
	SnapshotID string `json:"snapshot_id"`
	Generation uint64 `json:"generation"`
}

type PolicyComponentName string

const (
	PolicyCommon    PolicyComponentName = "common"
	PolicyAuthority PolicyComponentName = "authority"
	PolicyWorkspace PolicyComponentName = "workspace"
	PolicyEgress    PolicyComponentName = "egress"
	PolicyHarness   PolicyComponentName = "harness"
	PolicyMCP       PolicyComponentName = "mcp"
	PolicyResources PolicyComponentName = "resources"
)

// PolicyComponent is a host-confidential inspection copy. Value can contain
// workspace paths and policy provenance; never send it to guests, external
// APIs, logs or telemetry. It is not an authorization input: private evaluator
// state and the curated/operator distinction remain in the host resolver.
type PolicyComponent struct {
	Name   PolicyComponentName `json:"name"`
	Digest string              `json:"digest"`
	Value  json.RawMessage     `json:"value"`
}

// PolicyComponentBinding acknowledges every field in a complete component.
// A generic capability is insufficient to acknowledge a translated policy.
type PolicyComponentBinding struct {
	Name   PolicyComponentName `json:"name"`
	Digest string              `json:"digest"`
}

// PolicyReceipt is trusted adapter evidence bound to an immutable policy and
// exact runtime/harness bytes. Never accept it from an API client or workload.
// Structural admission does not manufacture qualification or authorize a
// credential grant, installation, workspace path or process launch.
type PolicyReceipt struct {
	Runtime      RuntimeIdentity          `json:"runtime_identity"`
	Harness      HarnessIdentity          `json:"harness_identity"`
	PolicyDigest string                   `json:"policy_digest"`
	Components   []PolicyComponentBinding `json:"components"`
}

// ExecutionPolicy is a host-owned immutable policy for one resolved run. No
// constructor from JSON or backend-provided policy is supported. Its private
// evaluator retains host facts and the existing DefenseClaw broker semantics;
// exported JSON views cannot replace that authority with an MXC allowlist.
// Those views remain host-confidential and are not external API projections.
type ExecutionPolicy struct {
	effective  *packs.Effective
	options    PolicyOptions
	enabled    map[ID]bool
	required   []Capability
	components []PolicyComponent
	canonical  []byte
	digest     string
}

// ResolveExecutionPolicy reuses common projection and the existing pack,
// repository and administrative resolution. It starts no runtime or listener.
// Input snapshots must be stable during this call; no mutable input is retained.
// Nonfatal clamps remain visible as violations, matching the existing resolver.
func ResolveExecutionPolicy(cfg *config.Config, flags packs.Flags, options PolicyOptions) (*ExecutionPolicy, []packs.Violation, error) {
	if cfg == nil || !cfg.SandboxEnabled() {
		return nil, nil, sandboxapi.Errorf(sandboxapi.CodeDisabled, "sandboxes are disabled")
	}
	if options.Harness.Validate() != nil {
		return nil, nil, sandboxapi.Errorf(sandboxapi.CodeInvalid, "execution policy requires an exact harness identity")
	}
	if !sessionID.MatchString(options.Authority.SnapshotID) || options.Authority.Generation == 0 {
		return nil, nil, sandboxapi.Errorf(sandboxapi.CodeInvalid, "execution policy requires an opaque host authority snapshot identity and positive generation")
	}
	owned, err := cfg.DeepCopy()
	if err != nil {
		return nil, nil, err
	}
	owned.OpenShell, err = owned.EffectiveSandboxPolicy()
	if err != nil {
		return nil, nil, err
	}
	if err := owned.ValidateOpenShell(); err != nil {
		return nil, nil, err
	}
	flags, err = copyPolicyFlags(flags)
	if err != nil {
		return nil, nil, err
	}
	effective, violations, err := packs.Resolve(owned, flags)
	if err != nil {
		return nil, violations, err
	}
	if fatal := packs.FirstFatal(violations); fatal != nil {
		code := sandboxapi.CodePolicyViolation
		if fatal.Admin() {
			code = sandboxapi.CodeAdminViolation
		}
		return nil, violations, &sandboxapi.Error{Code: code, Message: fatal.Message, Detail: fatal.Detail}
	}
	if effective.Harness == "" {
		return nil, violations, sandboxapi.Errorf(sandboxapi.CodeInvalid, "execution policy requires one admitted harness")
	}
	if allowed := effective.Floor().Allowed; allowed != nil && !*allowed {
		return nil, violations, sandboxapi.Errorf(sandboxapi.CodeAdminViolation, "sandbox execution is disabled by the administrative floor")
	}
	if options.Offline && (owned.OpenShell.LLM != config.OpenShellLLMNone || len(effective.MCP.HostPorts) != 0) {
		return nil, violations, sandboxapi.Errorf(sandboxapi.CodePolicyViolation, "offline execution requires llm none and no host ports")
	}
	policy := &ExecutionPolicy{
		effective: effective, options: options,
		enabled: map[ID]bool{OpenShell: owned.SandboxRuntimeEnabled(string(OpenShell)), Axis: owned.SandboxRuntimeEnabled(string(Axis))},
	}
	if err := policy.freeze(owned.OpenShell, flags); err != nil {
		return nil, violations, err
	}
	return policy, slices.Clone(violations), nil
}

func copyPolicyFlags(flags packs.Flags) (packs.Flags, error) {
	flags.Unmask, flags.HostPorts, flags.UserPack = slices.Clone(flags.Unmask), slices.Clone(flags.HostPorts), slices.Clone(flags.UserPack)
	var err error
	if flags.Floor, err = clonePolicyValue(flags.Floor); err != nil {
		return packs.Flags{}, err
	}
	if flags.RepoPolicy, err = clonePolicyValue(flags.RepoPolicy); err != nil {
		return packs.Flags{}, err
	}
	if flags.Subject != nil {
		subject := *flags.Subject
		flags.Subject = &subject
	}
	// Observability is an immutable plan read only during resolution; the
	// resolver retains its computed reserved ports, not the plan pointer.
	return flags, nil
}

func clonePolicyValue[T any](value T) (T, error) {
	var out T
	data, err := json.Marshal(value)
	if err == nil {
		err = json.Unmarshal(data, &out)
	}
	return out, err
}

// commonPolicyValues preserves every shared config field, including settings
// not represented by packs.Effective (LLM, headless retention, undo settings).
// Selection metadata is separate; an unknown shared field refuses construction.
func commonPolicyValues(o config.OpenShellConfig) (map[string]any, error) {
	out := map[string]any{}
	common, projected := reflect.TypeFor[config.SandboxConfig](), reflect.ValueOf(o)
	for i := range common.NumField() {
		field := common.Field(i)
		if field.PkgPath != "" || field.Name == "Runtime" || field.Name == "Runtimes" {
			continue
		}
		value := projected.FieldByName(field.Name)
		if !value.IsValid() {
			return nil, fmt.Errorf("sandbox execution policy: shared field %s has no projection", field.Name)
		}
		key, _, _ := strings.Cut(field.Tag.Get("yaml"), ",")
		out[key] = value.Interface()
	}
	return out, nil
}

func (p *ExecutionPolicy) freeze(source config.OpenShellConfig, flags packs.Flags) error {
	eff := p.effective
	common, err := commonPolicyValues(source)
	if err != nil {
		return err
	}
	var cpu, memory int64
	if eff.Resources.CPU != "" {
		if cpu, err = config.ParseOpenShellCPU(eff.Resources.CPU); err != nil {
			return err
		}
	}
	if eff.Resources.Memory != "" {
		if memory, err = config.ParseOpenShellMemory(eff.Resources.Memory); err != nil {
			return err
		}
	}
	values := []struct {
		name  PolicyComponentName
		value any
	}{
		{PolicyCommon, common},
		// The complete resolved view preserves the floor, pack and repository
		// provenance. It remains inspection-only; egress uses the private eff.
		{PolicyAuthority, map[string]any{"binding": p.options.Authority, "resolved": eff}},
		{PolicyWorkspace, map[string]any{"posture": eff.Workspace, "undo_ignored": source.Workdir.UndoIgnored,
			"project": flags.Project, "project_real": flags.ProjectReal, "protected_policy_sources": eff.PolicySources()}},
		{PolicyEgress, map[string]any{"profile": eff.Profile, "mode": eff.NetworkMode, "posture": eff.Egress,
			"approvals": eff.Approvals, "offline": p.options.Offline, "authority": "defenseclaw-host-broker-v1"}},
		{PolicyHarness, map[string]any{"name": eff.Harness, "identity": p.options.Harness, "yolo": eff.Yolo,
			"any_harness": eff.AnyHarness, "allowed_harnesses": eff.AllowedHarnesses, "process_tree": eff.ProcessTree,
			"hook_fail_mode": eff.HookFailMode, "hook_on_tamper": eff.HookOnTamper, "hook_on_silence": eff.HookOnSilence,
			"hook_silence_after": eff.HookSilenceAfter, "terminal": p.options.Terminal}},
		{PolicyMCP, eff.MCP},
		{PolicyResources, map[string]int64{"cpu_millicores": cpu, "memory_bytes": memory}},
	}
	for _, component := range values {
		data, err := json.Marshal(component.value)
		if err != nil {
			return fmt.Errorf("sandbox execution policy: %s: %w", component.name, err)
		}
		p.components = append(p.components, PolicyComponent{Name: component.name, Digest: policyDigest(data), Value: data})
	}
	p.required = []Capability{StrictFilesystem, ProcessTreeContainment, ManagedHooks}
	if p.options.Terminal {
		p.required = append(p.required, Interactive)
	} else {
		p.required = append(p.required, Headless)
	}
	if eff.Workspace.Mode == config.OpenShellWorkdirCopy {
		p.required = append(p.required, CopyWorkspace)
	} else {
		p.required = append(p.required, LiveMount)
	}
	if p.options.Offline {
		p.required = append(p.required, OfflineNetwork)
	} else {
		p.required = append(p.required, BrokerEgress)
	}
	if source.LLM != config.OpenShellLLMNone {
		p.required = append(p.required, HostCredentials, ExecutableCredentialBinding)
	}
	if eff.Yolo {
		p.required = append(p.required, SkipPermissions)
	}
	if eff.MCP.Import {
		p.required = append(p.required, MCPImport)
	}
	if len(eff.MCP.HostPorts) > 0 {
		p.required = append(p.required, MCPRemoteBroker)
	}
	if cpu > 0 {
		p.required = append(p.required, CPUHardLimit)
	}
	if memory > 0 {
		p.required = append(p.required, MemoryHardLimit)
	}
	p.canonical, err = json.Marshal(struct {
		Version      int               `json:"version"`
		SourceDigest string            `json:"source_digest"`
		Options      PolicyOptions     `json:"execution"`
		Enabled      map[ID]bool       `json:"enabled_runtimes"`
		Required     []Capability      `json:"required_capabilities"`
		Components   []PolicyComponent `json:"components"`
	}{1, eff.Digest(), p.options, p.enabled, p.required, p.components})
	if err == nil {
		p.digest = policyDigest(p.canonical)
	}
	return err
}

func policyDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func (p *ExecutionPolicy) Digest() string {
	if p == nil {
		return ""
	}
	return p.digest
}

// Snapshot is copied host-confidential enforcement JSON, not a serializable
// runtime authority or an external API view. It includes policy/workspace
// provenance and must never be sent to guests, logs or telemetry. External
// consumers need a separate deliberately redacted projection.
func (p *ExecutionPolicy) Snapshot() json.RawMessage {
	if p == nil {
		return nil
	}
	return slices.Clone(p.canonical)
}

func (p *ExecutionPolicy) RequiredCapabilities() []Capability {
	if p == nil {
		return nil
	}
	return slices.Clone(p.required)
}

// Components returns copied host-confidential values for trusted adapters.
// Component values are not suitable for guest, external API or telemetry use.
func (p *ExecutionPolicy) Components() []PolicyComponent {
	if p == nil {
		return nil
	}
	out := slices.Clone(p.components)
	for i := range out {
		out[i].Value = slices.Clone(out[i].Value)
	}
	return out
}

// DecideEgress keeps host broker decisions on the original resolver, including
// host/private-address guards and curated-versus-operator allow semantics.
// It performs no DNS lookup or connection and grants no credential or approval.
func (p *ExecutionPolicy) DecideEgress(host string, port int) packs.EgressDecision {
	if p == nil || p.effective == nil {
		return packs.EgressDecision{Rule: packs.RuleInvalid}
	}
	if p.options.Offline {
		return packs.EgressDecision{Rule: packs.RuleNetworkDeny, Reason: "this execution policy is offline"}
	}
	return p.effective.DecideEgress(host, port)
}

// AdmitPolicy requires exact host-generated enforcement/routing evidence for
// every component, as well as qualified runtime and harness capabilities.
// current must be fetched from trusted host authority at dispatch, never from
// a guest or API request. The caller must serialize authority rotation with
// admission and launch (or condition launch on this generation); a check alone
// cannot prevent rotation immediately after it returns. This method never
// chooses another adapter or interprets absence as a permissive default.
func (p *ExecutionPolicy) AdmitPolicy(info RuntimeInfo, receipt PolicyReceipt, current PolicyAuthorityBinding) error {
	if p == nil || p.effective == nil || !artifactDigest.MatchString(p.digest) {
		return sandboxapi.Errorf(sandboxapi.CodePolicyRejected, "sandbox execution policy is not host-resolved")
	}
	if current != p.options.Authority {
		return sandboxapi.Errorf(sandboxapi.CodePolicyRejected, "sandbox policy authority changed before dispatch")
	}
	if !p.enabled[info.Identity.Runtime] {
		return sandboxapi.Errorf(sandboxapi.CodeDisabled, "sandbox runtime %q is not enabled for this policy", info.Identity.Runtime)
	}
	if receipt.Runtime != info.Identity || receipt.Harness != p.options.Harness || receipt.PolicyDigest != p.digest {
		return sandboxapi.Errorf(sandboxapi.CodePolicyRejected, "sandbox policy receipt does not match its runtime, harness and policy identity")
	}
	if err := info.RequireHarness(p.effective.Harness, p.options.Harness, p.required...); err != nil {
		return err
	}
	if len(receipt.Components) != len(p.components) {
		return sandboxapi.Errorf(sandboxapi.CodePolicyViolation, "sandbox policy receipt must cover every policy component exactly")
	}
	expected := make(map[PolicyComponentName]string, len(p.components))
	for _, component := range p.components {
		expected[component.Name] = component.Digest
	}
	for _, component := range receipt.Components {
		if expected[component.Name] == "" || expected[component.Name] != component.Digest {
			return sandboxapi.Errorf(sandboxapi.CodePolicyViolation, "sandbox policy receipt has missing, duplicate, unknown or changed component %q", component.Name)
		}
		delete(expected, component.Name)
	}
	return nil
}
