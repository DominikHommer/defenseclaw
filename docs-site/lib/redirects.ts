// Old docs URLs that moved when the navigation was reorganised. Each key
// is the old slug under /docs; the value is the page that now owns the
// topic. The docs catch-all route pre-renders a small "moved" page for
// every key (static export has no server-side redirects), so bookmarks,
// search results and links printed by the CLI keep working.
//
// When you move a page: `git mv` it, add its old slug here, and update
// internal links to the new URL. Keep entries forever. A value must be a
// real page (never another key) and carry no #anchor: the redirect page
// copies the old URL's #hash onto the target. `scripts/validate-links.ts`
// enforces both rules and that no key is also a real page.
export const legacyRedirects: Record<string, string> = {
  // Pre-1.0 setup/* slugs.
  setup: '/docs/reference/cli/',
  'setup/guardrail': '/docs/reference/guardrail-setup/',
  'setup/guardrail/aliases': '/docs/reference/guardrail-setup/',
  'setup/guardrail/multi-connector': '/docs/how-to/guardrail/add-or-remove-an-agent/',
  'setup/guardrail/switching-connectors': '/docs/how-to/guardrail/add-or-remove-an-agent/',
  'setup/guardrail/disabling': '/docs/how-to/guardrail/turn-off-the-guardrail/',
  'setup/semantic-routing': '/docs/how-to/guardrail/route-models/',
  'setup/unified-llm-key': '/docs/how-to/guardrail/set-up-an-llm-key/',
  'setup/sandbox': '/docs/how-to/sandboxes/run-an-agent/',
  'setup/sandbox-policy': '/docs/reference/sandbox-policy/',
  'setup/skill-scanner': '/docs/how-to/scanning/scan-a-skill/',
  'setup/mcp-scanner': '/docs/how-to/scanning/scan-an-mcp-server/',
  'setup/registries': '/docs/how-to/scanning/subscribe-to-a-registry/',
  'setup/webhooks': '/docs/how-to/observability/set-up-webhook-alerts/',
  'setup/enterprise-deployment': '/docs/enterprise/secure-client/',
  defaults: '/docs/reference/policy-defaults/',
  benchmarks: '/docs/appendix/benchmarks/',
  'llm-judge-benchmark': '/docs/appendix/llm-judge-benchmark/',
  'capability-matrix': '/docs/reference/capability-matrix/',
  'get-started/windows/capabilities-commands': '/docs/reference/capability-matrix/',
  'get-started/windows/connectors-enforcement': '/docs/connectors/',
  'get-started/windows/managed-enterprise': '/docs/enterprise/windows/',
  openclaw: '/docs/connectors/openclaw/',
  'connectors/tool-call-state': '/docs/reference/cel/tool-call-state/',

  // 1.0.4 documentation restructure: root pages.
  'acp-guard': '/docs/features/acp-guard/',
  'ai-discovery': '/docs/features/ai-discovery/',
  'command-generator': '/docs/how-to/guardrail/generate-a-setup-command/',
  hitl: '/docs/features/guardrail/',
  'macos-app': '/docs/features/macos-app/',
  segmentation: '/docs/appendix/coverage-by-layer/',
  tui: '/docs/features/tui/',

  // connectors/
  'connectors/capability-matrix': '/docs/reference/capability-matrix/',
  'connectors/compatibility': '/docs/reference/hook-contracts/',
  'connectors/openclaw-integration': '/docs/connectors/openclaw/',
  'connectors/openhands': '/docs/get-started/upgrade/',
  'connectors/omnigent': '/docs/get-started/upgrade/',

  // edge-connector/
  'edge-connector': '/docs/features/edge-connector/',
  'edge-connector/install': '/docs/how-to/install-the-edge-connector/',
  'edge-connector/architecture': '/docs/reference/edge-connector/architecture/',
  'edge-connector/policies': '/docs/reference/edge-connector/policies/',
  'edge-connector/api-reference': '/docs/reference/edge-connector/api/',

  // get-started/
  'get-started/download': '/docs/get-started/install/',
  'get-started/first-run': '/docs/reference/first-run/',
  'get-started/first-guardrail': '/docs/how-to/guardrail/ask-before-risky-calls/',
  'get-started/windows/install-lifecycle': '/docs/get-started/windows/',
  'get-started/windows/paths-troubleshooting': '/docs/reference/paths/',
  'get-started/windows/telemetry-security': '/docs/appendix/windows-security-model/',

  // guardrail/
  guardrail: '/docs/features/guardrail/',
  'guardrail/aliases': '/docs/reference/guardrail-setup/',
  'guardrail/multi-connector': '/docs/how-to/guardrail/add-or-remove-an-agent/',
  'guardrail/switching-connectors': '/docs/how-to/guardrail/add-or-remove-an-agent/',
  'guardrail/disabling': '/docs/how-to/guardrail/turn-off-the-guardrail/',
  'guardrail/semantic-routing': '/docs/how-to/guardrail/route-models/',
  'guardrail/unified-llm-key': '/docs/how-to/guardrail/set-up-an-llm-key/',
  'guardrail/user-and-group-policies': '/docs/how-to/guardrail/give-a-group-its-own-policy/',
  'guardrail/benchmarks': '/docs/appendix/benchmarks/',
  'guardrail/llm-judge-benchmark': '/docs/appendix/llm-judge-benchmark/',

  // observability/
  observability: '/docs/features/observability/',
  'observability/local-observability': '/docs/how-to/observability/run-grafana-locally/',
  'observability/grafana-dashboards': '/docs/reference/dashboards/',
  'observability/agent360': '/docs/reference/dashboards/',
  'observability/galileo': '/docs/how-to/observability/send-to-galileo/',
  'observability/splunk': '/docs/how-to/observability/send-to-splunk/',
  'observability/webhooks': '/docs/how-to/observability/set-up-webhook-alerts/',
  'observability/redaction': '/docs/reference/redaction/',
  'observability/sandbox-telemetry': '/docs/reference/sandbox-telemetry/',
  'observability/end-user-identity': '/docs/reference/telemetry-identity/',

  // policies/
  policies: '/docs/features/policies/',
  'policies/admission': '/docs/reference/admission/',
  'policies/creator': '/docs/how-to/policies/build-a-policy-in-the-browser/',
  'policies/verify-locally': '/docs/how-to/policies/build-a-policy-in-the-browser/',
  'policies/defaults': '/docs/reference/policy-defaults/',
  'policies/thresholds': '/docs/how-to/policies/change-block-and-alert-levels/',
  'policies/rules': '/docs/reference/rules/',
  'policies/deterministic-detection': '/docs/reference/detection/',
  'policies/recipes': '/docs/reference/rule-recipes/',
  'policies/regex-cookbook': '/docs/reference/regex-cookbook/',
  'policies/rulepack-validation': '/docs/how-to/policies/validate-a-rule-pack/',
  'policies/suppression-cookbook': '/docs/how-to/policies/tune-the-llm-judge/',
  'policies/cel': '/docs/how-to/policies/write-a-custom-rule/',
  'policies/cel/authoring': '/docs/reference/cel/authoring/',
  'policies/cel/engine': '/docs/reference/cel/engine/',
  'policies/cel/tool-call-state': '/docs/reference/cel/tool-call-state/',

  // reference/
  'reference/setup-commands': '/docs/reference/cli/',
  'reference/migrate-v9': '/docs/appendix/migrate-v9/',

  // sandboxes/
  sandboxes: '/docs/features/sandboxes/',
  'sandboxes/guide': '/docs/how-to/sandboxes/run-an-agent/',
  'sandboxes/first-session': '/docs/how-to/sandboxes/run-an-agent/',
  'sandboxes/linux': '/docs/how-to/sandboxes/set-up-on-linux/',
  'sandboxes/macos': '/docs/how-to/sandboxes/set-up-on-macos/',
  'sandboxes/network': '/docs/reference/sandbox-network/',
  'sandboxes/policy-packs': '/docs/reference/sandbox-policy/',
  'sandboxes/apps': '/docs/how-to/sandboxes/watch-from-the-tui-or-app/',

  // scanning/
  scanning: '/docs/features/scanning/',
  'scanning/skill-scanner': '/docs/how-to/scanning/scan-a-skill/',
  'scanning/mcp-scanner': '/docs/how-to/scanning/scan-an-mcp-server/',
  'scanning/registries': '/docs/how-to/scanning/subscribe-to-a-registry/',

  // stories/
  stories: '/docs/how-to/guardrail/block-a-destructive-command/',
  'stories/observe-claude-code': '/docs/how-to/guardrail/block-a-destructive-command/',
  'stories/prompt-injection-codex': '/docs/how-to/guardrail/catch-prompt-injection/',
  'stories/cursor-secret-exfil': '/docs/how-to/guardrail/stop-a-secret-upload/',
  'stories/hitl-approvals': '/docs/how-to/guardrail/ask-before-risky-calls/',
  'stories/local-observability': '/docs/how-to/observability/run-grafana-locally/',
  'stories/switch-connectors': '/docs/how-to/guardrail/add-or-remove-an-agent/',
};

export function legacyRedirectFor(slug: string[] | undefined): string | undefined {
  return legacyRedirects[(slug ?? []).join('/')];
}
