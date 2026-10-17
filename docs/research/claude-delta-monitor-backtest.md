# Claude Code delta monitor: historical and invariant backtests

Local experiment, 2026-10-16. No push, remote workflow execution, agent installation
or DefenseClaw runtime configuration change was performed.

Shared-invariant revision tested 2026-10-17, after refreshing `origin/main` and
confirming the same baseline below. The older relevance experiment is retained
separately from the new deterministic contract-mutation checks.

## Inputs and results

| Item | Result |
| --- | --- |
| DefenseClaw baseline | Current `origin/main`, `f9c88b4bd348efd505b2b5b64114897511a61ce3` |
| Local branch | `codex/claude-delta-monitor` |
| Upstream changelog | [`03b5892ee77de289bcd5dfa39f541525ade74aff`](https://github.com/anthropics/claude-code/blob/03b5892ee77de289bcd5dfa39f541525ade74aff/CHANGELOG.md) |
| Requested version range | `2.1.150` through `2.1.301` |
| Releases present in that range | 126 |
| Release-note entries replayed | 4,807 |
| Selected for semantic review | 396 |
| Filtered by the artifact manifest | 4,411 |
| Curated relevance checks | 21/21 passed: 15 relevant examples and 6 irrelevant examples |
| Live model calls | 0; no Anthropic API credential was available |

The collector also retrieved the official hooks and settings Markdown documents.
Their first snapshots establish baselines; they do not constitute a historical
documentation-diff backtest. Full snapshots, JSON results and the generated
report are saved locally under `output/connector-delta-monitor/` and ignored by Git.

These are retrospective upstream signals compared with today's local code.
They measure candidate discovery, not historical prediction or actual breakage.
The 21 labels were used during development/tuning, so 21/21 is a regression
check, not an independent accuracy estimate. The remaining candidates have not
all received semantic review.

## Useful historical matches: manual comparison

The following conclusions are manual review of source evidence and current
consumers, separate from the unexecuted live model adapter.

| Upstream change | DefenseClaw comparison | Assessment |
| --- | --- | --- |
| `2.1.154`: plugins can default to disabled through `defaultEnabled` | `cli/defenseclaw/inventory/plugin_directories.py`, `_claude_enabled`, reads the field and honors boolean false | Relevant to inventory; current support exists. The first hook-only matcher missed it, which led to adding the plugin-inventory artifact class. |
| `2.1.219`: new `DirectoryAdded` event | `internal/gateway/connector/claudecode.go`, `claudeCodeAllHookGroups`, registers the event; `hook_contracts.json` versions it in v2 | Event coverage change detected; already represented on current main. Do not report an additive event as a current parser failure. |
| `2.1.268`: SessionEnd timeout extension fix | `internal/gateway/connector/hookexec/hookexec.go`, `ClaudeCodeHookTimeoutSeconds`, sets an explicit 60-second SessionEnd timeout; the installer uses that helper | Relevant host-budget signal, but the vendor statement concerns hooks without a per-hook timeout. No current mismatch established. |
| `2.1.284`: fixed ignored blocking decisions on Elicitation events | `internal/gateway/connector/claudecode_hook_profile.go`, `claudeCodeOutputForProfile`, emits event-specific `action: decline` for Elicitation and ElicitationResult | Important enforcement signal; current main already uses a distinct event-specific decline response. Runtime validation would establish behavior on particular client versions. |
| `2.1.299`: UserPromptSubmit moved before skill expansion | Current registration and profile decoder cover both UserPromptSubmit and UserPromptExpansion | Review execution ordering and expanded-content inspection together. The note alone does not demonstrate that coverage was lost. |
| `2.1.300`: fixed missing SessionEnd delivery while background commands run | DefenseClaw registers SessionEnd and handles it in `internal/gateway/claude_code_hook.go` | Relevant lifecycle-delivery change; recommend an authentic-client session-exit check. This vendor fix is not evidence of a new current break. |
| `2.1.300`: stricter validation of hook-provided `updatedInput` | The current response emitters return allow/deny/ask/decline and context; they do not ordinarily rewrite tool input through this field | Needs review with policy governing other hooks. A keyword match alone would overstate the effect on DefenseClaw's own emitted responses. |

No current DefenseClaw incompatibility was proven by this static experiment.
It did find real upstream changes worth reviewing and separated several already
covered changes from potential validation work.

## What the tests establish

The focused monitor, invariant and CI-classifier/efficiency suites passed locally:
85 tests plus 103 parameterized subtests. Tests cover real collection seams, immutable
changelog URLs, source failures, document changes/removals, incremental replay,
initial lookback, failed/partial analysis, resume after budget exhaustion,
newer-release arrival during a pending batch, and malformed checkpoint refusal.

The model boundary was exercised with fixtures: request/authentication shape,
missing credentials, truncated/non-text output, strict fields and enums, exact
upstream/local quotes and line numbers, and refusal of invented paths and test
commands. This is not a successful live provider call or semantic-quality eval.

## Shared-invariant backtest

The catalog now defines eight reusable command-hook requirements: discovery,
registration, event delivery, payload decoding, deny decisions, execution
barriers/budgets, failure exit status and lifecycle correlation. Claude-specific
code extracts actual values from the current writer, request struct, responder,
native runner and versioned contract. Another test-only provider uses the same
generic comparator with a different discovery path; production Codex/Cursor
providers remain future work.

The offline mutation backtest passed **32/32 synthetic cases**. Representative
comparisons against current code:

| Mutated upstream contract | Actual local dependency | Expected and actual verdict |
| --- | --- | --- |
| Hooks no longer read `~/.claude/settings.json` | Default user writer emits that file | `hook.discovery`: static `breaking_change` |
| New path is added but the old path is explicitly still accepted | Same writer | `compatible` |
| Old path disappears from a table, with no retirement statement | Same writer | `review_required`, not a proven break |
| Cloud-only or hypothetical path retirement | Local user binding | `review_required`, not a local-path conflict |
| `hooks` key or command-handler type explicitly rejected | Writer emits `hooks` and `type: command` | `hook.registration`: static `breaking_change` |
| PreToolUse `tool_input` changes object -> string in a declared schema | Go decoder uses `map[string]interface{}` | `hook.payload`: static `breaking_change` |
| Only a JSON example changes object -> string | Same decoder | `review_required`: an example is not a schema |
| PreToolUse ignores `permissionDecision: deny` | Exact field/value is emitted by the responder | `hook.decision`: static `breaking_change` |
| Elicitation ignores `decision: block` | Responder instead emits `action: decline` | `compatible` for this scoped encoding change |
| PreToolUse becomes asynchronous or post-action | Bound synchronous pre-proposal inspection | `hook.execution`: static `breaking_change` |
| Hard timeout becomes 5s / only the default becomes 5s | Explicit per-event timeout is 30s | Hard cap: conflict; default-only: compatible |
| Exit code 2 stops blocking | Native strict-unreachable path returns `blockExit=2` | `hook.failure`: static `breaking_change` |
| `tool_use_id` is no longer sent | Paired lifecycle identity; field is optional to the JSON decoder | Correlation conflict; payload-removal consequence stays review |

All conflict results explicitly have `runtime_verified=false`. These cases
validate the detector, not actual released-client regressions. Both sides carry
exact source spans, line numbers and revisions; forged citations and unknown
local extraction shapes cannot establish compatibility or conflict. Historical
versions below the registry's declared minimum do not inherit the latest binding.

Replaying the same 4,807 historical notes still passes 21/21 relevance labels.
It selects 396 review candidates, with **594 individual invariant checks: 592
review-required and 2 compatible**. The compatible checks are the already-bound
DirectoryAdded event and the newly validated `updatedInput` response field that
DefenseClaw does not emit. Those entries still have unresolved companion checks,
so the overall entries remain review candidates. **Zero static breaking changes
were proven.** The extractor intentionally leaves most prose unnormalized.

The AI packet now contains only unresolved invariant IDs and their concrete local
bindings, with a separate grounded comparison required for each ID. The model
must cite within that specific binding's source ranges, not unrelated real code.
Unverified local extraction is held for human review, not filled in by a model.
The model cannot return the deterministic `breaking_change` verdict or override it. Unbound
telemetry/plugin classes remain visible without a general-purpose AI request.
Live model execution is still untested; the API boundary and invariant scoping
were validated with fixtures.

Reproduce the mutation run with:

```bash
python3 scripts/connector_delta_monitor.py backtest-invariants \
  --output output/connector-delta-monitor/invariant-backtest.json \
  --summary output/connector-delta-monitor/invariant-backtest.md
```

The revised historical report is saved locally as
`output/connector-delta-monitor/historical-invariants.json` and `.md`.

Ruff, workflow YAML/shell syntax and read-only permissions, whitespace checks,
and the repository skill-freshness check were also checked. Full product
Go/TypeScript/Rego suites and hosted Actions execution are outside this focused
local tooling validation; no runtime implementation was changed.

## Reproduction and next use

See the [tool README](../../scripts/connector_delta/README.md) for exact
collection/replay commands, workflow switches, model credentials and retention.
The first local run over `2.1.280`–`2.1.301` selected 228 entries before tuning;
natural-language “Continue” and unrelated compaction settings were false matches.
The final manifest tightens those signals and adds the missed plugin consumer.

Use the reports-only workflow first. Before relying on AI classifications, run
a small live provider batch, review its grounded comparisons, then evaluate
untouched historical cases. Keep public-source collection gaps and mod-hook/UI
noise visible; do not auto-update connector contracts from these findings.
