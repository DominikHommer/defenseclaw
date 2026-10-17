# Connector Delta Monitor: Claude Code and Codex

Local results, 2026-10-17. Both providers were tested against DefenseClaw main
`a6ab014b0ceb4c783e4afafce39fe6e1a76f249b`, refreshed from `origin/main`.
The measurements below were collected locally before the refactor. At collection
time no push, issue/PR write, hosted workflow run, client installation or runtime
configuration change was performed. Downloaded source was parsed, never executed.

## Organized implementation and regression comparison

The tool now lives under `scripts/connector_delta/`, with shared invariants and
per-provider `connectors/{claudecode,codex}/` manifests, bindings, extractors and
fixtures. The original CLI entry point remains stable. Only those two providers
are implemented.

The final focused refactor/inventory/notification/CI suite passed **138 tests
plus 139 parameterized subtests**. No live GitHub writes or mail delivery were
used for these checks.

Before adding inventory or platform behavior, the pure file-layout refactor was
compared with the saved flat implementation: **all 55 mutation cases and all
4911 historical deltas matched exactly**, including invariant checks/evidence
and finding decisions (excluding report timestamps/implementation fingerprints).

The two PRs from the earlier latest-PR experiment were then replayed at their
same exact first-parent/merge revisions, adding their actual GitHub file lists:

| PR | Old watched-artifact result | With PR inventory | Notification dry-run |
| --- | --- | --- | --- |
| [Codex #54776](https://github.com/openai/codex/pull/54776) | 0 findings; all 24 watched files unchanged | 1 review item: hook-context renderer, typed fragments, protocol models and tool-output conversion changed outside the watchlist | One informative tracker notice; repeated delivery deduplicated |
| [Claude #100293](https://github.com/anthropics/claude-code/pull/100293) | 0 findings; watched changelog unchanged | 1 review item: four settings-example files outside the watchlist | One informative tracker notice; repeated delivery deduplicated |

Neither is a proven breaking change. Claude's example is conditional on adoption,
not a change to host defaults. Current unversioned Claude docs were not used as
historical PR evidence. Changed-file lists were read live; all issue writes and
email delivery were mocked, so **no actual issues or emails were sent**.

Notifications are opt-in GitHub issue/comment mentions, not SMTP. The publisher
receives a public-safe envelope, not raw findings or AI caches. A checkpointed
outbox and receipts retain notices after publisher failures. OS-qualified path,
registration and execution changes stay review-required where no OS-specific
binding exists; Linux/macOS/Windows metadata is partial static coverage, not
native certification.

## Results at a glance

| Check | Claude Code | Codex |
| --- | --- | --- |
| Shared invariant catalog | Same eight requirements | Same eight requirements |
| Historical input | Official pinned changelog, releases 2.1.150–2.1.301 | 15 sampled main-reachable commits, each against its first parent |
| Sample size | 126 releases; 4,807 notes | 30 pinned source bundles; 24 fixed artifacts per bundle |
| Time range | Version range above, current checkout used retrospectively | 2026-09-05 through 2026-10-16 |
| Relevant deltas | 396 review candidates; 4,411 filtered notes | 104 source/schema hunks from 10 transitions affecting watched artifacts |
| Invariant comparisons | 594: 592 review-required, 2 compatible | 319 review-required |
| Proven static breaking conflicts | 0 | 0 |
| Collection gaps in these runs | 0 | 0 |
| Curated relevance labels | 21/21 passed; development labels, not independent accuracy | No historical verdict labels or precision/recall score claimed |
| Synthetic mutations | 32/32 passed | 23/23 passed |
| Live model/client execution | None | None |

The focused monitor/provider/classifier/workflow-efficiency suites passed:
**101 tests plus 131 parameterized subtests**. The shared AI adapter was exercised
with fixtures for both providers, including provider-specific binding ranges,
refusal of invented citations, unresolved-invariant coverage and model limits.
This is not a successful live AI call or an evaluation of model reasoning quality.

## What the historical result means

Zero proven conflicts is **not** a finding that all reviewed versions are safe.
Most natural-language or implementation-only changes lack an extractable,
authoritative contradiction. They remain explicit review items. No live AI
credential was used to semantically classify those remaining items.

Claude's two compatible comparisons are the already-supported DirectoryAdded
event and validation of `updatedInput`, which DefenseClaw does not emit. Other
unresolved checks keep those overall entries at review-required. The earlier
[Claude-only experiment](claude-delta-monitor-backtest.md) has the detailed
manual comparisons; its original baseline was older main `f9c88b4`.

Codex history is selected from the main-filtered `codex-rs/hooks` and
`codex-rs/config/src/hook_config.rs` commit histories. Each commit and first
parent is fetched independently at its immutable SHA. This is not an exhaustive
merged-PR feed, an invented linear replay across branches, or an as-of-time test
of old DefenseClaw code. Five sampled transitions did not change any watched
artifact; they are not claimed compatible. Core-only changes outside those
sampling paths can be absent from this historical sample, even though ongoing
main-snapshot monitoring watches the configured core artifacts.

The boundary revisions are
[`2bd71f96d41809b95ea881429a1b68eb48d089b6`](https://github.com/openai/codex/commit/2bd71f96d41809b95ea881429a1b68eb48d089b6)
and
[`2bf2bdf82c33f4c66ba3f0767b8e4b6a933aac40`](https://github.com/openai/codex/commit/2bf2bdf82c33f4c66ba3f0767b8e4b6a933aac40).
The complete revision/parent list is retained in the ignored local history bundle.
Missing or renamed files are reported as coverage gaps, never silently compatible.

### Useful Codex matches

| Actual upstream change | Concrete DefenseClaw comparison | Recorded outcome |
| --- | --- | --- |
| [Prevent command hooks hanging on blocked stdin, #44288](https://github.com/openai/codex/commit/885113aa1d68ccbc567b83698feac3cd42163088) | Upstream command-runner I/O and timeout handling versus active 30/90-second registrations and native failure handling | Execution/failure review. A vendor hang fix is not automatically a new connector break. |
| [Compile hook matchers during discovery, #49379](https://github.com/openai/codex/commit/bd4204efc24a888c6671681f5cd41fbf9377c163) | Loader/matcher behavior versus actual event groups and wildcard matchers | Review whether wildcard semantics and registration remain effective; no explicit incompatible contract fact extracted. |
| [Bind plugin hook approval to plugin contents, #54619](https://github.com/openai/codex/commit/2bf2bdf82c33f4c66ba3f0767b8e4b6a933aac40) | Upstream discovery/trust changes versus inline command registrations, position-aware state keys and local canonical handler hashing | Registration/discovery review. A plugin-specific trust change alone is not proof that inline user hooks stop loading. |
| [Track source attribution through context parts, #52195](https://github.com/openai/codex/commit/ad54b75574dca8b24f09ab3c0ca4106529afed04) | Wire types, parser and runtime changes versus typed request/response consumers | Review. No incompatible declared payload type or retired emitted deny was proven. |

These are evidence-backed review targets, not automatically cleared findings or
claims of released-client regressions.

## What the mutation tests establish

Claude's 32 cases exercise explicit path retirement versus table omission,
registration keys/types, owned-event removal, payload types, actual deny
encodings, async/phase changes, hard versus default timeouts, blocking exits and
paired identities. Examples cannot establish a schema change.

Codex's 23 cases mutate actual-shaped source/schema artifacts: closed-schema
field removal, incompatible input types, deny enum retirement, universal
`continue: false` rejection, typed event/dispatch removal, command-handler
retirement, SessionEnd budget changes and blocking exit reassignment. Open
schemas, unknown implementations, aliases, unconstrained values, remote/cyclic
references and default-directory changes without legacy-path proof stay review.

All static conflicts carry exact local/upstream source spans and revisions with
`runtime_verified=false`. A boolean denial is not confused with numeric zero.
Comments, nested Rust comments, raw strings and test declarations do not supply
contract facts. The local SessionEnd timeout is taken from the active three-second
declaration, not an old 60-second migration example in the same file.

## Codex behavior examples

The following examples are hypothetical upstream mutations, not historical bugs
discovered in this sample. The [official hook contract](https://learn.chatgpt.com/docs/hooks)
is useful context; pinned source/schema deltas and current DefenseClaw code are
the monitor's comparison evidence.

**Discovery path and registration.** DefenseClaw's default local Codex binding
writes inline hooks into `~/.codex/config.toml`, following `CODEX_HOME` when set.
It emits command handlers and, on trust-aware tiers, position-aware state keys
plus a canonical handler hash. The monitor watches the home resolver, config
defaults, typed handler configuration and discovery/trust loader. For example,
removing the `command` handler variant without preserving an alias conflicts
with what DefenseClaw emits. Merely changing the default home directory remains
review-required until the monitor can establish whether the old registration
is still loaded through a migration or compatibility path.

**Required events and payload types.** The current contract selects 11 owned
events, while older Codex tiers select smaller sets. The provider compares typed
event declarations and group dispatch with those registrations, and compares
declared input types with the Go request decoder. For example, an authoritative
`tool_input` object-to-string change conflicts with the map-typed consumer.
An unconstrained schema or a new optional field does not demonstrate the same
failure. Event removal requires more than a missing documentation row.

**Blocking responses and failure exits.** Codex uses event-specific control:
PreToolUse receives `hookSpecificOutput.permissionDecision=deny`, PermissionRequest
uses nested `decision.behavior=deny`, and other events use top-level block or
`continue: false`. Strict-unreachable handling separately relies on exit 2.
For example, retiring `deny` from the PreToolUse output enum is a concrete wire
conflict. Treating exit 2 as nonblocking would instead affect the failure path.
SessionEnd is advisory and is not falsely assigned a JSON-denial requirement.

**Ordering, budgets and correlation.** The active registrations require blocking
command hooks to remain synchronous and preserve their configured budgets:
PreToolUse is 30 seconds, Stop/SubagentStop are 90 seconds, and SessionEnd is
three seconds. Moving inspection after a protected action would undermine the
barrier even if the payload and deny encoding remain valid. For a directly
tested example, lowering the SessionEnd hard cap to one second conflicts with
the configured three-second budget; changing only its default does not.
Separately, removing `tool_use_id` from a closed paired-event schema conflicts
with lifecycle pairing even though that field is optional to JSON decoding.

## Reproduction

See the [monitor README](../../scripts/connector_delta/README.md) for
collection, historical replay and optional AI commands. Representative offline
replays, after the snapshots/history have been collected:

```bash
python3 scripts/connector_delta_monitor.py backtest --connector claudecode \
  --snapshot output/connector-delta-monitor/claude-current-snapshot.json \
  --from-version 2.1.150 --to-version 2.1.301 \
  --expectations scripts/connector_delta/connectors/claudecode/fixtures/history-labels.json \
  --output output/connector-delta-monitor/claude-current-backtest.json \
  --summary output/connector-delta-monitor/claude-current-backtest.md

python3 scripts/connector_delta_monitor.py backtest --connector codex \
  --history output/connector-delta-monitor/codex-history.json \
  --output output/connector-delta-monitor/codex-historical.json \
  --summary output/connector-delta-monitor/codex-historical.md

python3 scripts/connector_delta_monitor.py backtest-invariants --connector claudecode \
  --output output/connector-delta-monitor/claude-invariant-backtest.json

python3 scripts/connector_delta_monitor.py backtest-invariants --connector codex \
  --output output/connector-delta-monitor/codex-invariant-backtest.json
```

The workflow has isolated Claude Code/Codex analysis jobs with read-only
permissions and sanitized state/report artifacts. A separate, opt-in publisher
has issue-write permission and the five requested contributor mentions.
No workflow or notification delivery was enabled or dispatched during testing.

Security checks retain fixed HTTPS source allowlists, verified platform TLS,
SHA-256 content fingerprints, bounded inputs and local-only schema resolution.
API credentials are environment references, never embedded in source or fixtures;
GitHub credentials are sent only to the GitHub API, not raw content hosts. No new
dependency or agent setup is required. Full product Go/TS/Rego suites, live client
behavior, hosted execution and live model quality remain outside this tooling test.
