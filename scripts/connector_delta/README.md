# Upstream connector monitor

A small GitHub Actions script watches **Codex and Claude Code only**. It reads
merged upstream changes and compares them with DefenseClaw main. Neither agent
is installed or run; downloaded code is never executed. Python uses only stdlib.

## Flow

1. Restore a cursor for each connector. Select up to twenty unseen PRs merged into
   upstream main, oldest first. The first run intentionally takes the latest twenty.
2. Read the complete changed-file inventory, including renames and deletions.
   Hook-related paths **or edited hook references** select relevant files, even
   outside known schemas. Fetch up to ten relevant files at the merge's first
   parent and merge SHA. Several PRs are never conflated into one delta.
3. Read the latest local hook contract and selected actual connector source from
   DefenseClaw main. Small deterministic checks detect changed `tool_use_id`
   types, newly rejected deny responses in named Codex schemas, and exact,
   unqualified Claude changelog statements retiring a registered path. Other
   relevant edits require human review.
4. Optional AI compares the delta with eight explicit requirements in
   [connectors.json](connectors.json): discovery, registration, delivery, payload,
   decision, failure, execution and correlation. Local/upstream quotes are checked
   against supplied text. AI can raise a suspected-conflict notice but cannot
   declare a proven break or certify safety. Raw output stays runner-local;
   reproduce privately to inspect its detailed reasoning.
5. A separate main-only publisher optionally creates contributor issues, then
   persists the processed-PR cursor. Failed analysis stays pending. Failed delivery
   prevents that candidate checkpoint being committed. Retry deduplication checks
   bot markers in the latest 100 bot issues; email is not exactly-once delivery.

Zero matches means **no tracked dependency identified**, never "connector safe".
OS-specific paths, managed policy, launchers, ordering, timeouts and arbitrary
source semantics are review topics, not independently verified platform bindings.
Examples, omission from docs and changed defaults are not proof of retirement.
Claude's private runtime and external unversioned docs are not monitored here.

## Enablement and email

All switches default off. After merge, manually run `Connector Delta Monitor` on
main with `notify=false` to smoke-test collection and checkpoint restoration.
Set `CONNECTOR_DELTA_MONITOR_ENABLED=true` for the six-hour schedule. Publication
also needs `CONNECTOR_DELTA_NOTIFICATIONS_ENABLED=true`; manual runs additionally
require `notify=true`. Disabled publication queues no later emails.

Hook-related changes are emailed even without a proven break; unrelated PRs stay
informational in the run bundle instead of creating inbox noise. Issues mention
the five configured contributors. GitHub email depends on their
settings and access; this is not SMTP or a private channel. Concrete-conflict
details, local source and model output stay out of public notices/artifacts.
AI additionally needs `CONNECTOR_DELTA_AI_ENABLED=true`, `CONNECTOR_DELTA_MODEL`
and the dedicated `CONNECTOR_DELTA_ANTHROPIC_API_KEY` Actions secret. Collection
uses GitHub HTTPS endpoints; optional AI uses `api.anthropic.com`.

State is a main-only Actions artifact retained 90 days. Missing state after prior
runs fails visibly. The scanner reads at most 300 recently updated closed PRs and
1,000 files per PR; a cursor outside that window requires manual recovery.
No background service, installation, model cache, generic parser or outbox exists.

## Local tests and a single-PR replay

```sh
python3 -m unittest cli.tests.test_connector_delta -v
python3 scripts/connector_delta_monitor.py analyze --pr codex 44349 --output /tmp/connector-replay
```

Replay uses the supplied checkout as its local comparison target (`--repo` can
select a current-main checkout). Inspect `private-report.json` locally; never
upload it publicly. Replay output cannot publish or advance production state.
No live model calls are needed by tests. Selected regression examples are not a
population accuracy benchmark or live-client certification.

Six real merged PRs were replayed against DefenseClaw main `e1aeafc`: Codex
#44349, #22882, #51433, #19194 and Claude #96570, #96930. All produced review
items with no collection gaps or proven static alerts. In particular, #44349 is
now a review item, not an automatically proven event-routing conflict. This
reduced proof coverage is deliberate; the generic Rust parser has been removed.
