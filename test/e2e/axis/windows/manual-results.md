<!-- Copyright 2026 Cisco Systems, Inc. and its affiliates -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Native Windows AXIS/MXC contributor results

Recorded on 2026-10-18 on Windows 11 Enterprise, build `26200.9457`, x86-64,
using the existing non-administrator account. These are native Windows
ProcessContainer observations. Customer runtime qualification remains incomplete.

## Verified baseline build

The baseline came from [workflow run 39105989574](https://github.com/cisco-ai-defense/defenseclaw/actions/runs/39105989574),
DefenseClaw workflow commit `001c776266df9b7828645662d33e89ce33316a7e`.
It built AXIS `fb5fd5f0f9377c2ccb30d7e027a36373de0d037c` and Microsoft MXC
`1736b48398c3fe4d1315b2311c0951cc893eb3ae` with all three AXIS compatibility
patches, using Rust `1.95.0` and locked dependencies.

| Input | SHA256 |
| --- | --- |
| GitHub artifact ZIP, ID `12128646666` | `0f631868d3b87aa73435110cf237a519af09d538165ee36cf92826d3895272f3` |
| Packaged Windows source-build ZIP | `b4754c8b62a4529a4074b962740626bc0cb198944774f72ed6df7d8f3e0485ec` |
| `axis.exe` | `b1a88754b3f45dfa0dbb7f4a051c43e253dd8cdf9e568f406c23d5a1702a765e` |
| `axisd.exe` | `259b7125ebcae3d331543a359991f29943aa6f2b1ffeccf2ff0a9f602abf93bf` |
| Paired `wxc-exec.exe` | `b5d7425e0674e13e6e5e5c23286e353a623281f36e9ead5009264e416e76e60a` |
| Fixed boundary/exit/timeout probe | `3edebd77f59103fd9780907d717567c28a6c5d6d1f88f4fa276b24817ec1c906` |

The GitHub artifact digest, inner archive checksum, exact file inventory,
every binary hash, compiler metadata, AXIS source metadata, MXC source lock,
and all three source patches were verified before runtime execution. The
Windows checkout used CRLF for MXC's lock and license; these matched the pinned
Git blobs after only CRLF-to-LF conversion. Both byte hashes were retained:
the packaged MXC lock is `c688121170cfeac6b6b2444e2559558636af7bcded61605a5496101eec92be0a`;
the Git blob is `2a5c071bbcbb021796a81e4a28e1aaec90ea046a91b6804876cd89eb57eb98f0`.

The fixed baseline probe binary is retained at the digest above. Its source
subsequently gained terminal and descendant modes while still uncommitted;
these historical runs therefore do not certify a later committed source
revision. A final source-bound rebuild and rerun remain required.

## Executed fixed cases

Each case used newly created private HOME, USERPROFILE, AppData, temporary and
workspace directories under
`C:\Users\vnarajal\.codex\axis-manual-test\windows-baseline`.
The process environment was constructed explicitly, including only a synthetic
API-key canary. The policy explicitly selected `provider: mxc`, process
containment, `filesystem.compatibility: hard_requirement`, the private workspace
and temporary grants, one read-only fixture, one outside canary, and
`network.mode: block`. No real model credentials were supplied.

The command shape was:

```text
<verified>\bin\axis.exe --socket 127.0.0.1:0 run --policy <case>\policy.yaml -- <case>\workspace\axis-windows-fixed-probe.exe -mode <fixed-case> -root <case> -tcp-port <owned-port> -udp-port <owned-port> -tcp6-port <owned-port> -udp6-port <owned-port>
```

Port zero is an unavailable-daemon selection experiment for this contributor
test. It is not a production standalone API contract. Standard input was closed,
so these cases requested headless execution.

| Case | Actual observation |
| --- | --- |
| `boundary-02` | Child started inside ProcessContainer; `TokenIsAppContainer=true`; CLI exit **0**. |
| Private state | CWD matched the private workspace; HOME, USERPROFILE, AppData and temporary paths stayed beneath the private case root. |
| Environment canary | Synthetic `OPENAI_API_KEY` was absent from the payload. |
| Workspace write | Allowed synthetic write succeeded. |
| Outside canary | Read and write returned Windows **Access is denied**; contents remained unchanged. |
| Read-only fixture | Read succeeded; write returned **Access is denied**; contents remained unchanged. |
| IPv4 and IPv6 TCP loopback | Positive host delivery controls passed; contained connect returned **WSAEACCES**; neither host listener accepted a contained connection. |
| IPv4 and IPv6 UDP loopback | Positive host delivery controls passed; contained sends were accepted locally, but neither host receiver observed a datagram. |
| `exit23-01` | Confirmed payload start; child exit **23** propagated as CLI exit **23**. |
| `timeout-01` | Confirmed payload start; one-second policy timeout returned CLI exit **1** with `Windows MXC process timed out after 1 seconds`; outer deadline was not reached. |
| Post-case inspection | AXIS leaders were reaped; CIM inspection found **0** processes with executable paths beneath the task's Windows baseline root. |

Receiver observations covered the four task-owned loopback endpoints through
250 ms of receiver waiting after payload exit. They do not establish Internet,
DNS, arbitrary destination, or strict proxy enforcement. The initial
`boundary-01` assertion incorrectly expected every UDP send to return an
immediate permission error; its failed result is retained. `boundary-02` added
positive host controls and receiver-side observations rather than interpreting
a successful UDP send as delivery.

## Retained evidence and remaining gates

Raw `verification.json`, policies, exact argument arrays, stdout, stderr,
`result.json` files, and source-built binaries remain in the task-owned baseline
directory. Fixture directories are retained as evidence. No AXIS daemon, WFP
service, privileged helper, installer, or WSL environment was started by these
Windows probes. These runs did not measure general descendant custody or host
ACL invariance.

## Inherited-console experiment

[Workflow run 39107327232](https://github.com/cisco-ai-defense/defenseclaw/actions/runs/39107327232)
built the same upstream commits and toolchain with DefenseClaw workflow source
`23dfdbc2df6b7a5c1951c280bb0d10854e6e2c84`. Its reviewed AXIS admission overlay
retained `interactive_terminal=true` and required all three standard handles to
be consoles. It did not pass HPCON directly to the BaseContainer API or select
another isolation tier.

| Input | SHA256 |
| --- | --- |
| GitHub artifact ZIP, ID `12128339507` | `b901f002bc6848f816580766f6beb939ff40919ad6d72107b9f6a6a97568f1d9` |
| Packaged inherited-console ZIP | `135f4836f3c81ec7afc10ddf9da3896124479ae24b942a99418514d0438342ca` |
| Reviewed admission patch | `2dae4716da9581632fe9f19929a78902df71a2d828ea726b3545c7387686b8c4` |
| `axis.exe` | `e80b0277b371c555cdad4197f5785658338678f5895205c6c85507bab913dd65` |
| Paired `wxc-exec.exe` | `f1856f248004d9649a596391e10fc387b5585bc82838eb879bcb170577b8a0d2` |
| Fixed terminal/tree probe | `7f3d1aa8dcc6714f6bd52a625cb5a03c5d1e2ea13b349652a8b94142e52f08e6` |

The outer GitHub digest, inner archive, exact inventory, all binary hashes,
source and lock metadata, three paired MXC patches, and byte-identical reviewed
admission overlay passed verification before execution. Evidence remains under
`C:\Users\vnarajal\.codex\axis-manual-test\windows-inherited`.

| Case | Actual observation |
| --- | --- |
| Initial harness diagnosis | `terminal-basic-01` and `outer-control-01` failed because the harness inherited redirected standard handles. These failed results are retained. |
| `outer-control-02` | Explicit uncontained fixed host control passed console handles, input, 100×30 to 160×40 resize and exit 7 after the harness supplied null standard entries with `STARTF_USESTDHANDLES`. This is plumbing evidence only. |
| `terminal-basic-02` | Inside AppContainer, private state and all three console handles passed; keyboard input was acknowledged; resize reached 160×40; child exit **7** propagated. |
| `terminal-01` | Basic checks passed, then Ctrl-C terminated AXIS with **0xC000013A** before the payload acknowledged the interrupt. Continued input remains unqualified. |
| `timeout-02` | A contained fixed leaf started; the one-second timeout stopped AXIS with exit **1** and the exact timeout diagnostic. The first assertion raced output draining; that failed result is retained and the corrected bounded drain passed. |
| `close-session-01` | A contained fixed leaf started; closing the owned ConPTY stopped the AXIS supervisor with **0xC000013A**. |
| `parent-death-01` | CIM positively observed AXIS, MXC, payload and contained leaf. Killing only the tracked harness handle left **0** observed processes beneath the owned directory prefixes or at the known task PIDs. |
| Post-lifecycle inspection | No processes with executable paths beneath the task's Windows inherited-console root remained. |

The terminal commands used the fixed `console_harness_windows.go` executable,
the verified bundle record, an explicit payload SHA256, a fresh case root, and
one of the documented fixed modes. Exact argument arrays, policies, output and
statuses are retained in the private result files. The helpers changed during
these diagnostics; final committed-source rebuilds and reruns remain required.

Process termination does not establish complete resource cleanup. The pinned
MXC source [explicitly leaves profile, BFS policy and tracking cleanup as a stub](https://github.com/microsoft/mxc/blob/1736b48398c3fe4d1315b2311c0951cc893eb3ae/src/backends/appcontainer/common/src/base_container_runner.rs#L101-L119).
These old paired binaries remain feasibility evidence. A maintained cleanup
contract and review of the current MXC API are required for a customer adapter.

A third `inherited-console-relay` build adds separately reviewed AXIS and MXC
process-local Ctrl-C handlers. Its artifact and live behavior are pending.
Claude, hook relay, credential confidentiality, strict proxy enforcement and
the complete customer runtime remain unqualified.
