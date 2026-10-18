<!-- Copyright 2026 Cisco Systems, Inc. and its affiliates -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Proposed DefenseClaw runtime bridge

This is a contributor design, not an implemented execution path. The current
product still refuses active AXIS configuration. The shared controller alias,
selection/capability contracts and immutable execution-policy resolver exist;
the router, AXIS adapter, bridge protocol and production qualification below
do not. The offline probes are separate feasibility evidence.

## Ownership boundaries

| Owner | Responsibility | Existing seam or required change |
| --- | --- | --- |
| Common Go control plane | Current config and administrative/repository resolution, session ownership, policy generations, approvals, hook health, audit and workspace review/pull/undo | `internal/sandboxruntime.Controller`, existing manager/workspace logic and `ResolveExecutionPolicy`; extract shared orchestration incrementally |
| OpenShell implementation | Its vendor gateway, images, profiles, discovery and existing execution/transport | Retain `internal/openshell/manager` and current CLI transport while adding a common facade |
| Go AXIS adapter | Translate a frozen admitted policy, prepare session state, invoke the host bridge and check its exact evidence | New adapter beneath the common control plane; no new configuration authority |
| Typed Rust host bridge | Own the selected MXC SDK backend and all resulting process/PTY handles, bounded I/O, resize, wait, cancellation and cleanup | New pinned executable bundle; no daemon/listener when disabled |
| Trusted final child bootstrap | Validate its private launch plan, establish platform execution state, apply AXIS guards and exec the admitted literal agent argv | Executes inside MXC containment before untrusted code; receives no provider credentials |
| Host credential/egress broker | Evaluate the original host policy and approvals, bind requests to the admitted executable/session, hold and inject credentials | Existing Go authority retained; platform attribution/transport must be qualified before granting credential capabilities |

The original private policy evaluator remains authoritative. Its inspection
JSON omits host evaluator facts and cannot be reconstructed into executable
authority. Never flatten curated/operator rules into an MXC allowlist and
treat that list as equivalent policy. `strict` still permits separately
authorized broker traffic; explicit offline execution is a separate posture.

## Prepare, admit, then launch

The currently inert `Backend.Provision(ctx, Spec)` contract has no frozen
policy or prepared-plan/receipt parameter. It is insufficient as a production
launch API. Before its first implementation, change or supplement that
optional contract so policy custody is explicit; do not implement launch by
deserializing a `Spec` or accepting its runtime identity as admission.

The concrete flow should be:

1. Under the current trusted configuration snapshot, Go resolves the complete
   execution policy and captures its host authority snapshot ID/generation.
   It validates the chosen exact runtime/harness artifacts and capabilities.
2. Go creates an immutable, bounded typed translation for one private staged
   workspace and one exact session identity. The trusted adapter/host bridge
   prepares resources and returns a prepared handle plus its complete policy
   translation receipt. Preparation runs no agent and grants no credentials.
3. While holding the authority-generation serialization boundary, Go checks
   the receipt against the frozen policy, current authority binding, complete
   component coverage and exact runtime/harness identities. It checks current
   owner, listeners, repository identity and prepared workspace custody too.
4. Go submits a one-use launch authorization bound to that prepared handle,
   policy digest and still-current generation. The bridge must reject reused,
   changed or stale requests. Authority rotation cannot race between this
   admission and the untrusted process launch.
5. The trusted child bootstrap reads only its guest-safe launch subset, closes
   the plan transport, establishes containment-specific process/terminal
   state, sets `no_new_privs` and applies required AXIS guards before literal
   `execve`/native process launch. Provider credentials stay on the host.
6. Policy/broker revocation closes grants and contains the running session.
   Reattachment, resize, stop, export and deletion compare the full recorded
   owner/session/runtime identity and applicable current generation.

The shared `LaunchGate` now supplies host-side admission/launch serialization,
one-use private prepared handles, copied full launch specifications and receipt
evidence, actual authority-source/history checks, and bounded owned cleanup on
refusal or partial launch. All host authority writers must enter its rotation
transaction; the adapter/controller must reserve unique session identities and
own successful workloads. It is not yet wired to a production adapter, policy
translator, workspace preparer or credential broker. The remaining bridge flow
above is still a protocol requirement.
The policy inspection snapshot contains host-confidential workspace paths and
provenance; it must stay on the trusted host. The child receives a deliberately
restricted execution plan, not the original snapshot or broker authority.

## Existing integration points

The public `gateway.SandboxController` name is a compatibility alias for
`sandboxruntime.Controller`. A router implementing that full contract can
preserve existing REST and managed behavior. Creation needs an additive
runtime selector. A missing selector/default/legacy record continues to mean
OpenShell. After creation, route from the private stored full identity, never
from the current default or a guessed platform. Refusal never changes runtime.

`sandboxapi` currently lives under OpenShell and the common controller imports
it. Importing `sandboxruntime.RuntimeIdentity` back into those wire structs
would create a cycle. Use a scalar runtime selector initially, with full
identity in owned state, or first extract dependency-free identity wire types.

The controller seam alone does not abstract execution. In
`internal/openshell/sandboxcli/session.go`, `session.attach` still builds
`s.cli.Exec` OpenShell invocations. Workspace staging/upload/download also
uses OpenShell transports. Introduce one common session execution/terminal
and workspace transport there, preserving current output filtering,
interrupt/session handling, review, pull, accept and undo behavior. Keep the
current OpenShell implementation as one transport.

The gateway and managed per-user daemon remain the execution owners. The CLI
should attach to their authenticated execution stream on the existing API
listener rather than launch an unsupervised host bridge itself. A bounded
stream carrying stdin/output, resize and completion can adapt
`Backend.Exec(ProcessIO)` and `TerminalBackend.Resize`. The repository already
uses `gorilla/websocket`; no additional network listener or transport
dependency is necessary merely to provide this stream.

`buildSandboxRuntime` currently constructs a concrete OpenShell manager, and
`sandboxRuntime.manager` is `*manager.Manager`.
`managedSandboxController` also embeds that concrete manager. Extract narrow
broker/registration/health and custody interfaces around those calls before
wiring a second implementation. Preserve the managed registration,
generation and listener-loss transactions. Copying the manager into a second
provider would duplicate its authority and lifecycle behavior.

## Host bridge transport and launch data

Use a versioned, length-bounded private pipe protocol between the owning Go
process and its verified Rust child. Define explicit preparation, launch,
stdin, resize, wait, cancellation and destroy messages, bounded responses,
sequence/request IDs and exact session/policy identity. Do not introduce a
long-running listener or an unbounded queue. Closing the owner channel must
revoke grants, kill and wait the owned SDK handle; helper/descendant behavior
still needs separate platform qualification.

The Rust API can preserve native Unix `OsString` bytes internally. A JSON IPC
protocol has a narrower string domain: reject invalid UTF-8 at that wire
boundary, rather than replace bytes lossily. Preserve empty arguments,
Unicode, quotes and shell metacharacters as data. They are never command text.
Windows needs native UTF-16 command-line quoting and an explicit application
name when it gains literal argv support.

MXC V1 currently takes a string command. Bubblewrap appends `-- sh -c`; Seatbelt
launches `/bin/sh -c`. The separate
[literal-argv contributor patch](patches/mxc-literal-argv.patch) proposes an
additive typed route while retaining existing public command-string APIs.
That SDK patch now compiles on both Unix platforms and passes the selected
pure tests; actual literal workload probes and production support remain pending.
Unsupported backends must refuse the literal request without shell rendering
or a generic fallback. A future bootstrap uses its actual admitted argv,
not string interpolation into those legacy command paths.

## Platform-specific outstanding work

For Linux, preserve MXC's user/PID/IPC/UTS/network namespaces and owned PTY.
MXC establishes its controlling PTY before entering Bubblewrap's PID namespace,
so a trusted final bootstrap may need to establish the visible child process
group and set it as foreground, temporarily blocking/restoring SIGTTOU. Zero
namespace group IDs are not positive foreground evidence. Actual positive
IDs, input/resize and fixed foreground-signal acknowledgement must pass without
dropping PID isolation or weakening AXIS guards.

MXC's newer proxy-only slirp/firewall route is not executable-bound credential
authority. Pinned AXIS connect-time attribution is private and its older MXC
integration accepts a different network strategy. A maintained attribution
handoff to the host broker, with peer/executable/session verification, is
required before the new route can advertise `HostCredentials` or
`ExecutableCredentialBinding`. A namespace allowlist or a transferable
placeholder alone is insufficient.

Native Windows uses its own strict PSEC ownership and qualification route;
native macOS uses Seatbelt. Their argv, terminal, broker and credential
evidence must be independently qualified. A result on Linux or WSL does not
enable either platform. Keep platform patches composable at the exact reviewed
upstream source, with explicit artifacts and no provider/tier fallback.

## Implementation order

First review/build the literal-argv seam and finish discriminating platform
probes. Next implement the private typed host protocol and synthetic offline
adapter with no production activation. Then connect the common CLI transport,
policy preparation/admission/launch serialization and owned workspace flow.
Add authenticated hook and host broker/credential binding with real denial
tests, followed by listener loss, parent/descendant cleanup and managed
ownership/generation tests. Finally run real headless/interactive Claude and
review packaging, installation, upgrade and rollback before enabling a
qualified platform/runtime option.
