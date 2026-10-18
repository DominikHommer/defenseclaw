<!-- Copyright 2026 Cisco Systems, Inc. and its affiliates -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Native Windows current-MXC PSEC contributor probe

This separate, headless experiment investigates AXIS policy validation with
the current typed MXC SDK. It does not activate a DefenseClaw provider, replace
the old paired executor, or certify a customer runtime. No WSL, host fallback,
credentials, Claude, model, hook, proxy, privileged helper or service is used.

Exact source inputs are AXIS
`fb5fd5f0f9377c2ccb30d7e027a36373de0d037c` and Microsoft MXC
`fda29ac63bc306b7f97f3b86b4b63d44f7f40cf2`, SDK 1.0.1. AXIS contributes its
public policy parser and validation. The runner constructs only a fixed
hard-filesystem/block-network policy, then explicitly translates its accepted
filesystem and timeout fields into typed MXC 1.0.0 authoring types. This is
not a general AXIS policy translator, and it does not forward the old AXIS
0.6.0-alpha wire contract or claim LPAC token equivalence. The fixed AXIS policy
uses `process.identity: backend_default` and allows child processes; no isolated
identity intent or resource limit is silently dropped.

## Reviewed SDK overlay

`patches/mxc-strict-windows-psec.patch` introduces a Windows-only public
`v1::spawn_windows_psec` entry point. It requires explicit ProcessContainer,
forces DACL mutation off, and calls the native `BaseContainerRunner::new`
through the SDK's existing logger/telemetry wrapper. Native policy and host
serviceability validation still run before creation. The fallback dispatcher
is never called. Missing native support or a policy requiring unavailable
PSEC capabilities is an error. No host DACL/BFS fallback is permitted.
This contributor entry point also refuses ingress/host-loopback allowances,
egress allowances, proxy configuration, added capabilities and denial capture
before constructing the backend. Only the explicit fixed offline posture is
admitted; later proxy work requires its own capability and PSEC-version checks.

The patch also makes a failure to confirm an empty owned Job an error, instead
of a warning followed by successful teardown. Native PSEC owns a security
environment handle, closes it after process termination, and does not create
the legacy profile/tracking resources observed in the old paired experiment.
This source behavior still requires actual host verification. An error is a
failed qualification, never evidence of completed containment or cleanup.

The first prototype uses piped stdio only. An inherited-console SDK option
and process-local Ctrl-C callback require a later separately reviewed change
with all three console handles validated. Windows ProcessContainer's advertised
typed PTY function currently refuses caller-controlled PTY creation; this
headless experiment makes no terminal-support claim.

## Build and lock gate

Use an already-provisioned Windows x86_64 build host, Rust 1.95.0, Python 3,
Git and the native MSVC/Windows SDK prerequisites required by MXC. Cargo
downloads dependency sources during this explicit contributor build. The
helper never installs prerequisites or runs its resulting probe. Windows
Server 2022 CI is a compilation host only; no PSEC live run is permitted there.

Prepare a fresh staging directory containing this subtree's tracked files
and exact clean child checkouts:

```text
mxc-v1/
  Cargo.toml
  prepare_build.py
  src/
  patches/
  axis-source/       # exact AXIS commit
  mxc-source/        # exact current MXC commit
```

Run `python prepare_build.py generate-lock`. It verifies source identities,
applies only the reviewed MXC overlay, generates a combined lock, builds with
`--locked`, compiles probe tests without running them, and packages the
binary, source, patch, licenses, locks, compiler identity and SHA256 provenance.
The pure Python build-helper gates run with:

```powershell
python -m unittest discover -s test/e2e/axis/windows/mxc-v1 -p test_prepare_build.py
```

Review and commit the generated combined `Cargo.lock`, then prepare fresh
source checkouts and run `python prepare_build.py build-locked`. A missing or
changed lock is a refusal. Neither upstream lock is a substitute for this
combined lock. No live execution is allowed before the reviewed locked rebuild
and independent source/artifact verification.

## Fixed live scope, after review

The probe accepts no caller command, path, policy or environment flags. Its
child selector accepts only fixed boundary, exit-23 and timeout cases. It
clears the supervisor environment before invoking SDK code or creating threads;
the child receives only explicit system/private state entries with environment
inheritance off. A harmless parent-only `DC_AXIS_INHERIT_CANARY=fixed-public`
must be absent in the child, so inherited safe environment cannot pass silently.
CWD, HOME and temporary paths are private synthetic fixtures.
A 20-second outer watchdog bounds the contributor process, while MXC owns the
configured per-child timeout. It is not a production supervisor contract.

The boundary case tests an allowed write, a read-only canary and a synthetic
outside canary beneath a granted writable parent and an explicit deny on the
nested file. The reviewed SDK seam verifies all explicit grants and denies
survive typed normalization before construction; same-string overlap pruning
cannot make this a default-deny-only observation. Access-denied errors
are required; an unrelated failure is not accepted. Four task-owned IPv4/IPv6
TCP/UDP listeners receive positive host controls before the child attempts its
connections. UDP sends may succeed locally, so the host receivers must observe
no contained delivery. This covers those loopback endpoints only, through the
bounded receiver window; Internet/DNS and proxy enforcement remain unqualified.

The SDK's actual native entry point supplies the PSEC evidence; the child does
not assert `TokenIsAppContainer`, because a current PSEC token is a different
contract from the old BaseContainer experiment. The supervisor retains a
read-only handle opened for the returned direct-child identity before wait,
checks it becomes signaled, and never signals an inferred PID. General process
tree and parent-death qualification require additional controlled live cases.
The verified owned fixture path is removed only after handles have stopped.

This host's read-only query on 2026-10-18 reported PSEC major 1/minor 0 and
support flags `0x3`: native filesystem deny is present, enumeration and ingress
capabilities are absent. Runtime validation remains authoritative. Denial
capture, ingress allowances, enumeration-only grants and proxy identity modes
are outside this prototype; it must refuse requests it cannot represent.
