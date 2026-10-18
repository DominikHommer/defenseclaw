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

The first locked native run (build `215f3e98936b34279e31670a4fed14d5f47542c2`)
failed before its payload marker with `0xC0000142` (`DLL_INIT_FAILED`). Its outer
Job was empty afterward and the failed fixture was retained. The SDK-bearing
self-payload imports Shell32/COM and other libraries; a Win32k/import interaction
is a hypothesis, not an established cause. No UI restriction or filesystem
grant is relaxed to make the experiment pass.

The distinct `separate_std_loader_diagnostic` artifact includes a second binary,
`defenseclaw-axis-windows-psec-loader-child.exe`, whose source uses only Rust std
and has no AXIS/SDK references. The parent requires the fixed `--loader-only`
selector and computes that exact sibling path. It uses the same hard/block
policy and native admission, then requires the unique marker and typed exit23.
Its four checks cover that marker, exit, retained direct handle and owned fixture
removal only; it never reports the nine boundary checks. Both image hashes and
the diagnostic variant must be verified, and the child's imports inspected,
before any separately reviewed native execution.

That separate diagnostic passed once on the native host from build
`a96ef846d7c75987c9266aa96f928c8915dbcc3d`: the std-only child printed its marker,
returned typed exit 23, and its retained direct handle was signaled. The outer
custody Job was empty and no owned fixture remained. This demonstrates startup
under the unchanged policy; it does not establish the precise DLL failure cause
or qualify the original boundary checks.

The next source-only variant, `standalone_std_boundary_literal_argv`, moves
the boundary, exit and timeout payload into a third, std-only binary. It also
tests empty arguments, spaces, quotes, trailing backslashes, Unicode and shell
metacharacters as literal arguments. These new sources have not been compiled
or executed. The previously reviewed loader live helpers intentionally reject
this different variant until separately updated and reviewed.

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

The next build composes that strict overlay, the shared reviewed
`test/e2e/axis/patches/mxc-literal-argv.patch` (SHA256
`7117afc3c7ae28345757c364518b7b9120a7dd8e6b844403b06fe05403e4a76d`),
then `patches/mxc-windows-literal-argv.patch`. The last overlay adds only a
strict `v1::spawn_windows_psec_argv` route. It retains the native admission and
fallback refusal, requires an empty legacy command, passes an explicit absolute
application name to `CreateProcessW`, and encodes bounded UTF-16 arguments using
Windows C/Rust quoting rules. It starts no shell. The generic Unix literal-argv
dispatcher continues to reject ProcessContainer. Native pipes, Job setup,
filesystem policy, UI restrictions and network policy remain unchanged.
The new route admits only unambiguous local drive paths on fixed volumes.
It refuses UNC/device/ADS paths, redirected or SUBST drives, and reparse points.
It opens each path component without following reparse points, keeps read-only
sharing custody through process creation, and uses the image handle's volume
GUID path as the explicit application. The host still needs its own reviewed
digest/identity admission before this contributor seam can become a general
customer launcher.

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
and exact clean child checkouts. Stage the shared literal-argv patch from its
exact repository Git bytes into `patches/mxc-literal-argv.patch`; it is an
explicit additional build input rather than a duplicate tracked patch:

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
applies the three reviewed MXC overlays in order, generates a combined lock, builds with
`--locked`, compiles probe tests, runs one selected pure path-spelling test, and packages the
three binaries, source, patches, licenses, locks, compiler identity and SHA256
provenance. It fingerprints the 12 modified and three added SDK files before
and after the build; an unstaged Git diff alone cannot detect changes to added
files. No dependency has been added for the separate std-only child.
The pure Python build-helper gates run with:

```powershell
python -m unittest discover -s test/e2e/axis/windows/mxc-v1 -p test_prepare_build.py
```

Review and commit the generated combined `Cargo.lock`, then prepare fresh
source checkouts and run `python prepare_build.py build-locked`. A missing or
changed lock is a refusal. Neither upstream lock is a substitute for this
combined lock. No live execution is allowed before the reviewed locked rebuild
and independent source/artifact verification.

The committed combined lock is SHA256
`3b29ecb06dd2a81266c84712f8d6e088605290f386e87498bb7a7472a005af69`
(223 packages). Review matched 150 registry checksums to the two upstream
locks and checked the other 70 versions against the official crates.io index
for checksum, non-yanked status and Rust 1.95 compatibility. The only path
packages are this fixed probe, AXIS core 0.3.5 and MXC SDK 1.0.1. This lock
review is independent of the still-pending native build and live gates.
The disposable Windows build initializes its installed Visual Studio x64
developer environment and verifies that `link.exe` belongs to that exact
installation; Git for Windows' Unix linker is not a compatible MSVC linker.

## Fixed live scope, after review

The probe accepts no caller command, path, policy or environment flags. Its only
optional operator selector is the fixed `--loader-only` diagnostic. Its
standalone child accepts only fixed argv, boundary, exit-23 and timeout cases. It
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
Errors retain the fixture for inspection, including an SDK Job-empty failure;
the retained direct-child handle closes through RAII even on an early pipe error.

This host's read-only query on 2026-10-18 reported PSEC major 1/minor 0 and
support flags `0x3`: native filesystem deny is present, enumeration and ingress
capabilities are absent. Runtime validation remains authoritative. Denial
capture, ingress allowances, enumeration-only grants and proxy identity modes
are outside this prototype; it must refuse requests it cannot represent.

The fixed boundary child records its DOS-based Rust `canonicalize` result but
uses its explicit current directory for the canary operations. A native run on
this host opened that directory with access 0, obtained its NT final path and
read its fixed seal, while both normalized and opened DOS final-path queries
returned Access denied. The fixture shape, exact private environment and seal
checks remain mandatory. This preserves the DOS-query compatibility limitation
without confusing it with denial of a granted file operation; no grant or SDK
policy is broadened. A passing canary run would not qualify applications that
require the denied query.

The fixed private-environment assertion accepts only the optional `\\?\`
prefix on an otherwise byte-for-byte identical local drive path. The parent
canonicalizes the fixture, while Windows can return its current directory
without that prefix. Case folding, slash changes, dot components, other drives,
UNC/device paths and a different home remain refused. A selected pure Rust
test exercises these cases during the build; it performs no sandbox operation.
