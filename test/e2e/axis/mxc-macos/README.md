<!-- Copyright 2026 Cisco Systems, Inc. and its affiliates -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# macOS MXC Seatbelt + AXIS policy contributor experiment

This standalone crate is a fixed, benign composition probe. AXIS 0.3.5 parses
and admits a synthetic block-network policy, and MXC SDK 1.0.1 owns Seatbelt
execution and both pipe and PTY handles. It is **not** the AXIS macOS runtime
dispatch path or a DefenseClaw provider. AXIS fb5 currently refuses MXC in
its macOS runtime dispatch; this probe does not substitute the AXIS-native
Seatbelt backend or change any production setting.

The exact source inputs are AXIS
[`fb5fd5f0f9377c2ccb30d7e027a36373de0d037c`](https://github.com/ROCm/axis/tree/fb5fd5f0f9377c2ccb30d7e027a36373de0d037c)
and MXC
[`fda29ac63bc306b7f97f3b86b4b63d44f7f40cf2`](https://github.com/microsoft/mxc/tree/fda29ac63bc306b7f97f3b86b4b63d44f7f40cf2).
The crate uses the published `mxc_sdk::v1` typed API. AXIS's existing
`build_mxc_process_config` validates the admitted plan but emits an older
`0.6.0-alpha` JSON shape; that JSON is never submitted to MXC 1.0.1. The
fixed bridge checks its selected Seatbelt platform, blocked network,
filesystem lists and timeout before constructing `ContainerRequest`.

## Policy and test boundary

The fixed AXIS policy sets `runtime.provider: mxc`,
`filesystem.compatibility: hard_requirement`, `network.mode: block`, and
process resource limits to zero. Zero disables AXIS's process-count, memory
and CPU quota claims, which this Seatbelt route cannot enforce. The planner
receives no weaker-capability acceptance. MXC availability is observed before
the AXIS planner's Seatbelt dependencies are marked present; the actual spawn
remains the decisive host check. The request selects
`Containment::Seatbelt` with no profile override, GUI, nested PTY, Keychain,
or extra Mach lookups. It supplies only a fixed environment under a private
0700 fixture and disables default-environment inheritance and telemetry.

MXC's generated profile has `(deny default)`, but it also grants read access
to `/bin`, `/sbin`, parts of `/usr`, `/System`, `/Library`, `/private/etc`,
and other system directories before applying caller grants and trailing
explicit denies. The synthetic AXIS policy names those static system reads
and MXC's four read-write device nodes. The profile also permits `/` data
reads, ancestor metadata, PTY access, and may add the active Xcode bundle;
those are not exact AXIS filesystem allowlist semantics. General metadata
confidentiality and dynamic system-read parity are **outside this probe**.
Production DefenseClaw policy translation would need to account for every
implicit grant or refuse the backend for policies it cannot represent. The
existing AXIS-native profile is not used; this experiment tests MXC's
generated policy and does not establish equivalence with that separate backend.

The child receives a private `HOME`, CWD and TMPDIR. It must write in HOME
and CWD, read a nested read-only canary but fail to write it, fail to read,
write or stat explicitly denied canaries in both HOME and CWD, and fail to
read or create an ungranted sibling. Every canary contains a public fixed
string. A host-side positive control connects to a local ephemeral listener;
the sandboxed child must fail the same loopback connection with a permission
error. No external network service, credentials, Claude session, proxy,
model or shell command supplied by a user is involved.

Separate cases require a pipe echo on stdout and stderr with exit 23; an
MXC-owned PTY with foreground/`isatty` checks, a readiness handshake,
30x100 to 40x120 resize visible to the child, echo and exit 23; and an MXC
typed timeout after a descendant announces readiness. A delayed descendant
would write a private marker three seconds later if it survived. The
supervisor checks that the marker remains absent. Output capture is capped
at 64 KiB per stream, each case has an MXC timeout and an additional
15-second polling deadline. An outer CI process deadline is still needed in
case SDK spawn itself hangs. A clean result proves only these exact benign
cases on the tested macOS host; it cannot certify general policy equivalence,
all descendant cleanup, security of arbitrary paths or production readiness.

## Build-only lock discovery and reviewed rebuild

Use a fresh disposable macOS arm64 or x86_64 staging directory containing
this directory's source, plus clean full checkouts at the exact commits:

```text
mxc-macos/
  Cargo.toml
  prepare_build.py
  src/
  axis-source/       # exact AXIS commit
  mxc-source/        # exact MXC commit
```

The build requires already-provisioned Rust 1.95.0, Python 3, Git and the
upstream native build prerequisites. It may download Cargo dependency
sources; no build step runs the probe. In the first staging directory run
`python3 prepare_build.py generate-lock`. The helper verifies source Git
identities and cleanliness, generates a combined `Cargo.lock`, builds with
`--locked --release`, compiles tests with `--no-run`, and emits a
`build-artifact/` with source, binary, upstream locks and licenses, toolchain
record, SHA-256 manifest and provenance. Review and commit the generated
combined lock. Then use a **new** staging directory with fresh clean source
checkouts, the reviewed lock and `python3 prepare_build.py build-locked`.
That mode refuses a missing lock and checks it did not change. The generated
lock artifact must not be run live before review and locked rebuild.

There is no workflow or live result in this directory. An eventual disposable
macOS Actions live job should run only the reviewed locked artifact as an
unprivileged user, with an outer process-group watchdog and a 60-second
deadline. It should record the artifact provenance and hashes with the exact
macOS version/architecture and the probe's fixed JSON outcome. A failed
admission, unavailable Seatbelt, wrong errno, missing acknowledgement, wait
error or teardown failure is a failed experiment; no alternate backend is
used.
