<!-- Copyright 2026 Cisco Systems, Inc. and its affiliates -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Fixed native peer contributor harness

This is source for a separate Linux amd64 experiment. **Artifact admission is
disabled:** `liveRegistry.Reviewed` is false, and the explicit command refuses
before reading an artifact, creating a fixture, sealing a memfd or starting a
peer. No peer, Bubblewrap or payload execution has been performed by this
harness. Nothing here activates a customer runtime.

The first slice connects the actual `bridgeprocess` factory and Rust protocol
to four fixed payload cases: literal argv, binary stdin plus EOF and separate
stderr, exit23, and filesystem/offline-socket boundaries. Tests use fake owners,
public synthetic files and deliberately non-runnable ELF headers only. They
never call `bridgeprocess.Start`, create a namespace or execute a native image.

## External artifact review remains mandatory

The eventual registry entry is a source-reviewed exact receipt digest and
complete typed contents. There is no executable/hash/argv/policy CLI override,
discovery, network request, download or fallback. An independent reviewer must
first verify source Git blobs/patches, both build run/artifact/archive/provenance
identities, reviewed locks and all static-musl compiler/UAPI/startup/link inputs.
The two independently staged Bubblewrap builds must reproduce the admitted
image. ELF structure alone cannot qualify this closure. The Go payload must be
source-bound and built using Go1.26.5 with `CGO_ENABLED=0`.

The exact receipt is named `REVIEWED-ARTIFACTS.json`. Its directory contains:

```text
images/peer
images/bwrap-static-musl
images/fixed-payload
proofs/STATIC-CLOSURE.json
proofs/peer-PROVENANCE.json
proofs/payload-PROVENANCE.json
source/payload-main_linux.go
```

The receipt binds version1/scope, no prior execution or production certification,
the three upstream commits, static-closure/payload-source SHA256, ordered peer
and payload build identities, and the exact three image roles/paths/sizes/hashes.
Only a subsequent independently reviewed source change can populate the closed
registry. The running harness verifies the exact receipt/proof/source/image
bytes through nonfollowing held-relative reads and copies admitted images into
sealed memfds. The static Bubblewrap and payload also refuse ELF interpreter or
dynamic program headers. The trusted peer permits only the known system ELF
interpreter and libc/libgcc dependencies, without RPATH/RUNPATH; those host
loader objects remain part of the independently reviewed native host floor.

## Fixed host capabilities and protocol

The live entry requires non-root native Linux amd64, equal real/effective IDs,
the factory's supported unprivileged user/PID/network namespaces and atomic
pidfd custody. It changes no host sysctl, namespace mapping, capability,
privilege, ACL or firewall configuration. Missing kernel/host prerequisites
refuse; disposable-runner preparation belongs to a separately reviewed recipe.

The normal fixed selector always creates a separate guardian-owned PID
namespace for a sealed copy of its own already externally admitted running
static wrapper image. It never executes a caller-selected wrapper. The guardian
retains the atomic clone pidfd and its creating OS thread through native wait.
Worker PID1 first verifies its inherited private pipes and sealed self identity,
installs `PR_SET_PDEATHSIG`, then sends fixed READY. Only after READY does the
guardian write one exact GRANT and EOF. There is no queued future work before
READY: parent loss before that guard yields no GRANT; after it, kernel SIGKILL
of namespace init also terminates its descendants, including nested peer PID
namespaces. This avoids Go's pre-exec parent-PID comparison across a new PID
namespace. An explicit hidden worker selector refuses outside PID1/getppid0,
without the exact descriptors, or without the grant. No test exercises clone,
prctl, the hidden worker or this death/cleanup behavior; it needs independent
source/artifact review and actual native qualification.

One fresh random `/tmp/dc-axis-native-peer-<32 lowercase hex>` fixture is created
under the held root-owned sticky `/tmp`. Its owner-private root has distinct
`work`, `home`, `tmp`, `outside` directories, readonly file and fixed public
canaries. Before launch the host proves outside read and write-open positives
without changing bytes. Original canary file identities/bytes and grant modes
are checked before/after execution. The held `/tmp` parent, original root name
and outside child name must still resolve without links to the held directory
identities at each check. These are sampled checks, not an atomic guarantee
against a same-UID actor renaming an object mid-case. Negative payload probes only open/close
without truncation, creation or writes. The fixture is retained on all outcomes;
partial setup errors report its new name, and no previous fixture is removed.

Only held readonly/work/home/tmp objects cross the factory's exact capability
table, with work also supplied as held cwd. Outside descriptors never cross.
The peer receives no host object path for its grant table, full policy snapshot,
credential or broker binding. Guest mappings are exactly `/readonly`, `/work`,
`/home`, `/tmp`; argv0 is the sealed `/.defenseclaw/payload`. The only supplied
environment values are HOME=/home, TMPDIR=/tmp and the fixed public selector;
the payload separately requires Bubblewrap's exact derived PWD=/work.

Each fixed case uses a fresh unique correlated session and serialized
Prepare→Prepared→Launch→Started, Input/EOF where applicable, Wait/Exited23,
Destroy/Destroyed. The first three cases check exact byte streams; boundaries
also checks host-visible writes to all three grants and unchanged original
canaries. The owner enforces sequence/request/state/output limits; the harness
checks expected replies, exact binding, aggregate output, typed exit/timeout/
truncation and markers. It drains while running, rather than waiting for process
completion before receiving. The fixed policy is offline with 5-second workload
and 64KiB output bounds, a 20-second owner deadline per case and 90-second total
context. Cleanup gets a fresh bounded context; success additionally requires
the factory's independent namespace-init pidfd termination/wait through Close.
The loop stops on the first failure, without releasing a failed reservation to
start another case. Receipt JSON/peer completion does not substitute for native
cleanup. A failed cleanup retains the exact Session in a reachable owner and
retries native StopAndWait with a fresh bounded context, including before final
reporting. The original failure remains a failed case even if retry cleans.
The outer guardian independently kills and waits the worker PID namespace at
the total deadline and on every return, with its own retained owner and bounded
retry. Remaining cleanup capability stays reachable through final reporting;
unobserved cleanup is a failure, never a success or an assertion of no residue.
After a pending native start, an unobserved creation result is reported as
unknown. A peer Started reply and validated fixed child output markers are
separate fields; a launch acknowledgment alone is not payload-code evidence.

The 90-second context is an execution deadline, not a promise that every host
filesystem syscall completes within 90 seconds. Artifact/fixture filesystem
operations run inside the guardian-owned namespace once admitted; the guardian
can terminate that namespace without depending on the worker's filesystem call
returning. Self-image preparation before clone has no descendants. A separately
owned outer wrapper deadline must also cover this pre-clone stage. Native kill
or wait that cannot complete within cleanup bounds remains explicitly pending.

Binding digests correlate only this contributor experiment. Production
`LaunchGate`/`ExecutionPolicy` require managed hooks and admitted harness
evidence that this canary does not implement. This source does not fabricate
ManagedHooks or a Claude identity to satisfy them. Common-gate integration,
hooks, broker/proxy, model/credentials, interactive terminals and customer
workspace import/export remain unqualified. Deadline/cancel/close, malformed
peer, root-parent-death/descendant and renamed/stale-grant live cases are
separate future experiments; a short successful exit is not those tests.

## Inert validation and later explicit invocation

```text
go test -race -p 1 ./test/e2e/axis/native-peer/harness -count=1 -timeout=2m
go vet -p 1 ./test/e2e/axis/native-peer/harness
```

Linux adds held-file/symlink/FIFO/identity and anonymous sealing tests. Other
platforms run only portable fake-protocol/admission tests and refuse native use.
No test installs or runs an artifact. Cross-compilation is not Linux execution.

After exact artifacts are independently admitted, the source registry is
reviewed, and one fresh native run is separately authorized, the only invocation
shape is `reviewed-harness --run-fixed --receipt <admitted-directory>/REVIEWED-ARTIFACTS.json --evidence <private-parent>/native-peer-fixed-01`.
The evidence parent must already be owner-private. The separate outer driver
must pin the wrapper/source identity, bound its retained process handle and
streams, and retain raw evidence even on early refusal. Acceptance requires
zero wrapper exit, the guardian's successful native wait in final stdout, and
matching worker observations in stdout/`RESULT.json`. Guardian-only fields are
added to final stdout after the worker's file receipt. A final result-file or
directory close failure may leave an earlier file image and must fail the run.
The wrapper reports bounded fixed reason codes rather than private backend
diagnostics. A future native run's actual result must be recorded separately.
