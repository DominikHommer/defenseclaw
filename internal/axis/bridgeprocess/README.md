<!-- Copyright 2026 Cisco Systems, Inc. and its affiliates -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Private native process custody

This disconnected Linux x86_64 source creates the trusted private Rust peer,
not a customer sandbox. No production caller, artifact registry, broker,
provider capability claim or configuration activation is supplied here.
Other hosts refuse before opening an image or starting a process.

The host must independently admit runtime and harness artifacts and obtain
their digests from its trusted registry. `SealImage` copies an already-open
regular file, checks the exact copied bytes, and seals an anonymous memfd.
It never discovers a path or accepts wire digests as authority. ELF structure
alone does not establish provenance or a static-musl loader closure.

The factory duplicates held images and filesystem objects into the Rust peer's
fixed FD table. Its only executable name is its own remapped sealed descriptor
through `/proc/self/fd`; it supplies zero arguments and an empty environment.
The peer starts inside fresh unprivileged user/mount/PID/network/IPC/UTS namespaces.
FD3 is a sealed parent namespace-identity proof; image/root capabilities begin
at FD4. Before control or backend work, the trusted peer proves new namespace
ownership, mounts a private matching procfs and clears its startup capability.
The only ambient startup capability is SYS_ADMIN in the new user namespace;
the verified parent has none. See [namespace bootstrap](../namespaceinit/README.md)
for the exact trusted initialization interval and refusal gates. This new
private handoff needs a freshly admitted peer and harness artifact; prior
artifact/runtime observations do not qualify it.
An atomic clone pidfd owns the exact namespace init; no workload name, PID
enumeration, process group or protocol completion is used for cleanup.
The PID namespace is an outer lifecycle boundary; the peer's inner MXC/
Bubblewrap route supplies the separately admitted filesystem/syscall boundary.

A pending native custody latch exists before protocol workers or clone.
Cancellation before native start permanently closes admission. A kernel start
already in progress retains all child-side image/pipe copies until remapping
finishes, even if the caller times out. Its creating thread then stops any late
trusted peer before completing cleanup; no workload Launch can follow closed
protocol admission. A dedicated locked Go OS thread performs both start and
native wait, keeping the peer's creating parent thread alive for that lifetime.
No custody mutex is held across the kernel start or native wait, so pending
creation cannot block the cleanup context's deadline.
Every post-constructor failure returns the nonnil `Session`; keep it after
cleanup errors. Its independent `StopAndWait` can retry native cleanup after
the protocol owner's one-use cleanup has failed. A protocol failure remains
a failed session even if native cleanup later succeeds.

Stopping signals the exact init pidfd and observes its owned native wait.
Linux kernel PID namespace teardown kills and waits for namespace members
before init can be reaped. Go's `SysProcAttr.Pdeathsig` is deliberately absent:
its post-clone parent-PID comparison cannot use an ancestor namespace PID.
The trusted peer sets its own parent-death signal before processing commands;
private protocol EOF covers host death before that setup. Creating-thread death
can still precede host process death, so this is additional defense rather than
the authoritative process-lifetime signal. A cleanup timeout retains custody
and reports failure. Hosts lacking atomic pidfds are refused; any already
created direct child remains owned through its exact Go process object and
reaper while cleanup is observed.

Tests cover inert sealed-image copying, ownership after source mutation,
closed-image refusal, cancellation before native creation, unsupported-host
refusal and independent cleanup retries using fake native custody. They do
not execute the private peer or a contained workload. Exact native clone,
descriptor transfer, nested namespace/deadline/parent-death cleanup, and
read-only/read-write boundary tests remain required before activation.
