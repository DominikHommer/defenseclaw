# Native AXIS backend ownership slice

This package connects `sandboxruntime.Backend` and `PreparedProcess` to the
existing concrete `bridgeprocess.Session`. It starts nothing at construction.
Its public installation catalog is unavailable, with no advertised capabilities
or qualified harnesses. The gateway does not activate this backend.

The manager supplies a bounded session-lifetime context and binds one complete
session identity to exclusively owned image/directory handles. Artifact admission
and sanitized host staging belong to that trusted producer. `Spec.HostWorkspace`
is metadata; it is never reopened or used to select a host object. No caller hash,
PID, executable name, environment variable or serialized receipt grants authority.
The private owner permits at most 64 active records and 4,096 lifetime IDs.
Deleting a record never permits its immutable session ID to be reused.

The concrete native path prepares the trusted peer, checks its correlated
`Prepared` frame, freezes the specification, and exposes one `Launch` operation.
The existing manager must reserve the identity and dispatch that handle through
its common `LaunchGate`. Preparation starts no agent or credential grant. A
request cancellation closes partial preparation with a fresh bounded cleanup;
successful preparation remains owned by the manager lifetime. Failed native
cleanup retains the exact session and assets for retry. Asset release requires
joined protocol workers and independent native wait success under a still-live
cleanup context, not a `Destroyed` frame. A sticky protocol failure is reported
even when that verified cleanup releases assets; the phase is `failed_closed`.
An asset-close failure stays sticky and cannot become successful on retry.

The policy compiler refuses all incomplete components and emits no partial
`PolicyReceipt`. Sparse filesystem/native offline canaries do not implement
common policy, administrative authority, workspace provenance, managed hooks,
MCP or a credential broker. Runtime/harness qualification and each complete
component translation must be added explicitly before the catalog can open.
The initial native mechanism is Linux MXC Bubblewrap. Other platforms,
interactive execution and repeated execution remain unavailable here.
The generic `Backend.Exec` refuses rather than starting an unqualified process
or creating an uncancellable worker around a caller's arbitrary stream.

`OpenAttachment` implements the bounded headless transport for one already
launched concrete session. The default unavailable catalog refuses admission.
The existing manager must verify current policy and the complete owned identity
before calling it; a client name or session ID is insufficient. One immutable
session admits one consumer for its lifetime. Attachment input is literal binary
stdin, EOF or cancellation, bounded to 64MiB and 8,192 successful input frames;
resize remains refused. It cannot start a command,
change environment or extend the original execution deadline. The HTTP admission
context detaches on success; the manager lifetime and requested shorter timeout
still cancel the owned native session. Output and exit are correlated to the
original Launch request and complete bridge binding, with aggregate output bounds.

Send and Receive use the existing cancellable protocol owner directly. They do
not hold the entry lifecycle token during stream I/O, so Stop/Close can terminate
a blocked receiver. Disconnect/Close uses the same retained native custody and
independent wait as every other teardown. Failed cleanup retains assets; retry
does not erase the attachment's original failure. A peer exit event alone never
releases assets. This source implementation does not qualify production streaming
or activate a gateway manager route.

Tests use private function injection over the existing concrete session and
inert held files. They never execute images, clone namespaces, mount, change
capabilities or call a native worker entry point. Fixed test qualification is
never registered as production evidence.
