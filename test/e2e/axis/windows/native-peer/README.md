<!-- Copyright 2026 Cisco Systems, Inc. and its affiliates -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# TASK-only fixed Windows native-peer canary

Failure diagnostics accept only validated request/binding correlation, closed
protocol operation and reason codes, and the optional closed Windows native
preparation/cleanup stages. They never print raw errors, paths, environment,
arguments or peer stderr. Source13 uses the fixed fixture basename canary-08;
the retained fixture prevents an unchanged rerun.

This source draft exercises the existing bridgeprocess SealImageIn/Start and
the shared Prepare/Launch/Input/InputEOF/Wait/Exited/Destroy protocol. It adds
no production provider, common production LaunchGate qualification, hook/model
traffic, credential handling, terminal or arbitrary command runner. The source
registry is closed until independently reviewed exact peer artifact and local
Go payload build receipts supply fixed source pins. This revision has not been
built or executed. The prior fixed outer attempt retained the `canary-01` fixture
and stopped at host network positive controls before Prepare or peer launch.
A separate fixed diagnostic observed WinSock 10106 with an empty host environment
and TCP/UDP success with only kernel-derived SystemRoot. The revised outer recipe
therefore supplies exactly that one host variable. Go Start still gives the Rust
peer an explicit empty environment; the fixed workload plan remains unchanged.
The next outer attempt passed both host network controls, then returned at Start
without observing Prepared; its first Session.Close failed and retained custody,
while the explicit retry and outer Job cleanup completed. Its fixture is retained.
This revision adds failure-only stderr diagnostics at Start, initial Session.Close
and a failed StopAndWait retry: closed stage/error classes plus numeric Win32 code
only. No Error() text, wrapped path, peer text or environment is formatted. Any
such stderr continues to refuse outer success; the initial cleanup failure is
still preserved. No launch/policy behavior changes besides the fresh fixed label.

The only harness argument is `--run-fixed`. A separately reviewed root recipe
must stage exact admitted files beneath one fresh protected private directory
named `windows-native-peer-canary-05`: the fixed harness filename,
`REVIEWED-ARTIFACTS.json`, `peer.exe` and `payload.exe`. Their complete hashes
and sizes are source constants, not runtime inputs. The recipe must own the
harness image/ancestry and an atomic kill-on-close Job before its Resume, with
a mandatory independent 40-second process cutoff. Its internal 30-second
elapsed deadline counts setup time but is polled, and the harness's 20-second
context does not make blocking filesystem calls cancellable.

All fixed ancestors are nonfollowing, local mounted NTFS and held with real
directory read/list access and no delete sharing. Fresh private fixture and
child directories are created with owner+SYSTEM protected descriptors using
the existing creation-aware safefile API; an existing directory is refused and
its ACL is not repaired. Source images remain held; SealImageIn owns private
immutable copies, image views and their exact subtree cleanup. Parent leases
remain held through native cleanup. No original image, host profile, policy,
existing ACL or namespace is modified.

CWD is the fresh private `fixture/work` directory. It is granted readonly;
only its `workspace`, `home` and `tmp` subdirectories are granted readwrite.
The readonly sentinel has an ordinary writable host handle and no readonly
attribute, so a share-mode or DOS attribute restriction cannot stand in for
PSEC enforcement. An ungranted public sentinel is the sibling `outside.txt`.
Host positive writes precede launch and unchanged bytes/full identities are
checked afterward. Fixture files are retained; only admitted Image.Close owned
copies are removed. No recursive or historical-fixture deletion exists.

The std-only Go canary accepts one fixed literal argv vector and a bounded
binary stdin frame followed by actual EOF. It compares exact CWD and the four
stable HOME/USERPROFILE/APPDATA/SystemRoot values plus the fixed canary variable.
It admits exactly eight environment names. The three OS-redirected values have
only bounded private-prefix/presence/relationship observations; these are not
native-profile attestation or exact requested/realized equality. Their bytes
are never logged, opened or used as authority. No native profile is created.
The earlier Packages/AC/Temp refusal was the boundary probe's explicit
post-spawn native-environment admission gate, not CreateProcess itself: its argv
control had already run. Claude version03 also skipped that boundary-only gate
and passed with directories only through Local. This first canary therefore
does not provision or claim usability of the redirected native environment
subtree. Workloads that actually use those directories need their own reviewed
provisioning contract; the string observations cannot supply it.

The canary verifies readonly read/write denial, explicit workspace write,
ungranted outside read/write PermissionDenied, fixed binary input/EOF, exact
stdout/stderr markers and exit23. The host keeps live loopback TCP/UDP endpoints,
first proves their operation outside PSEC, then requires TCP PermissionDenied
and finite no-arrival observations for both endpoints. UDP send success is not
itself a denial proof. These finite IPv4 loopback observations do not qualify
all network transports or destinations.

Start receives nil Bubblewrap and held native image/object capabilities. The
SDK floor requires actual role access and exact protected root identity; the
Go host retains the complete ancestor/image lease contract. A Started reply
is labeled as a peer acknowledgment separately from the canary's marker.
Only a terminal native exit and exact streams permit Destroy. Session cleanup
is attempted with a fresh two-second context, then exact custody can retry
once with another two-second context; the first failure remains a case failure.
If native cleanup remains incomplete, the reachable owner retains every lease
until the independently owned outer Job ends the harness and descendants.

Only closed booleans/stage labels enter JSON. Raw protocol output, native
errors, paths, environment, SIDs and handles do not. The pure tests use synthetic
protocol frames and input parsers only. Required next gates: ROOT/Max full source
review, small local inert builds, exact Windows peer artifact review, fixed
source-bound outer recipe review, then ROOT alone authorizes one actual run.

Source07 adds a private Start substage wrapper after Session allocation and after
its existing cleanup. The wrapper preserves Unwrap/errors.Is and formats only a
closed source stage; it never formats the cause. The canary independently admits
that interface's fixed vocabulary before emitting `native_start_stage` to stderr.
No admission, rights, launch, protocol or cleanup operation is changed. Prior
attempt04 reported only process_admission with successful initial Session.Close
and native/outer cleanup; that failed fixture remains retained. Internal stage
evidence is still pending a separately reviewed changed-source attempt.

Source08 changes only directory capability duplication to an NT empty-name
self reopen under the original held handle. A current-handle GrantedAccess
query must cover the mapped read/write role before any directory or regular
file reopen; a reduced copy must match the SDK role floor plus optional traverse.
The read mask is 0x120089 and write adds 0x116; no traverse right is added. Full
FileID/type/local-NTFS checks remain required and allocated refusals remain owned.
The prior changed attempt identified asset_cwd; twelve read-only ReOpenFile
controls refused, while the exact held self reopen succeeded without a child.
This is source evidence, not a new peer/PSEC/canary execution or policy grant.

Source09 additionally fixes only the existing NT-open helper's partial-handle
ownership: a valid allocated handle is returned before refusal classification;
zero/INVALID are never wrapped. Its constructor callers already assign into the
same cleanup state before checking errors. The local delete-open cleanup caller
now closes any nonnil refusal through that state's one-attempt sticky-close
method. Access, names, dispositions, image admission and numeric status wording
are unchanged. The native host-only asset test includes real allocated-handle
control/native-error finalization and close checks; execution remains ROOT-owned.

The next fixed diagnostic retains both original native termination failures as
private causes and emits only attempted/failed flags and numeric Win32 codes
for the Job and root roles at the native_signal cleanup stage. A failed call
with code zero is unclassified, not success. Cleanup decisions remain unchanged.
