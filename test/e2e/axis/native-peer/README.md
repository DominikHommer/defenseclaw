<!-- Copyright 2026 Cisco Systems, Inc. and its affiliates -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Private native peer contributor live gate

This directory is contributor test source, with no product caller. Its fixed
Go payload must be built using the pinned Go toolchain with `CGO_ENABLED=0`,
reviewed as a static ELF artifact, and launched only after the native peer,
static-musl Bubblewrap closure and held-object mount seam pass independent
source and artifact admission. The separate fixed contributor harness does not
enable customer AXIS execution.

The payload accepts only fixed canary selectors and, for `boundaries`, a strict
`/tmp/dc-axis-native-peer-<32 lowercase hex digits>/outside` fixture path. The
trusted harness must exclusively create and pin that private tree and both
outside canary files before launch; it never accepts a customer path. The
payload requires the private guest `/work` cwd, exact fixed seal, three supplied
environment entries and Bubblewrap's exact derived `PWD=/work` before any
mutation. Before its boundary selector writes, it also checks bounded seals
in both `/home` and `/tmp`. The trusted harness must verify the held identity
of each source. It tests literal arguments, binary input plus EOF, separate stderr,
exit 23, read-only/read-write/outside boundaries, and representative socket
and socketpair denial. The syscall filter's complete policy needs independent
source/artifact admission beyond these sampled live calls. Its negative access
probes only open and close nonblocking, nofollow handles: they never write,
truncate or create an ungranted target if containment is broken. Fixed seal
and read-only canary reads are bounded. Root writability and private device
writes are distinct from access to an outside host file. The boundary selector
requires the root mount's `ST_RDONLY` flag and writes positive canaries to all
three explicit private read-write directory grants. Its process tree includes
a grandchild in a separate session and fixed heartbeat
files for bounded cleanup observations. It never selects a host executable,
PATH entry, credential or arbitrary path.

The future trusted host harness must independently demonstrate host-positive
filesystem and loopback controls, one-use preparation, stale/renamed grant
refusal, timeout/cancel/EOF, parent death, and exact retained pidfd wait. The
heartbeat observation is supplemental; lack of writes alone does not prove
arbitrary descendant containment. Nested PID-namespace behavior and terminal
support require separate tests. Old Landlock/MXC probe pass results do not
qualify this new mount and process-custody posture.

No payload has been executed, and these files do not enable AXIS.

The separate [fixed host harness](harness/README.md) supplies contributor-only
artifact admission, held synthetic grants and actual factory/protocol wiring
for the first argv/stdio/exit/boundary slice. Its compiled registry admits only
the independently reviewed e054 peer/static-musl Bubblewrap and d074 fixed
payload receipt. Tests inject unreviewed registries or fake supervisors and
never inherit that native authority. The [outer driver](driver/README.md) and
[fixed CI recipe](live/README.md) separately own the complete wrapper namespace
and exact reviewed artifact inputs. Their source, build and inert artifact
reviews establish no native runtime or production launch-gate qualification.

## First native attempt: startup refusal, no payload evidence

On October 18, the first separately reviewed fixed recipe at source
`ba2eb7124c4bba1403b96b36e8aceb83e099beb5` ran in
[Actions run 39143689390](https://github.com/cisco-ai-defense/defenseclaw/actions/runs/39143689390).
It failed; the four payload cases did not pass. There was no automatic retry.

| Stage | Actual retained observation |
| --- | --- |
| Host | Disposable Ubuntu runner, kernel `6.17.0-1022-azure`; unprivileged driver. |
| Driver | Atomic outer custody reached bootstrap READY/GRANT and executed the exact reviewed wrapper. |
| Wrapper | Exited 1 after recording its inner worker start attempt, before worker READY/GRANT or fixture/native peer/payload evidence. |
| Cause | Start, post-start custody, or early worker admission remains unresolved; the generic failure record cannot distinguish them. Nested namespace support is a hypothesis. |
| Cleanup | Driver whole-namespace and wrapper outer cleanup both reported success, with zero pending owners; stderr was empty and output was not truncated. |
| Host restoration | The specific disposable-runner AppArmor knob recorded original `1`, changed `1`, current `1`. |

Exact evidence artifact ID `12141999966` contains 21,877 ZIP bytes with SHA256
`f984380f4548345580932fe70f7487cb9f0810573fefd8f8886d157725ba34cc`.
The admitted driver image was
`df678a3fd138907554e5a551cee0c4152eecf1357c264b7d1502153366cb9553`;
the wrapper was
`2017f419020e862b7d5bc77d01b76c522655c07eab2bbb7918869c51e6cc2e03`.
Both independent reviews checked the evidence without executing an image.
Next work is bounded stage/errno diagnostics and a new reviewed build before a
separate attempt. This failure qualifies neither the payload boundary nor the
complete provider, Claude, terminal, hooks, model traffic or credentials.

## Diagnostic attempt: pre-exec refusal and a different proc PID view

The separately reviewed diagnostic recipe at
`8b46c7055b4bc6d61940f3e646d64e7f884bb0b7` ran once in
[Actions run 39145905366](https://github.com/cisco-ai-defense/defenseclaw/actions/runs/39145905366).
It used the newly reviewed d056 wrapper and c8d4 driver. No earlier artifact
was retried, and this attempt also failed before the fixed payload started.

The retained wrapper record distinguishes `worker_start_stage=exec_start_refused`
and `worker_start_errno=eacces`. There was no started child wait, exit status was
`-1`, and both worker streams were empty. The bounded `/proc/self` observation
was available and did not match `getpid`. This establishes a different procfs
PID view inside the wrapper's namespace. It does not prove which syscall failed
or that the PID-view mismatch caused the refusal; Go's parent-side ID-map writes
are a source-supported hypothesis.

Both cleanup owners reported success with zero pending owners; there was no
output truncation. The disposable runner setting again recorded original `1`
and current `1` after restoration. No fixture was copied because none was created.
Evidence artifact `12143636345` has 22,001 ZIP bytes and SHA256
`4ddaab4d1ee5856a1b1e54d95bf17bd74fb20711730d77bff7bdc01f7f192626`.
The next change must supply a reviewed coherent namespace/procfs bootstrap and
preserve unprivileged host operation, native custody and policy enforcement.
