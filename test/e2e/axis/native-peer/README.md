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
three explicit private read-write directory grants. Separate, unexecuted
`tree-*` selectors include a grandchild in a separate session and fixed
heartbeat files for future bounded cleanup observations. It never selects a host executable,
PATH entry, credential or arbitrary path.

Beyond the four-case result below, the trusted host harness still needs
separate loopback controls, one-use preparation and stale/renamed grant
refusal, timeout/cancel/parent death, and descendant stress with exact retained
pidfd wait. The
heartbeat observation is supplemental; lack of writes alone does not prove
arbitrary descendant containment. Nested PID-namespace behavior and terminal
support require separate tests. Old Landlock/MXC probe pass results do not
qualify this new mount and process-custody posture.

The four fixed selectors passed on October 18 in the source-bound run recorded
below. These files do not enable customer AXIS execution.

The separate [fixed host harness](harness/README.md) supplies contributor-only
artifact admission, held synthetic grants and actual factory/protocol wiring
for the first argv/stdio/exit/boundary slice. Its compiled registry admits only
the independently reviewed c914 build (unchanged Rust peer bytes and revised
static-musl Bubblewrap) and d074 fixed payload receipt. Tests inject unreviewed registries or fake supervisors and
never inherit that native authority. The [outer driver](driver/README.md) and
[fixed CI recipe](live/README.md) separately own the complete wrapper namespace
and exact reviewed artifact inputs. Their source, build and inert artifact
reviews alone establish no native runtime or production launch-gate
qualification. The result below is limited to its exact fixed cases.

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

## First passing native attempt: four fixed offline cases

The separately reviewed recipe at
`2e494e16e75410903577f62fa07cb9a009711f70` ran once in
[Actions run 39161504223](https://github.com/cisco-ai-defense/defenseclaw/actions/runs/39161504223)
and passed. No earlier failure was retried unchanged or converted into a pass.
The host was a disposable Ubuntu runner, kernel `6.17.0-1022-azure`, with the
driver running as UID1001. The combined input receipt was
`6af34ded1837e54d4909f782235613acd56232eafe0c60e2ebc61af5e7fd6ec6`.

| Reviewed input | Source | Build run | Artifact |
| --- | --- | --- | --- |
| Rust peer and static-musl Bubblewrap | `c914cb9a66d3e05a11d5eac4dcf4da7a8c0de139` | `39158759518` | `12148605722` |
| Fixed static Go payload | `d07485c4cc8ecf8ab7db1a0121ac61a6a8b636f3` | `39134453264` | `12138953410` |
| Fixed wrapper | `ae9f9e0c8cea430501f723bb79430955f76df013` | `39160365924` | `12148552547` |
| Whole-wrapper outer driver | `5125d37fed95e3b7967c94edb3d1f9ddd59260c6` | `39160923199` | `12148188690` |

All four cases (`argv`, `stdio`, `exit23`, `boundaries`) recorded `Prepared`,
`Started`, the exact fixed payload marker, exit23, `Destroyed`, and successful
native cleanup. They checked literal arguments (including empty, Unicode and
shell metacharacters), private cwd and exact environment, binary stdin/EOF and
separate stderr, read-only guest root, permitted writes in three explicit private
grants, read-only and outside synthetic canary denial, and `EPERM` for IPv4,
IPv6 and Unix stream/datagram socket creation plus Unix socketpair creation.
The host-positive outside access controls and original held canary identities
and bytes were preserved. Nine retained public fixture files totaled 288 bytes
(13 collected members including directories).

The separate native, worker and whole-wrapper cleanup owners all reported
completion with zero pending custody; output was not truncated. The exact
driver preclone current-mount/no-IDMAP check was observed. The disposable
AppArmor user-namespace setting recorded original1, preparation0 and restored1.
Evidence artifact `12148742045` contains 26,987 ZIP bytes with SHA256
`b6c94089128c45c936217776663dcd8d175d58fdf07cefa7f232496c2334e0c8`.

The `wait` and `tree-*` selectors did not run. Guest FD enumeration and guest
namespace-ID assertions did not run; the parent/worker namespace bootstrap
observations do not substitute for those tests. Timeout, cancellation, parent
death and descendant stress, terminal behavior, actual Claude, hooks, credential
relay and model traffic remain unqualified. The retained result explicitly has
`common_launch_gate_qualified=false` and `production_certification=false`.

## Next lifecycle probe revision: source only

The historical d074 tree selector requests setsid for a grandchild; the pinned
offline filter denies that syscall. The new fixed tree source instead requires
Setsid to return EPERM in every role, then creates its normal parent/child/
grandchild chain. Only the child and grandchild substantiate filter denial:
both require a positive process-group ID different from their own PID before
the syscall. The parent's EPERM is consistency only, since a group leader
can receive that error naturally. The filter, peer and static Bubblewrap are
unchanged. A new
payload artifact, combined receipt and paired wrapper/driver reviews are
required before the separate wait-timeout, wait-cancel and tree-cancel suite
can run. The earlier four-case success and its exact historical artifacts stay
unchanged. No lifecycle, terminal or customer runtime qualification follows
from this source revision.
