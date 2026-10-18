# Fixed Linux native peer CI canary

The pairing below completed one contributor-only four-case attempt using the
separately reviewed
c914 peer/revised static-musl Bubblewrap, d074 fixed payload, ae9 diagnostic
wrapper, and 5125 outer driver. The cases check literal argv, binary stdin/EOF and stderr, exit
23, and fixed offline filesystem and socket-creation boundaries. This is not
customer activation, PTY/Claude/model/hook qualification, or completion of the
AXIS integration.

The workflow is manual, same-repository and canonical-branch only. It has no
caller-selected artifact, command, image digest, policy, environment or retry.
The exact Actions source/run/attempt/workflow/branch/event and archive digest
must match constants in `prepare.py`. Each ZIP/provenance manifest is checked
in full with bounded readers, and every selected image/proof must match its
fixed hash and size. The combined receipt bytes are pinned to `6af34ded...`.
The four archives already received two independent inert reviews of source,
build, dependency and image evidence. CI preparation rechecks their exact
byte identity; it does not repeat upstream source/toolchain reconstruction.
The new peer, wrapper and driver include the reviewed FD3 namespace proof,
private mount propagation, matching procfs and capability drop before control
or workload launch. One [native attempt](https://github.com/cisco-ai-defense/defenseclaw/actions/runs/39152319549)
at `dabf4fa5` completed that bootstrap and started the owned worker with a matching
procfs PID view. It then refused before artifact admission or payload cases.
Both namespace cleanup owners completed with zero pending custody, and the
runner setting was restored. Source review found that this workflow supplied
an evidence-directory basename `wrapper`, while the harness requires
`native-peer-fixed-*` before creating evidence. The recipe now supplies
`native-peer-fixed-wrapper`; the reviewed images and policy are unchanged.
This explains a deterministic recipe refusal, without qualifying the unexecuted
payload cases or attributing every observed failure to that check.
The [corrected recipe attempt](https://github.com/cisco-ai-defense/defenseclaw/actions/runs/39152617635)
at `ff1c9e55` admitted the fixed artifacts and created evidence, then stopped
before fixture or peer creation. Source review found a host-UID0 check on `/tmp`
inside a namespace that maps only the nonzero runner UID; its actual Fstat value
was not recorded. The revised 90cd driver verifies the held root-owned sticky
parent and creates its private fresh fixture before cloning, then passes exact
held parent/root capabilities through the 6eec wrapper to the worker. It retains
the original root-ownership requirement without accepting an overflow UID as
proof. Artifact and policy admission otherwise retain their scope;
the peer, Bubblewrap, payload and combined receipt are unchanged. This new pair
has passed source/build/artifact review and inert tests, but has not yet passed
the native four-case attempt.
One [held-fixture attempt](https://github.com/cisco-ai-defense/defenseclaw/actions/runs/39155130062)
at `b656cf66` passed fixture admission and reached the actual peer's `Prepared`
and `Started` replies. The first argv case then reported exit code 1, before any fixed
payload marker or `Destroyed` reply; the remaining cases did not run. All three
native/worker/driver cleanup owners completed with zero pending custody. The
runner setting was restored, and ten synthetic fixture members totaling 192 bytes
were collected. Evidence artifact `12146776297` has ZIP SHA256
`bcb2c471fc7ca9a6759437b5c156f57f010db53825f89fa2a64a4c0a760300d1`.
The recorded zero stdout/stderr counts are inconclusive: the harness returns on
an unexpected exit before assigning captured buffer lengths. No payload, runner
or Bubblewrap cause is established, and no unchanged retry was performed.
The new 9ea wrapper retains validated bounded stream lengths even on failed
exits, and reports only a closed first-line stderr reason/OS-text category.
The 08c driver pins that exact reviewed wrapper. This is a diagnostic source
change; policy, fixture capabilities, native peer and payload remain unchanged.
One [diagnostic attempt](https://github.com/cisco-ai-defense/defenseclaw/actions/runs/39157247895)
at `05d7aa0c` again reached `Prepared` and `Started`, then argv exited 1 before
the payload marker. This time the validated counts were stdout 0 and stderr 68,
with closed category `bwrap_owned_source` and OS-text category `none`. That
category covers the original source's cached reopen, held-object identity,
mount-ID and mount-topology admission; it does not identify the failed condition.
No `Destroyed` reply or later case passed. All three cleanup owners completed
with zero pending custody and the runner setting was restored. Ten retained
synthetic fixture members totaled 192 bytes. Evidence artifact `12147416204`
has ZIP SHA256
`131301b4623c7462ddf6cae32a6a803a0c414e3b464276d784d0d90fce785ccc`.
No unchanged retry occurred. Source review is investigating inherited mount
descriptors across namespace clones; this result alone does not establish that
as the cause or qualify any boundary behavior.
The new pairing uses the reviewed c914 static Bubblewrap source-view revision,
ae9 wrapper and 5125 driver. The incoming held object and restrictive flags
remain authority; a cached identity-checked reopen supplies the current
namespace mount ID, and both current namespace inventories still refuse nested
mounts. This is scoped to the trusted clone-only creator chain. Before the
first clone, the driver requires current-namespace unique mount identity and
`statmount` basic attributes for its held parent and fresh root, refusing
ID-mapped or unsupported sources. The driver build passed 18 selected inert
tests. The Rust peer and d074 payload bytes are unchanged; static Bubblewrap,
its closure, wrapper/driver pins and combined receipt are revised. This pairing
passed the fixed attempt recorded below; no earlier failure is converted into
a pass.

## Passing fixed attempt

[Actions run 39161504223](https://github.com/cisco-ai-defense/defenseclaw/actions/runs/39161504223)
at `2e494e16e75410903577f62fa07cb9a009711f70` passed once with the exact
c914/ae9/5125/d074 pairing. All `argv`, `stdio`, `exit23` and `boundaries` records
agree across the driver, wrapper result and owned worker stdout: Prepared,
Started, fixed marker, Exited23, Destroyed and native cleanup. The private cwd
and exact environment, binary input plus EOF and separate stderr, read-only
guest root, explicit private writes, synthetic outside/read-only denials and
IPv4/IPv6/Unix socket/socketpair `EPERM` checks passed. Host-positive synthetic
access controls and original canary identities/bytes were preserved.

All three cleanup owners completed with zero pending custody and no output
truncation. The driver reported its current-mount/no-IDMAP preclone check.
The disposable runner's setting recorded original1, preparation0 and restored1.
Collection retained 13 synthetic members (nine public files, 288 bytes).
Evidence artifact `12148742045` has 26,987 ZIP bytes and SHA256
`b6c94089128c45c936217776663dcd8d175d58fdf07cefa7f232496c2334e0c8`.
The exact input source/build/artifact table is in the
[parent result](../README.md#first-passing-native-attempt-four-fixed-offline-cases).

This did not execute `wait`, `tree-*`, guest FD enumeration or guest namespace-ID
assertions. Parent/worker bootstrap observations are narrower. Timeout, cancel,
parent-death/descendant stress, terminal, Claude, hooks, credentials and model
traffic remain separate gates. Both production and common launch-gate
qualification fields remain false. Earlier failures remain unchanged above.

## Lifecycle pairing: first attempt failed

The checked-in recipe now selects `--suite lifecycle`, retaining the wrapper's
baseline default and the historical four-case evidence above. The new pairing
uses the same reviewed c914 peer/Bubblewrap, reviewed 3f295 payload, and 52e4
wrapper under combined receipt
`8b50970b9636ff84ff6ed0aa3ae7d68d2bc063809e5d8af9073d8e4c804a3e9b`.
The paired driver is built at `b38a49dda8da9aca450994b709b44e9cea7d5c19`,
run `39169432727`, artifact `12151303749`, image
`a93df15dba750e5e2363ec4276b7c0e75f593101fa58ee9ef0e5b901bb2b3f39`
(3,211,390 bytes). Wrapper run `39168692019`, artifact `12151861098`, binds
image `70159109952811847fa4e16cc02fca1046d696ebcbb0ff3aa820e1562899dccb`
(3,473,534 bytes). Payload run `39167683927`, artifact `12151291706`, binds
image `ff14f6e2bbce3c35566326ba98cec890b500b6032df3c3ee2b408c9a494128f2`
(1,929,342 bytes). The wrapper recorded nine approved inert test passes and the
driver recorded twenty. The sole actual run `39170295582` at source
`c9e657b9c87ed3464cc1b3a7f339ea56ec805395` failed overall: wait-timeout and
wait-cancel passed their ready/terminal/Destroyed/native-cleanup assertions;
tree-cancel refused with `payload_tree_setsid_precondition` after only its
parent marker. Cancel, heartbeat progress/stability and descendant cleanup were
not observed for that tree. No terminal tree exit code was observed.

Evidence artifact `12152376279` has ZIP SHA256
`b2fa7afcf79a02bb6a5574deba17210616335a5fe7bc68cd571f21c46929ba6c`
(27,726 bytes). All three cleanup owners completed with zero pending custody;
eight public fixture files totaled 224 bytes (12 members including directories),
and the runner setting was restored to 1. There was no automatic retry. See the
[parent record](../README.md#lifecycle-probe-revision-and-first-failed-attempt)
for the source-level syscall mismatch and remaining gates.

The three cases are `wait-timeout`, `wait-cancel`, and `tree-cancel`. Timeout
requires the live ready marker before the five-second deadline; cancel requires
readiness and an explicit Cancel before the fifteen-second deadline. The tree
case additionally requires all three exact markers, held ready files and live
heartbeat progress before Cancel. It then samples six stable heartbeat states
after native Exited and before Destroy/Destroyed or host outer cleanup. The
finite observation corroborates only these three synthetic writers; independent
native owner cleanup and zero pending custody remain mandatory. The unchanged
offline filter must deny Setsid; only positive-group nonleader descendants
substantiate that denial, and the parent result is consistency only.

The trust assumptions documented in
[`artifact-review.md`](../../../../../internal/axis/native/artifact-review.md)
still apply.

Only the trusted host metadata process receives the read-only Actions token.
The driver runs with an empty environment. Its reviewed code copies and seals
the exact wrapper, establishes atomic pidfd ownership of a new PID namespace,
and requires READY then one GRANT before exec. The wrapper separately owns its
worker and native sessions. The outer driver has a 120-second deadline plus
bounded cleanup/retry, and a trusted 160-second timeout encloses the driver.
The workflow requires the exact three lifecycle case assertions and cleanup
results for success. It never restarts a failed experiment automatically.

The disposable Ubuntu GitHub VM is the only permitted host for this recipe.
If its AppArmor unprivileged-userns knob is 1, the explicit preparation step
saves it, changes that one knob to 0, and restores/verifies it on ordinary exit.
An abrupt runner/VM termination cannot promise trap execution; that VM is
discarded. Production readiness must report this host requirement, and must
not change the user's host. No installer, service, firewall, DACL, capability
grant or user-PC sysctl change is part of this workflow.

The evidence artifact retains exact input API/provenance records, preparation
hashes, driver raw result/stderr, wrapper result, host-floor/restore records,
and a bounded copy of the exact owned synthetic fixture when native custody
has completed. Copying requires the wrapper receipt, fixed random path shape,
current UID ownership, no-follow descriptor opens, regular single-link files,
and total depth/member/byte bounds. The only dot-containing names admitted are
the six exact public `tree-{parent,child,grandchild}.{ready,heartbeat}` files,
only as regular files immediately under `work`. It never deletes the source fixture. A
missing or unsafe copy is recorded as incomplete evidence.

Source tests use inert archives, fake metadata, missing admission, and private
temporary data only. No test executes a peer, driver, Bubblewrap or payload.
The two Linux descriptor-copy tests are skipped on Windows and run in the CI
source test step. A local preparation rehearsal may read the four already-downloaded
reviewed archives as data without executing them.

Before dispatch, the root and independent reviewer must review this exact
workflow/helper source and the driver artifact. After one attempt, preserve
the actual result before diagnosing or changing source/policy. A successful
canary still leaves terminal, arbitrary prepared workloads, credential relay,
agent hooks and actual Claude/model traffic as separate qualification gates.
