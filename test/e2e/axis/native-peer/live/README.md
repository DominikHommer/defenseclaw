# Fixed Linux native peer CI canary

This is one contributor-only four-case attempt using the separately reviewed
aa215 peer/unchanged static-musl Bubblewrap, d074 fixed payload, 9ea diagnostic
wrapper, and 08c outer driver. The cases check literal argv, binary stdin/EOF and stderr, exit
23, and fixed offline filesystem/network/FD/namespace boundaries. This is not
customer activation, PTY/Claude/model/hook qualification, or completion of the
AXIS integration.

The workflow is manual, same-repository and canonical-branch only. It has no
caller-selected artifact, command, image digest, policy, environment or retry.
The exact Actions source/run/attempt/workflow/branch/event and archive digest
must match constants in `prepare.py`. Each ZIP/provenance manifest is checked
in full with bounded readers, and every selected image/proof must match its
fixed hash and size. The combined receipt bytes are pinned to `9e7c6f82...`.
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
The trust assumptions documented in
[`artifact-review.md`](../../../../../internal/axis/native/artifact-review.md)
still apply.

Only the trusted host metadata process receives the read-only Actions token.
The driver runs with an empty environment. Its reviewed code copies and seals
the exact wrapper, establishes atomic pidfd ownership of a new PID namespace,
and requires READY then one GRANT before exec. The wrapper separately owns its
worker and native sessions. The outer driver has a 120-second deadline plus
bounded cleanup/retry, and a trusted 160-second timeout encloses the driver.
The workflow requires all four fixed case assertions and cleanup results for
success. It never restarts a failed experiment automatically.

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
and total depth/member/byte bounds. It never deletes the source fixture. A
missing or unsafe copy is recorded as incomplete evidence.

Source tests use inert archives, fake metadata, missing admission, and private
temporary data only. No test executes a peer, driver, Bubblewrap or payload.
The Linux descriptor-copy test is skipped on Windows and runs in the CI source
test step. A local preparation rehearsal may read the four already-downloaded
reviewed archives as data without executing them.

Before dispatch, the root and independent reviewer must review this exact
workflow/helper source and the driver artifact. After one attempt, preserve
the actual result before diagnosing or changing source/policy. A successful
canary still leaves terminal, arbitrary prepared workloads, credential relay,
agent hooks and actual Claude/model traffic as separate qualification gates.
