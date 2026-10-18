# Fixed Linux native peer CI canary

This is one contributor-only four-case attempt using the separately reviewed
aa215 peer/unchanged static-musl Bubblewrap, d074 fixed payload, efc2 diagnostic wrapper, and 7429
outer driver. The cases check literal argv, binary stdin/EOF and stderr, exit
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
or workload launch. This source change has not yet been exercised natively.
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
