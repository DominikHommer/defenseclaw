# Fixed Linux outer driver

This contributor driver owns one closed baseline or lifecycle suite from the
reviewed native peer wrapper in a separate user/mount/PID/network/IPC/UTS namespace. It does not activate
the AXIS customer provider or qualify the common launch gate.

The fixed input wrapper was built at `52e4a071109d1522d3cadf53085c9537467ef9c7`
in Actions run `39168692019`, artifact `12151861098`. Two independent inert
reviews checked its source, dependency, archive, provenance and static image.
The image SHA-256 is
`70159109952811847fa4e16cc02fca1046d696ebcbb0ff3aa820e1562899dccb`
(3,473,534 bytes); archive SHA-256 is
`86d78d2aee702fbcbfb356a94b8bd654dc07b842f8c54b5531c744f434f59f5e`;
provenance SHA-256 is
`7d4dad5aa155b47e932c61e88a72ff1f5d42bb00dca80c7fb2955d7add767d31`.
Its fixed combined peer/payload receipt is
`8b50970b9636ff84ff6ed0aa3ae7d68d2bc063809e5d8af9073d8e4c804a3e9b`.
These are compiled source pins. There is no caller-supplied image, digest,
command, environment, backend or policy option.

The outer driver itself still requires independent source/build/image review
and explicit authorization for a bounded run. Its first lifecycle attempt is
recorded [separately](../README.md#lifecycle-probe-revision-and-first-failed-attempt). The build workflow compiles two static copies, runs only
fake/inert unit tests, and retains exact Git sources and dependency evidence.

The driver reads `REVIEWED-ARTIFACTS.json` and fixed member
`images/reviewed-wrapper` from a held, mode-0700, caller-owned artifact directory.
Every path component is opened without following links. Bounded bytes must
match the compiled digest before being copied into a sealed executable memfd.
The running driver image is likewise copied and sealed for its bootstrap.
The original artifact file path is never used to execute the wrapper.

An atomic pidfd owns a new outer PID namespace. A retained creating OS thread
waits for its init; the init installs `PR_SET_PDEATHSIG(SIGKILL)` before file
inspection. READY precedes one exact GRANT; EOF before GRANT refuses execution
and covers parent death before prctl. After GRANT the bootstrap execs the held
sealed wrapper with an empty environment. Only the fixed held fixture parent
and root survive that trusted-wrapper exec as FD8/FD9; other explicit non-stdio
descriptors close. No fixture parent/outside handle reaches a guest payload. The creator-thread death caveat is availability: an early
unexpected thread death terminates the owned init. No raw PID/group/name lookup
authorizes cleanup. An inability to obtain atomic custody never grants exec.

The outer deadline is 120 seconds. Cleanup gets a separate ten-second wait and
one ten-second retry. A failed first cleanup remains a failed result even when
retry succeeds; a pending exact owner stays reachable through reporting.
Stdout/stderr each retain at most 64 KiB, including failure paths. Success
requires the wrapper's exact selected suite, ordered cases, markers, canary
controls, exit values and both levels of cleanup. The outer cleanup result describes
whole-wrapper namespace custody; it does not replace SDK cleanup assertions.

After independent driver artifact admission, the fixed lifecycle invocation is:

```text
fixed-outer-driver --run-fixed --suite lifecycle --receipt /private/admitted/REVIEWED-ARTIFACTS.json --evidence /private/fresh-evidence
```

The paths carry metadata, not executable/policy authority. The evidence path
must be fresh; failed fixtures/results remain available. A future disposable
GitHub-runner recipe may save, change and restore the specific AppArmor userns
knob only when its explicit reviewed host-preparation contract permits it.
This driver never changes host sysctls, services, ACLs, credentials or firewall.

Unit tests always supply an unreviewed registry or fake runner. Linux-specific
tests parse inert ELF headers, use memory-only READY/GRANT streams and fake
custody; they never clone, call prctl, seal/execute an image or create a sandbox.

## Private proc bootstrap source revision

This source revision includes a fresh mount namespace and a fixed sealed FD3
parent-identity proof to each owned child. Before READY/control/backend work,
the child proves kernel ownership and single nonzero UID/GID mappings, makes
mount propagation private, mounts matching procfs and clears startup capabilities.
Only SYS_ADMIN inside the new user namespace crosses the trusted initialization
interval; all Go threads use the CGO0 all-thread barrier, and the Rust peer proves
it is single threaded with signals blocked until cap-zero. No host capability,
UID0 mapping, grant, alternate backend or customer activation is added.

This changes the private FD handoff. Existing e054 peer and d056 wrapper/c8d4
driver artifacts remain historical evidence and cannot qualify this source.
Fresh source-bound artifacts, registry pins and one separately reviewed runtime
attempt are required. The two earlier native failures remain failures.

## Host fixture capability revision

Before the first clone, the trusted driver opens held `/tmp` without links and
requires its original host UID0 and sticky directory mode. It creates one fresh
random `dc-axis-native-peer-<32hex>` directory with mode0700, verifies current-user
ownership, and retains both directory handles. No unmapped/overflow UID is proof
of host ownership. These two capabilities cross the trusted bootstrap/wrapper,
then the wrapper gives worker-owned duplicates at fixed FD7/FD8. Label/inode
correlation is checked without selecting a source through the display path.
Fixtures, including partial creation, are retained on every outcome.

The revised host preflight also requires `STATX_MNT_ID_UNIQUE` and
current-namespace `statmount(STATMOUNT_MNT_BASIC)` before the first clone. The
held parent and fresh empty root must belong to that same reachable mount,
with required status fields present and `MOUNT_ATTR_IDMAP` unset. Unsupported
or ambiguous queries refuse; there is no less strict fallback. This adds a
Linux 6.8 capability floor to this fixed contributor recipe. Unit tests use
synthetic response bytes only and never perform a mount or statmount call.
The kernel's clone-only private namespace chain then preserves that source
mapping; only reserved `/proc` is replaced before native source admission.
This is not provenance admission for arbitrary foreign production inputs.
Fresh source/artifact reviews and a new driver pin remain required before use.

Historically, the c914 static Bubblewrap, d074 payload and combined receipt
`6af34ded1837e54d4909f782235613acd56232eafe0c60e2ebc61af5e7fd6ec6` passed
one four-case attempt with the ae9 wrapper and 5125 driver. The new lifecycle
pairing replaces only that payload with 3f295; Rust peer and c914 Bubblewrap
bytes stay unchanged. Historical runs remain evidence for their exact earlier
source only. A fresh driver artifact review and separately reviewed native
attempt are required.

## Lifecycle suite handoff

The closed `--suite lifecycle` selector is passed unchanged through the existing
owned bootstrap into the reviewed wrapper; omitted `--suite` remains baseline.
The driver requires the returned suite to match and admits exactly three
ordered results: wait-timeout, wait-cancel, tree-cancel. Every result must bind
its marker, terminal flags, separate Destroyed and native cleanup; the tree
result also requires verified ready files, live heartbeat progress and bounded
stability before Destroy. The bounded public count snapshots must independently
show progress in every fixed role and six stable post-terminal samples.
Baseline and lifecycle evidence cannot replace one another. No new controller, arbitrary command, file selector or caller hash
is introduced. This source pins the reviewed 52e4 wrapper, including its nine
inert lifecycle unit-test passes. The reviewed b38 driver recorded twenty inert
passes before the first lifecycle attempt. That attempt failed overall: the
two wait cases passed, but the tree precondition refused before cancellation
or heartbeat observations. No descendant-cleanup result follows from it. The
new fixed payload requires EPERM from Setsid in every role and uses normal
descendants; it does not change the offline filter or admit session creation.
Only the positive-group, nonleader child/grandchild checks substantiate filter
denial; the parent check is consistency only.
The earlier four-case result remains evidence for its exact original pairing.
