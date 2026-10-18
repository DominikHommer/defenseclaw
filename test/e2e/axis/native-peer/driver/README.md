# Fixed Linux outer driver

This contributor driver owns one run of the reviewed four-case native peer
wrapper in a separate user/PID/network/IPC/UTS namespace. It does not activate
the AXIS customer provider or qualify the common launch gate.

The fixed input wrapper was built at `efc2c3b304690320447dee57f01a51fc6df25060`
in Actions run `39150168377`, artifact `12144044675`. Two independent inert
reviews checked its source, dependency, archive, provenance and static image.
The image SHA-256 is
`cd72428ee90356d4a9febe41bc8a131386c92dff43ad07871d74ec9763085233`
(3,432,574 bytes); archive SHA-256 is
`038fcd824a661d4ab81ccdc8b29ef3201cc47453f8b657ac7753750002084fc2`;
provenance SHA-256 is
`46e190705132b0e1098e37ee84af2ab775fc0f92a581c4411c822f7ebc19b2d7`.
Its fixed combined peer/payload receipt is
`9e7c6f82be689db0167067b0eb108f48870279e4a015c1b91604583b063e02db`.
These are compiled source pins. There is no caller-supplied image, digest,
command, environment, backend or policy option.

The outer driver itself still requires independent source/build/image review
and explicit authorization for a bounded run. No runtime result is claimed by
this source batch. The build workflow compiles two static copies, runs only
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
sealed wrapper with an empty environment. All explicit non-stdio descriptors
close on that exec. The creator-thread death caveat is availability: an early
unexpected thread death terminates the owned init. No raw PID/group/name lookup
authorizes cleanup. An inability to obtain atomic custody never grants exec.

The outer deadline is 120 seconds. Cleanup gets a separate ten-second wait and
one ten-second retry. A failed first cleanup remains a failed result even when
retry succeeds; a pending exact owner stays reachable through reporting.
Stdout/stderr each retain at most 64 KiB, including failure paths. Success
requires the wrapper's exact four ordered cases, markers, canary controls,
exit values and both levels of cleanup. The outer cleanup result describes
whole-wrapper namespace custody; it does not replace SDK cleanup assertions.

After independent driver artifact admission, the only intended selector is:

```text
fixed-outer-driver --run-fixed --receipt /private/admitted/REVIEWED-ARTIFACTS.json --evidence /private/fresh-evidence
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
