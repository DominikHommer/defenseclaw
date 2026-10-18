# Fixed Linux outer driver

This contributor driver owns one run of the reviewed four-case native peer
wrapper in a separate user/PID/network/IPC/UTS namespace. It does not activate
the AXIS customer provider or qualify the common launch gate.

The fixed input wrapper was built at `d056852e147bfd79309eda1e346439bbe317f30e`
in Actions run `39144832868`, artifact `12142861838`. Two independent inert
reviews checked its source, dependency, archive, provenance and static image.
The image SHA-256 is
`0197f67426caa1d0df19be5efc7bb7f9596caa67d50025a0522682ff9a1b9648`
(3,387,518 bytes); archive SHA-256 is
`744f4a72cc95874847cc503f0b6314d2532026826dc8ea09212b34f8c825bf3c`;
provenance SHA-256 is
`782708c28c02117a0ad984c2aa8a76db0e3f6268af0e78df7610a34dc9302adb`.
Its fixed combined peer/payload receipt is
`4f6cfd2e44f8b374f43aeb0587a0bd0c8220f3fafa8956a7ed6a93c7207ab621`.
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

The next source revision adds a fresh mount namespace and a fixed sealed FD3
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
