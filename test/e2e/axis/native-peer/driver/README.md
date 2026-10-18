# Fixed Linux outer driver

This contributor driver owns one run of the reviewed four-case native peer
wrapper in a separate user/PID/network/IPC/UTS namespace. It does not activate
the AXIS customer provider or qualify the common launch gate.

The fixed input wrapper was built at `c0a8f164feaa293016746bab21f12cda9cf0d357`
in Actions run `39141598755`, artifact `12141743050`. Two independent inert
reviews checked its source, dependency, archive, provenance and static image.
The image SHA-256 is
`2017f419020e862b7d5bc77d01b76c522655c07eab2bbb7918869c51e6cc2e03`
(3,379,326 bytes); archive SHA-256 is
`d217fad41ef60b46932e5c293947733a4ee9b88e6e57ce1686b2721fd12101aa`;
provenance SHA-256 is
`4fbb5b0e76e431e2141e8056a2ffca3e9284227178c45682b74f04e23af0d87f`.
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
