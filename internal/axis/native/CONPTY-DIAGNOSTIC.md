# Fixed Windows console diagnostic (source candidate)

This branch is unadmitted source. It does not enable customer Terminal, alter
bridgeprocess.Start, add a backend/catalog capability, or claim ConPTY works
inside PSEC. The ordinary peer entry, literal argument contract and all three
Cargo.lock files remain unchanged. The new binary requires the off-default
windows-conpty-diagnostic feature; that forwards only the dedicated new SDK
axis-conpty-diagnostic feature.

The three selectors are exact and independent:

| Selector | Security environment | Console | Fixed payload argument |
| --- | --- | --- | --- |
| ordinary_conpty | None, explicitly uncontained control | ConPTY | --fixed-console |
| headless_psec | Existing strict PSEC | Existing synchronous child stdio | --fixed-headless |
| conpty_psec | Exact same strict PSEC | ConPTY on the same CreateProcessW startup | --fixed-console |

There is no automatic retry, fallback or remapping between these cases. The
ordinary control is never containment evidence. Its Preparation.backend remains
the private windows_psec transport tag so the same existing capability prefix,
wire binding and Owner are reused; that tag is not an enforcement claim for
this explicitly uncontained diagnostic.

All cases use the same held image, supplied capability table, full file identity
and private-root checks, suspended primary thread, retained BaseChild/Job and
pre-Resume class44 checks. The child token is queried through the retained query
duplicate; same user and session are required before Resume. OrdinaryConPTY also
refuses an AppContainer token. PSEC token AppContainer fields remain measured
facts, not guessed OS guarantees or endpoint authentication. The peer requires
an empty environment and non-elevated current primary token. No SID, path, argv
value, environment value or raw SDK error is emitted.

ConPTY owns its two existing synchronous workload endpoints and one HPCON.
The existing overlapped parent endpoints and single Owner event loop are reused.
The PSEUDOCONSOLE startup attribute takes the HPCON value itself, whereas PSEC
uses a pointer to its retained boxed HANDLE. STARTF_USESTDHANDLES and
CREATE_NO_WINDOW are absent in the console cases. No broad UI policy, account,
desktop/session switch, helper service or SDK tier fallback is added.
Extra synchronous endpoints close after successful creation, while the suspended
process is already retained by Owner. Resize accepts only 31 rows by 97 columns.
The initial shape is fixed at 24 by 80, timeout8000ms and outputlimit16384B.

ConPTY output is one merged console stream. Its transport stderr slot is a
distinct pipe whose producer end is deliberately closed; it proves no separate
guest stderr behavior. Headless PSEC retains its three original streams.

The SDK releases HPCON only after the retained root signals and Job active0 is
observed. Owner still requires pipe EOF before Exited and Destroyed. A failed
native close terminates the private peer instead of reporting successful
cleanup; the independent outer Job remains final custody. No other controller,
unbounded reader thread, PID adoption or post-failure capability grant exists.
Before HPCON creation, the diagnostic refuses OS versions below major10 /
build26100: Microsoft documents that older ClosePseudoConsole can wait
indefinitely. This source floor is not target-OS qualification. A future admitted
native harness must retain a hard external deadline and Job teardown.

Phase1 source compilation only:

* Existing default GNU and Windows feature sets stay off. Linux applies only
  the 286-byte SDK Cargo feature-declaration overlay; the Windows terminal
  implementation overlay is explicit source data and is never applied there.
* Default Windows still builds the ordinary peer and runs exact21 peer plus9
  SDK inert roots. Its SDK source map has19 entries including the feature
  declaration; all existing18 source fingerprints remain exact.
* Only a first-attempt hosted workflow_dispatch with conpty_diagnostic=true may
  select prepare_windows_build.py --conpty-diagnostic. It builds the separate PE
  as data, runs exact25 peer plus13 SDK inert roots, and records21 SDK source
  fingerprints. The four extra peer and four SDK roots are pure. No HPCON,
  PSEC workload, peer, payload or diagnostic binary is invoked in hosted tests.
* Rust1.95.0, pinned AXIS/MXC, original dependency versions and all locks remain
  fixed. The new dedicated feature avoids SDK test-support, which enables
  telemetry/registry process-global override paths in the pinned SDK.
* Provenance always says runtime_admission=false, customer_terminal_activation=
  false and conpty_or_psec_console_support_qualified=false. No archive, image,
  registry, canary, customer route or native recipe is admitted by this change.

A later separately reviewed fixed harness must use a tiny fixed payload that
actually calls GetConsoleMode, ReadConsoleW, WriteConsoleW and
GetConsoleScreenBufferInfo. It must correlate literal input/echo, initial
geometry, live resize, explicit Cancel, non-timeout exit, same-root signal,
Job0, output EOF and Destroyed. Child creation or Resume alone cannot pass.
Neither Job0 nor HPCON close alone proves absence of every OS console-service
process; the diagnostic makes no such claim.
The current fixed Go canary is not that console payload and remains unchanged.
No native harness/launcher or its registry is added in Phase1.

Primary contracts:
* https://learn.microsoft.com/en-us/windows/console/createpseudoconsole
* https://learn.microsoft.com/en-us/windows/console/creating-a-pseudoconsole-session
* https://learn.microsoft.com/en-us/windows/console/resizepseudoconsole
* https://learn.microsoft.com/en-us/windows/console/closepseudoconsole
* https://github.com/microsoft/mxc/pull/1381 (closed unmerged; historical combined
  PSEC/ConPTY I/O failure, not proof of this host or a known implementation fix)
