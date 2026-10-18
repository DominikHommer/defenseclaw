<!-- Copyright 2026 Cisco Systems, Inc. and its affiliates -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Native Windows current-MXC observations

These contributor observations do not activate AXIS or certify a customer
runtime. The host is native Windows 11 x64 build 26200.9457, non-administrator.
No WSL, host ACL modification, AppContainer/DACL fallback, privileged host-prep,
WFP service installation, agent login, real credential, hook or model call was
used.

## First fixed native PSEC attempt: failed

[Locked build 39112591970](https://github.com/cisco-ai-defense/defenseclaw/actions/runs/39112591970)
at DefenseClaw source `215f3e98936b34279e31670a4fed14d5f47542c2` compiled the
reviewed AXIS policy parser and current MXC native-only contributor seam. The
exact source inputs were AXIS `fb5fd5f0f9377c2ccb30d7e027a36373de0d037c` and MXC
`fda29ac63bc306b7f97f3b86b4b63d44f7f40cf2`. Source blobs, inventories,
upstream locks/licenses, reviewed combined lock, overlay, compiler and both
archive/API digests were independently verified before the fixed attempt.

| Input | SHA256 |
| --- | --- |
| GitHub ZIP, artifact `12130379341` | `088a0e1edf12145e4a3133c85841a3c332010aa4d32a2d577a3c293421f76753` |
| Build provenance | `267d7b93c44b26b95048eadbbe2ad41f29b61af9d4de8aa56e3c247464843893` |
| Combined lock | `3b29ecb06dd2a81266c84712f8d6e088605290f386e87498bb7a7472a005af69` |
| Native probe PE | `bfb895fd2ea760aa7cc20f92368b2981927e20e0080282324d0985eb7f540198` |
| First-run custody executable | `a515ed12c4c919f73817628f41827293972afbc00e0013f44d80e59a21de1f1f` |
| First-run custody Go source | `f56db393a2d0c7934151c72b2d6fafec6b4c589e00234cf5f23bd514265a3792` |
| First-run Python outer driver | `e366b493186bf4a6ddf483ef5f70edd8c8c4b94f389069ae21f9ea3f66e2fda8` |
| First-run artifact verifier | `57edf7e9d647e3b6787adec3fc0e96f585cf2bc21d17bcaea2a79d2aefb87178` |
| Non-executing verification receipt | `50de519ab72c5cd90e4946486fce258218d1375cc1f057cee26afc2d79dc2170` |

The exact wrapper command was `custody-root.exe -receipt <verified-receipt>
-receipt-sha256 50de519ab72c5cd90e4946486fce258218d1375cc1f057cee26afc2d79dc2170
-case-root <fresh-private-evidence>/psec-headless-01`. It started the fixed
probe with no caller workload arguments. Native ProcessContainer was selected
directly with DACL fallback disabled, hard filesystem policy, blocked network,
explicit private environment and the unchanged default UI restriction.

| Observation | Result |
| --- | --- |
| Outer wrapper | Exit 1 in 3.484 seconds; no outer deadline, truncation or read error. |
| Native child | `Exited(-1073741502)`, NTSTATUS `0xC0000142` (`DLL_INIT_FAILED`); empty child stdout/stderr and no boundary marker. |
| Outer custody | Assignment to the owned Job before resume observed; active process count zero afterward; Job empty. |
| Fixture | One exact synthetic owned fixture retained for inspection. |
| Qualification | Failed; no filesystem/environment/network boundary success, terminal or Claude claim. |

Raw evidence remains privately under
`C:\Users\vnarajal\.codex\axis-manual-test\windows-current-psec-max-01`.
The verified artifact, source/import inspection records and exact first-run
helper source snapshots remain under
`C:\Users\vnarajal\.codex\axis-manual-test\mxc-v1-windows-215-root-review`.

Read-only inspection found Shell32/COM/TDH/Userenv/VCRuntime imports in the
SDK-bearing self-payload; this host's Shell32 imports User32 and GDI32. MXC
maps the default disabled UI policy to PSEC's Win32k system-call restriction.
Their interaction is a hypothesis, not an established failure cause. The next
distinct diagnostic uses a separate std-only payload with the same policy,
requires actual import inspection, and can report only its loader marker,
exit23 and bounded ownership/cleanup observations. It cannot turn this failed
boundary attempt into a passing qualification.

## Separate std-only loader diagnostic: passed

[Locked build 39115553188](https://github.com/cisco-ai-defense/defenseclaw/actions/runs/39115553188)
at `a96ef846d7c75987c9266aa96f928c8915dbcc3d` passed compilation and the pure
SDK admission tests. Those tests ran in the SDK's own workspace with its
unchanged upstream lock; Cargo had refused external-dependency package testing
in the earlier attempts. The contributor combined lock stayed unchanged.
Independent reviews verified all 16 inventory files, nine source Git blobs,
upstream locks/licenses, toolchain, overlays and exact successful workflow/API
identities before execution. PE import inspection confirmed that the distinct
122880-byte child imports kernel/NT/CRT support without the supervisor's
Shell32/COM/TDH/Userenv dependency surface.

| Input | SHA256 |
| --- | --- |
| GitHub ZIP, artifact `12132482302` | `9836ea32e96ca324bd19e0a96ff20213744f235a6ac416887d7f18770e1c1503` |
| Provenance | `1107fbbd9fe328c8e3d9197b233de0a8ff856d6e4b296cfdc402909f0061f9f5` |
| SDK supervisor | `c8e0f6bb418517e68d3b185cbac65320aa3ce165dfcb812ae4a597a7699d2c50` |
| Std-only loader child | `9bad1152a7391eb3fb02cbec6cf3ba35845327f71c1cd705e63aded9528a1446` |
| Reviewed custody Go source | `d08f4bad5d261708118017fb9f07efdb23f2842f009acae6a3a127166cb8e07e` |
| Custody executable, Go 1.26.5 | `58329247f68ff9ebe962c663a7fa27e3bbf566560be7dd4c1dbf4b370e7a8981` |
| Root verification receipt | `301792d55aaf0271393e63dc477c85ac32e94651d07a8367b06130493709faf6` |
| Actual live result | `43be5131c408eff3d2285d4aaa65f9809d0100bb5c297c66e03be10327f49fc8` |

The adversarial tester performed exactly one `run_live.py --loader-only`
execution, with the pinned custody executable and receipt, in a fresh private
fixture. It returned exit 0 in 5.047 seconds, with the exact
`FIXED_PSEC_LOADER_STARTED` marker, typed `Exited(23)`, a signaled retained direct
handle and all four loader diagnostic checks. Outer Job assignment happened
before resume; its final active process count was zero. The receipt reported
no deadline, overflow, reader error or retained exact owned fixture, and custody
stderr was empty. Helper/image/receipt pins matched before and after the run.
No filesystem, network or UI policy was relaxed.

Evidence remains privately under
`C:\Users\vnarajal\.codex\axis-manual-test\windows-current-psec-loader-max-02`.
This proves this distinct minimal payload can start under the same native
policy. It does not identify the exact cause of the SDK-bearing self-payload's
DLL failure or qualify its failed nine boundary checks. A separate std-only
filesystem/network/argv child remains the next gate; terminals, Claude, hooks,
credential brokering and complete lifecycle still require their own tests.

## Separate std-only boundary and literal argv: failed

[Locked build 39120734916](https://github.com/cisco-ai-defense/defenseclaw/actions/runs/39120734916)
at `3a8b1e8cec430209254f62bbe5afe52f60ce7b77` passed all ten exact SDK
admission tests, including one native file-custody fixture without payload
execution. Two independent reviews verified 24 ZIP entries, 20 inventory
files, 12 exact Git source blobs, all three overlays, all 15 reconstructed
SDK source fingerprints, unchanged locks/licenses and three PE import tables.
The std-only boundary child adds Winsock imports to the minimal loader's
kernel/NT/CRT footprint; the SDK-bearing supervisor stays outside PSEC.

| Input | SHA256 |
| --- | --- |
| GitHub ZIP, artifact `12135005005` | `6ce964e2ea6c37321780b32e061b1b73515a821f42cb9966b2aceded339e5ff5` |
| Provenance | `9b8d87f8185f5336b2b4e2ffa386877f8279a6e8a7c8c682740efdcfed9ed5ad` |
| Supervisor | `1ccbb1f1d7afb6f8be38cbc96cf89274f069ae655a1207564a1aa9daf7e4c338` |
| Boundary child | `077028f01c154de5a1fc521f0a68d036711b27541dd29bc4790f42139b250064` |
| Custody executable | `ab635640c1a6925854bd99f68b6a1d9d966dbb9e071b69cab704b544b4154b7d` |
| Root verification receipt | `00d85eadc878066fd2eff35f99497e1706dc1fc07cf9e1e3d07b241b3f42534d` |
| Actual live result | `7622beede7b34ff7694c5e4e904a708b34c80503ef9ecc50ca6b939a2e552aec` |

The adversarial tester performed exactly one fixed `--standalone-boundary`
run. The literal Windows argv case passed with `FIXED_ARGV_PASS`, typed exit 0
and a signaled retained process handle. The next boundary case exited 1 with
`Access is denied` before either permitted-write canary appeared. This does
not identify the precise failing call or qualify any filesystem/network
boundary checks. The wrapper took 9.265 seconds; its owned Job was assigned
before resume and ended with zero active processes. No deadline, output
overflow or reader error occurred. No policy, grant, ACL or UI restriction
was relaxed, and the failed artifact was not retried.

Private evidence remains under
`C:\Users\vnarajal\.codex\axis-manual-test\windows-current-psec-boundary-max-01`.
Its exact owned fixture `psec-headless-01\tmp\dc-axis-windows-psec-X8IPVg` is
retained. The next source adds fixed operation labels around early cwd,
seal-read and permitted-write calls, without changing those operations or
their grants. A fresh locked build and independent review are required before
another native attempt. Customer Windows AXIS remains unavailable.

## Fixed early-operation diagnostic: canonicalization refused

[Locked build 39122262255](https://github.com/cisco-ai-defense/defenseclaw/actions/runs/39122262255)
at `b405223cf9c26cc5ed76ac52025f5ca94e386dc1` retained the same policy,
grants and child operations, adding only fixed early-operation labels. Two
independent reviews verified the new artifact and exact source before one
fresh `--standalone-boundary` run. The literal Windows argv case again passed.
The boundary child completed its private cwd lookup, then exited 1 at
`private cwd canonicalize: Access is denied. (os error 5)`. Seal read and the
permitted-write checks were not reached. This label does not distinguish the
directory open from the subsequent final-path query inside Rust's
`canonicalize`.

| Input | SHA256 |
| --- | --- |
| Root verification receipt | `df3f4256fddaad2f5e88754d25a47933ce7fd32e57f103a2993bbef902fe732f` |
| Custody executable | `ab635640c1a6925854bd99f68b6a1d9d966dbb9e071b69cab704b544b4154b7d` |
| Actual live result | `f66a8ebd7355c393079b40674ff08cb5979cd2dc2097c1947033a5ea6ab89626` |

The owned outer Job was assigned before resume and ended empty with zero
active processes. No deadline, output overflow or reader error occurred. One
exact synthetic fixture was retained under the private evidence directory
`C:\Users\vnarajal\.codex\axis-manual-test\windows-current-psec-boundary-max-02`.
No policy, grant, ACL or UI restriction was changed, and this failed artifact
was not retried. Boundary qualification remains failed.

## Call-specific diagnostic: DOS path query refused, direct read passed

[Locked build 39123961008](https://github.com/cisco-ai-defense/defenseclaw/actions/runs/39123961008)
at `a13bc3e8369c12b74eb616b1db4f5d537769780c` adds only read-only diagnostics
after the same mandatory canonicalization error. Two independent reviews
verified its 24 ZIP entries, 20 manifest files, exact source/lock/license bytes,
three overlays and all 15 reconstructed SDK source fingerprints. One fresh
native `--standalone-boundary` attempt passed literal argv, then failed the
original mandatory canonicalization check. It was not retried.

| Fixed diagnostic | Actual result |
| --- | --- |
| `CreateFileW` directory open, access 0 | success |
| Normalized DOS final path on that handle | Win32 5, Access denied |
| Opened DOS final path on that handle | Win32 5, Access denied |
| Normalized NT final path on that handle | success, length 158 |
| Closing the diagnostic handle | success |
| Bounded direct fixture-seal read | success, exact public sentinel |

No path contents or credentials were logged. These observations distinguish
the DOS-query failure from the granted direct read; they do not establish why
the kernel denied those queries or qualify the remaining boundary checks.

| Input | SHA256 |
| --- | --- |
| ZIP, artifact `12134839210` | `0e4d8f495a99b1a40ccfa6b8c0d00c9376d321147451fff1e3be1785fa77025b` |
| Provenance | `475bc2e3b83038a39f3f85369e79d994b445584ae1e58e44a6298484d241e58d` |
| Root verification receipt | `67e926aa5e373e085729326a2d47dec1c258c7f98a3976ae0c59918137690c4f` |
| Actual live result | `97ab772b1c6fa198f4dc2f823e9f6c053f48962264f450609fb6aca5562eee5b` |

The wrapper exited 1 in 3.58 seconds without deadline, overflow or reader error.
The owned outer Job was assigned before resume and ended empty. The exact
synthetic fixture `dc-axis-windows-psec-vgwIwA` remains retained under private
evidence `windows-current-psec-boundary-max-03`. No policy, grants, host ACL,
firewall, UI restrictions or SDK code changed.

The next fixed test records canonicalization as a compatibility result and
uses its explicit current directory for the boundary operations. Fixture
shape, private environment and seal assertions remain mandatory. This is a
test correction, not broader filesystem permission or application support;
applications requiring the denied DOS query remain unqualified. A new locked
build, independent artifact review and native run are still required.

## Direct canary iteration: private environment spelling refused

[Locked build 39125660254](https://github.com/cisco-ai-defense/defenseclaw/actions/runs/39125660254)
at `830eb041671ebc2f6e685ab4d13847101643961f` passed its ten SDK admission
tests and two independent source/artifact reviews. One fresh fixed native
attempt passed literal argv and the same directory-open, NT-query and seal-read
controls. Both DOS queries again returned Win32 5. The child then refused its
private environment equality check before either permitted write. It was not
retried and no remaining boundary check is qualified.

The parent derives its environment from a canonicalized verbatim-disk path;
the revised child derives its expectation from `GetCurrentDirectoryW`. A
prefix spelling mismatch is the source-based explanation to test next, not a
measured environment leak. The next assertion accepts only an optional `\\?\`
prefix with every remaining UTF-16 unit identical. A pure build test preserves
refusals for different homes/drives/case, dot/slash rewrites and UNC/device
paths. Sandbox grants and native policy remain unchanged.

| Input | SHA256 |
| --- | --- |
| ZIP, artifact `12136312656` | `6b2e97352fa0b1f49d41b06c78ec2194238d924b336abfd648d19a4e52c17cce` |
| Provenance | `b8f99453c9cdfa958c2f90a2bfd1cbc2f130361c92c2c1b30023041b526c513c` |
| Root verification receipt | `44382c550f1e44d2e89862f8d244108091449a6084d142e1a3c818f5ce4f2026` |
| Actual live result | `1949b49c8e530f17d29cd2f0bc3c5ba85643ddc915285a18ee674865fd85de8d` |

The wrapper exited 1 in 12.781 seconds, without deadline, overflow or reader
error. The owned outer Job ended empty with zero active processes. The exact
failed fixture `dc-axis-windows-psec-NUZsHW` remains under private evidence
`windows-current-psec-boundary-max-04`. No host ACL, firewall, UI restriction,
policy or SDK change was made. Customer Windows AXIS remains unavailable.

## Narrow prefix comparison: mismatch remains

[Locked build 39127497805](https://github.com/cisco-ai-defense/defenseclaw/actions/runs/39127497805)
at `53281811a4fc41c099a756cf575de26e99d995cc` passed the ten selected SDK
admission tests and one exact pure private-path comparison test. Two
independent reviews checked its 24 archive entries, 20 manifest hashes, source
and locks, all 15 reconstructed SDK files and unchanged PE import DLL lists.
One fresh fixed native attempt passed literal argv and direct seal read, then
refused the private environment comparison again. The optional verbatim-disk
prefix correction did not resolve the mismatch. The generic six-key assertion
does not identify the differing key or value; no environment leak or precise
cause is established by this result.

| Input | SHA256 |
| --- | --- |
| ZIP, artifact `12137236542` | `c0d511dcbd215aac30b703f9f7b12b0e5e127e3dcb25f15cd851ab9330c45b77` |
| Provenance | `686e475c338927b67d1bdc44ae02bc60f527624bd6bbd8f5261d8208e3dbd64d` |
| Root verification receipt | `00e55fcc6dca641f737596ad605ddb72ca664819eac7b3b5ab0459d41847ac7d` |
| Actual live result | `239adb07ff169ab30944cab743017c0b123b16d4be5297e90d54fc042173ae05` |

The wrapper exited 1 in 5.016 seconds with no deadline, overflow or reader
error. The owned outer Job was assigned before resume and ended empty. The
exact failed fixture `dc-axis-windows-psec-m6U12J` remains under private
evidence `windows-current-psec-boundary-max-05`. The artifact was not retried.
No policy, grant, ACL, firewall, UI restriction or SDK overlay changed.

The next source retains the same exact assertion and adds only a fixed failing
key, bounded UTF-16 lengths, prefix flags, ASCII-case comparison flag and
first-difference index. It never logs path or environment contents. A fresh
locked build and independent review precede further native testing.

## Bounded diagnostic: TEMP differs before permitted writes

[Locked build 39129614000](https://github.com/cisco-ai-defense/defenseclaw/actions/runs/39129614000)
at `246210c3b484ea1de0785756dd4410beda25adfb` preserves the exact private
environment assertion and adds only bounded comparison metadata. Ten selected
SDK tests and the exact pure comparison test passed. Two independent reviews
verified the artifact, source, lock, all 15 reconstructed SDK files and the
unchanged import DLL lists before one fresh native attempt.

Literal argv and direct seal read passed. Both DOS path queries again returned
Win32 5. The child then reported:

```text
FIXED_PRIVATE_ENV_MISMATCH key=TEMP actual_units=214 expected_units=135 actual_verbatim=true expected_verbatim=true ascii_case_only=false first_difference=128
```

The preceding HOME and USERPROFILE assertions passed by the pinned source's
execution order. TMP, APPDATA and LOCALAPPDATA were not reached. The diagnostic
contains no environment values or path contents and does not establish the
cause of the differing TEMP value. No permitted write, negative write or
network check is qualified by this failed attempt.

| Input | SHA256 |
| --- | --- |
| ZIP, artifact `12137991365` | `715c01dac75dd24300f3154622eb3837afa0de36de37462873fc477b271c6b49` |
| Provenance | `099bcb4a93fb74974afa727911570f604300c7f44d56d5519bb8457723e53581` |
| Root verification receipt | `b257b27b49f1cf7ee4fa510e17e198760f77a31a409d9188d8458f054a720612` |
| Actual live result | `9dd809393930bf404fb020c8d708a6aedad217f98cf3014b1339a7982228b261` |

The wrapper exited 1 in 3.343 seconds without deadline, overflow or reader
error. The owned outer Job was assigned before resume and ended empty with
zero active processes. The exact failed fixture `dc-axis-windows-psec-BS9U2l`
remains under private evidence `windows-current-psec-boundary-max-06`. This
artifact was not retried, and no policy, grant, host ACL, firewall, UI setting
or SDK overlay changed. Windows customer execution remains unavailable.

A separate outside-PSEC control uses the same reviewed fixed child and eight
explicit environment entries. Its expected exit occurs at the successful
outside read, after the environment assertions and two private permitted
writes, before negative writes or sockets. This control cannot qualify PSEC
containment. Its first wrapper attempt refused the existing evidence parent's
DACL before creating a fixture or child; the raw stdout and nonzero exit are
retained in `environment-control-01-outer-result.json`. A fresh private parent
and separately reviewed invocation are required for a further attempt.

## Outside-PSEC environment control: passed

The same reviewed build-246 boundary child ran once outside PSEC with eight
explicit environment entries, no inherited credentials and a fresh synthetic
fixture. Its separately reviewed Go wrapper used `processutil.RunTree` and an
owned non-breakaway kill-on-close Job assigned before child resume. A pinned
outer wrapper image/process and bounded readers enforced a 55-second deadline.

The fresh evidence parent was created atomically with a protected DACL for
the current token SID and SYSTEM. No existing ACL was changed, and no failed
fixture was reused or removed. The wrapper revalidated the new parent's owner,
DACL and non-reparse identity before creating the fixture. The original
control-01 refusal remains a pre-execution result, not a containment test.

Control-02 passed in 0.156 seconds: zero wrapper exit, no deadline, overflow or
reader error, and matching stdout/persisted reports. The child exited 1 with
the exact expected `outside read was not denied` failure. By the pinned source
order, all six private environment comparisons and credential/parent-canary
absence checks had passed; both private allowed writes were present, and the
outside/read-only/seal sentinels remained unchanged. It stopped before
negative writes and sockets. The complete fresh fixture remains retained.

| Input | SHA256 |
| --- | --- |
| Exact Go wrapper source | `d91f089bc1f91e7184b248e9c6b67f3624e0d1456751632f430fd9b48b823ac3` |
| Go 1.26.5 wrapper image | `fd5132faff988a3a7ac7f96ff4bc878e15528c9993e30ea94754692d81b9c349` |
| Fixed private-parent creator | `4275cda2c0e5a45f897773a2b81061d9cd710676d0e14a30f1a512214e668fb2` |
| Bounded outer driver | `1df16fa4a749de7fd991be19b317784e1a4ac7b173dea9220ace6fce1244ed80` |
| Actual outer result | `e075cb59147d03e72695946c2a97a0148a79c4b314a6ed943d7091ab33317fbd` |

This narrows the TEMP discrepancy to the SDK/PSEC launch path compared with
the direct Go control. Source review found no SDK-side TEMP rewrite between
the explicit request and its UTF-16 `CreateProcessW` environment block.
Microsoft documents TEMP/TMP profile redirection for
[AppContainer launches](https://learn.microsoft.com/en-us/windows/win32/secauthz/implementing-an-appcontainer).
That is a hypothesis for this PSEC observation, not an established cause.
The existing metadata shows the differing value shares the entire exact
synthetic fixture root before diverging at its first child component. A new
child-only lexical diagnostic retains every exact assertion and continues
through the remaining present variables after a mismatch, then fails before
any credential check, write or socket. A missing variable still fails
immediately. It classifies root/home/local-AppData/private-tmp/Packages prefixes,
component count, dot/slash components and final Temp component without logging
values or accessing any filesystem path. A fresh locked build and independent
artifact review are required before that diagnostic can execute.

## Lexical diagnostic: three private Packages paths differ

[Locked build 39133952217](https://github.com/cisco-ai-defense/defenseclaw/actions/runs/39133952217)
at `42f8b10731b70b93bf754d493869f3e54a93ee68` passed the ten selected SDK
units and the expanded exact pure path-comparison test. Two independent reviews
verified all 24 archive files, 20 manifest entries, 15 reconstructed SDK paths,
source/lock identity and unchanged PE import inventories. One fresh native
attempt used the reviewed custody image and a fresh evidence directory under
the atomically private parent created for control-02. No previous fixture was
reused, and the artifact was not retried.

Literal argv and direct seal read passed; both DOS path queries still returned
Win32 5. The exact environment assertions failed with these bounded lexical
observations:

| Key | Actual/expected UTF-16 units | Relative components | Final component is exact `Temp` |
| --- | --- | --- | --- |
| TEMP | 245 / 166 | 7 | true |
| TMP | 245 / 166 | 7 | true |
| LOCALAPPDATA | 240 / 181 | 6 | false |

All three reported exact lexical prefixes for this fixture root, its home,
local AppData and Packages branch; none matched the originally supplied private
tmp branch. No dot component or forward slash was reported. HOME, USERPROFILE
and APPDATA matched exactly by the pinned loop's execution order. These are
lexical comparisons, not held-file identity or a proof of the redirection
mechanism. No values or profile names were logged, and no credential, write or
socket operation was reached after the failing environment loop.

The observed shape agrees with the documented AppContainer profile redirection
cited above. The next investigation must bind expected native paths to the
actual contained process's native identity; accepting an arbitrary matching
prefix would not establish that binding. No assertion, grant, policy, host ACL,
UI setting or firewall was broadened for this attempt.

| Input | SHA256 |
| --- | --- |
| ZIP, artifact `12139512326` | `f2bca34f9cb442be4beecbc02c1364c318eacc530c4ff2c6f0962dbdf83616c1` |
| Provenance | `b1703cf28cb7f2c0bdf858b10a0ab3d8739e0161f378200552b1f1f543706303` |
| Root verification receipt | `3f39edc6cf949502839d34cbf0a461b6d13c6f15a4cfcfde9f92901c1d074f65` |
| Actual live result | `7afa1f763bea5066373851117e47db2ba9c17e1af4aaaf352040cf8eae354901` |

The wrapper exited 1 in 2.953 seconds without deadline, overflow or reader
error. The owned outer Job was assigned before resume and ended empty with zero
active processes. The exact synthetic fixture `dc-axis-windows-psec-Yhxaa8`
remains under
`environment-control-private-02/windows-current-psec-boundary-max-07`.
Windows boundary, terminal, hooks, credentials and Claude qualification remain
incomplete; customer AXIS execution is unavailable.

## Native process identity: private environment mapping refuses

[Locked build 39138642152](https://github.com/cisco-ai-defense/defenseclaw/actions/runs/39138642152)
at `4a5aa3d964d19fe35fd27e933bacfc956088b0df` passed six exact pure Rust tests
and eleven exact SDK tests. Two independent artifact reviews checked all 27
archive members, source/lock identity and sixteen reconstructed SDK paths.
The child's ten imported DLLs match the prior standalone child; native token
and profile queries remain in the trusted parent.

The Go custody wrapper's native-identity receipt constants were synchronized
separately in `1ab78c8d`. Its new cross-language inert test accepts the actual
Python verifier's three-image identity and rejects the earlier variant/scope.
Native race/vet passed before a fresh Go1.26.5, CGO-disabled build. The attempt
loaded frozen hash-checked Git helper bytes, independently of later source work.

One fresh case08 ran. Literal argv passed with an observed signaled direct
process handle. The next case refused with the fixed error `native private
environment binding refused`. Source ordering places this failure in the pure
native-folder/private-root binding after successful token/SID/profile API
queries; it does not establish the returned folder's shape or a valid mapping.
No native-identity environment marker or subsequent credential/write/socket
boundary checks passed. The expected-path check was not weakened or retried.

The wrapper exited 1 in 6.083 seconds; the probe observation took 3.666 seconds.
The outer Job was assigned before resume, ended empty with zero active
processes, and reported no deadline, overflow or stream-read error. The exact
synthetic fixture `dc-axis-windows-psec-MnHFQy` remains under
`environment-control-private-02/windows-current-psec-boundary-max-08`.

| Input | SHA256 |
| --- | --- |
| ZIP, artifact `12141560414` | `df1864bdc92408e41a77736fbc4f3f6fce5502ab251129a3ced2bd6600693dfb` |
| Provenance | `296183a3e95c03fe1c6489ddc52776891b2512f72b12f2dda8af402232e9cdae` |
| Root verification receipt | `c595a5a503b4305117d2f4393a4514a21c77b12ba18b7874acf3916a0c633987` |
| Go custody image | `27c5d09fc98e8d46e0fb790a019ff12b18969bb60ba528c0a8a2da3f7a917be8` |
| Actual live result | `22b04d978b291028986fcd2c3a1687c2d50ba6a9dcd52b3c448e5564e1f3e522` |

The next investigation must establish the relationship between the native
profile API's result and the child's explicitly supplied private USERPROFILE.
No native path values were logged. Full Windows and real Claude acceptance
remain incomplete.

## Caller-context mapping: known-folder base differs

[Locked build 39144717621](https://github.com/cisco-ai-defense/defenseclaw/actions/runs/39144717621)
at `fcd356d70f19016aa84da6bc96b0efea005319d9` passed six exact pure Rust
tests, the separate native directory filesystem regression and eleven exact
SDK tests. Two independent artifact reviews checked all 27 archive members,
source/lock identity, sixteen reconstructed SDK LF fingerprints and child PE
imports. The superseded a7 artifact was not executed; planned case09 was held.

Exactly one fresh case10 used frozen reviewed helpers and the corrected build.
Literal argv passed. The next case refused with `native profile caller
known-folder base differs`, before the child received its expected environment
frame or reached credential, write or socket checks. This establishes that the
queried native path did not match the mapper's exact caller-base prefix; it does
not establish either actual path, its spelling, or a valid alternate mapping.
No raw native path values were logged and no expected-path assertion was relaxed.

The driver finished in 3.363 seconds, with a 3.255-second probe observation.
The owned Job was assigned before resume and ended empty with zero active
processes. No deadline, overflow or stream-read error was reported. The owned
synthetic fixture remains under the private case10 evidence directory.

| Input | SHA256 |
| --- | --- |
| ZIP, artifact `12143247367` | `9d07a3789b6218601eb56a382a15809a95bc266bc661918ee53ade982e4a66bf` |
| Provenance | `bc06c949c666871f4a38b9b3abda7d85f136f62bac70a4047fb43171c1737ae7` |
| Root verification receipt | `f5627a068f45a5d25903c750d484556b1094b2c8e5173e2dc2bae401d9c4b3d2` |
| Actual live result | `6f59697bb5bad56c6afa78a3975c1431c4f8e25dacdb4267e8114d0dc5044b9a` |

Windows boundary and full Claude qualification remained incomplete at this
gate. The separate fixed Claude version slice had not yet executed.

## Fixed signed Claude version: native process creation refuses

[Locked build 39146773781](https://github.com/cisco-ai-defense/defenseclaw/actions/runs/39146773781)
at `347735e54cffbe54f507e522f4cb11e28a1620fd` built the distinct fixed Claude
version slice. Its 22 exact test passes comprised six pure environment tests,
four pure DLL protocol tests, one native directory filesystem regression and
eleven SDK tests. Independent reviews checked the 30 archive members, 26 manifest
hashes, exact source/locks and all sixteen reconstructed SDK fingerprints. These
were build and inert reviews; they did not execute PSEC or Claude.

One fresh version-only attempt used that artifact and the independently reviewed,
signed Claude Code 2.1.292 image. The existing wrapper reported Win32 87
(`ERROR_INVALID_PARAMETER`) after `CreateProcessW` failed while attaching the PSEC
environment. That wrapper did not sample the raw native status immediately. The
payload produced no stdout. No Claude start, version output, child-side marker,
environment, hook, credential or model behavior was observed. This is a process
creation failure; it does not establish a DLL-initialization or runtime cause.
No policy, Win32k restriction, filesystem grant or expected value was relaxed.

The outer driver returned in 11.672 seconds; the probe observation took 4.911
seconds. The owned Job was assigned before resume and ended empty with zero
active processes. No deadline, overflow or stream-read error was reported. The
fresh inner synthetic fixture was retained after refusal. No retry occurred.

| Input | SHA256 |
| --- | --- |
| ZIP, artifact `12143867428` | `892053f72c45231645d2e8ed6186fea659c740b562ccba9b8b558016780367ed` |
| Provenance | `5006ce09e43e8bb235210b4753fed796de18891e2ee4371bb4075b7ef050800a` |
| Root verification receipt | `96374104298f058b9f739a066cef2ed357e968977bf3d7ba9a28c943436ba996` |
| Fixed local image | `eb95bb65955f8b1702e800815f9a2c0388a5de0f196c354c7ee1dd5cb9a2ba23` |
| Local-image review receipt | `a9c38cec7b47197f04e6016eada1e9743e218f3b0ee8d77c1c913a5d2351fa3a` |
| Go custody image | `32f21133e5037b4408fe6df89128e5b4e98014f4b4e5a7bb66ae130a9f13de77` |
| Actual live result | `a62bad914905fcdb45c6aa1f281cf8dfbd7b514a73fd5b66eb24fea58f24676d` |

The eight private environment values were requested configuration; the realized
Claude environment remains unverified. A changed-source diagnostic was prepared
to capture immediate status samples and bounded structural counts under the same
policy, rather than retrying the unchanged artifact.

## Changed-source Claude creation diagnostic: immediate status samples

[Locked build 39150253860](https://github.com/cisco-ai-defense/defenseclaw/actions/runs/39150253860)
at `ad643e9b5a85fc446316da8917a1d83ec8fc6bcf` passed 23 exact tests: six
pure environment tests, four pure DLL protocol tests, one native directory
filesystem regression and twelve SDK tests. The new pure SDK test checks status
capture order and numeric count bounds without launching a process. Independent
inert reviews checked 30 archive members, 26 manifest hashes, exact source/locks,
all sixteen reconstructed SDK fingerprints and the linked native status import.

One fresh version02 attempt used that changed diagnostic, the same fixed signed
Claude Code 2.1.292 image and literal `--version`. It retained the same filesystem,
offline and Win32k/UI policy. `CreateProcessW` failed before any Claude start was
observed. Immediately after its raw BOOL refusal, the diagnostic copied
`GetLastError` as 87 and sampled `RtlGetLastNtStatus` as `0xc0000034`.
The last NT status can be stale; this sample does not establish a missing path,
identify a parameter, or prove a filesystem or PSEC cause. Payload stdout was
empty. No version, realized environment, hook, credential or model behavior passed.

| Structural observation | Value |
| --- | --- |
| Application UTF-16 units | 199 |
| Command UTF-16 units | 171 |
| Environment-block UTF-16 units | 1144 |
| CWD UTF-16 units | 175 |
| Argv entries, including program | 2 |
| Environment entries | 8 |
| Any diagnostic count capped | false |

UTF-16 lengths include terminating NULs. No argument, environment value, volume
identifier or host path was emitted by this numeric diagnostic. The downstream
literal adapter derives the explicit application path from its held executable
handle using a volume-GUID name; argv[0] retains its separately quoted original
path spelling. Their unequal lengths do not by themselves identify an error.

The driver returned in 5.187 seconds; the probe observation took 4.8908274 seconds.
The owned Job was assigned before resume and ended empty with zero active
processes. No deadline, overflow or stream-read error was reported. The fresh
inner synthetic fixture was retained after refusal. No policy was relaxed and
no unchanged retry occurred.

| Input | SHA256 |
| --- | --- |
| ZIP, artifact `12145046979` | `253f47827c78d6fbb51323e76ce56d45b8cd9cf38daa36d17a504dd471a1195f` |
| Provenance | `83c1b606b6ba4ac1f7a03afb7d03ba095e4750aae4eec719967181546af2ee4d` |
| Root verification receipt | `be08283bd701bd2e924ccad8b9c76db1a8c9eda3c9012bda0121a9de313229f1` |
| Native probe image | `ad989718fcd8431f68d6fb9f8f4859e80f872c50b5cf4f816cfbca704a41b162` |
| Actual live result | `83ed3da797c222a0a666256a2efbf0bb4ac10955cfd8f02522018a7e4580543f` |

The evidence does not establish an upstream defect: this path uses reviewed
downstream SDK overlays for literal argv, held executable custody and native
process observation. A fixed comparison of the exact native launch parameters
outside PSEC may help separate parameter/path compatibility from containment,
but no such control is implemented or executed by this result.

## Read-only synthetic profile query: missing registered profile

One separately reviewed query02 control ran outside PSEC with eight exact private
environment values and an absent thread token. `SHGetKnownFolderPath` returned
`S_OK`; `GetAppContainerFolderPath` for the fixed unregistered synthetic SID
returned `0x80070002`. Path classes remained null. The attempt returned in 2.926
seconds without deadline, overflow, stream-read or pin-close errors.

The helper made no explicit profile-creation or filesystem-write calls. Its
supervisor used the existing owned-Job runner and reported no full-tree or
Job-empty qualification. This refusal neither classifies the Case10 path mismatch
nor binds any expected path to its actual contained child. See the separate
[control results](../profile-query-control/manual-results.md). The retained outer
query result SHA256 is
`e470d41ac2cf782c09131bdfd3258ec76f63cc2e2508ff58b4017e838e81f5fe`.
