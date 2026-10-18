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
