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
