<!-- Copyright 2026 Cisco Systems, Inc. and its affiliates -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Native macOS MXC contributor experiment

The first fixed strict Seatbelt run, [Actions run 39110683768](https://github.com/cisco-ai-defense/defenseclaw/actions/runs/39110683768), used the independently reviewed locked artifact from build `39110212879` at `f8a9055cfe599fb4905f547ffb83f496143b6dfb`. Verification matched all 13 packaged files and the reviewed provenance digest `dfe9e82bb25e0a4f6f614b33a0a000c38d843ac0fe652e2506fbee905a5aa4c4`; all 11 synthetic live-helper tests passed before execution.

The strict probe exited 1 at its first child, before the filesystem and network canaries ran. The bounded child diagnostic was `Error opening /private/var/select/sh: Operation not permitted`. The live receipt recorded 0 stdout bytes, 204 stderr bytes, no remaining matching artifact processes, and no new owned fixture directories. It does not establish sandbox-policy parity or provider qualification.

An attempted follow-up [build 39111804000](https://github.com/cisco-ai-defense/defenseclaw/actions/runs/39111804000) compiled the probe but failed its pure profile test: the selector was not the ordinary file that iteration required. It produced no qualified live result.

The next fixed-profile iteration accepts `/private/var/select/sh` only as a root-owned symlink to the exact root-owned `/bin/bash` executable, with nonwritable path ancestors. It includes both paths in the fixed AXIS policy and exact Seatbelt read grants. The profile remains deny-default and retains the same host-canary denial and required checks. A new locked build, independent artifact review, and newly pinned native live run are needed before drawing any further conclusion.

## Strict native result

[Native macOS experiment 39113129992](https://github.com/cisco-ai-defense/defenseclaw/actions/runs/39113129992) passed all 11 fixed strict checks with the reviewed locked artifact from build `39112683483` at `d05ed40afa43a1c1812259554646b887ae9a9c58`. The native build inventory and pure tests accepted the exact root-owned `/private/var/select/sh -> /bin/bash` selector and its protected ancestry. The live result records MXC SDK V1 Seatbelt with the reviewed strict profile override, the host-canary open denial, filesystem/metadata denials, read-only write denial, blocked loopback with host control, pipe/PTY echo and resize, exit 23, typed timeout, absent delayed descendant marker and owned fixture removal.

The receipt recorded exit 0 in 5.095 seconds, zero stderr bytes, no remaining matching own-UID artifact processes and no new owned fixtures. The fixed live harness was `9a79e22213bc209e7fe19e3e775ea8c10121a7ba` on `codex/axis-platform-live`. Binary SHA256 was `cfe79a436293a5e1e70849af46545bf69c1d2a0bb775c4f3fd1911ed91ab3b8c`, provenance `e32554154d4bd5f869e977f7b446180c896361af85b9bec99bfa8de8657ba9e7`. Live artifact `12131321968` has digest `1bfbf81cd9c34a44347d45ddb2d5a9841db2178ed40c37b4fcb38b97a0d3d4cd`. This fixed result does not establish general metadata/system-path parity, arbitrary descendant custody, broker/credential transport, real Claude, or a production provider.
