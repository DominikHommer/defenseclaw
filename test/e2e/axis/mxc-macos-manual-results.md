<!-- Copyright 2026 Cisco Systems, Inc. and its affiliates -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Native macOS MXC contributor experiment

The first fixed strict Seatbelt run, [Actions run 39110683768](https://github.com/cisco-ai-defense/defenseclaw/actions/runs/39110683768), used the independently reviewed locked artifact from build `39110212879` at `f8a9055cfe599fb4905f547ffb83f496143b6dfb`. Verification matched all 13 packaged files and the reviewed provenance digest `dfe9e82bb25e0a4f6f614b33a0a000c38d843ac0fe652e2506fbee905a5aa4c4`; all 11 synthetic live-helper tests passed before execution.

The strict probe exited 1 at its first child, before the filesystem and network canaries ran. The bounded child diagnostic was `Error opening /private/var/select/sh: Operation not permitted`. The live receipt recorded 0 stdout bytes, 204 stderr bytes, no remaining matching artifact processes, and no new owned fixture directories. It does not establish sandbox-policy parity or provider qualification.

The next fixed-profile iteration admits only the existing, ordinary, canonical `/private/var/select/sh` file for read. The profile remains deny-default and retains the same host-canary denial and required checks. That source change requires a new locked build, independent artifact review, and a newly pinned native live run before drawing any further conclusion.
