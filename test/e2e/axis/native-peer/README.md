<!-- Copyright 2026 Cisco Systems, Inc. and its affiliates -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Private native peer live gate, in preparation

This directory is contributor test source, with no product caller. Its fixed
Go payload must be built using the pinned Go toolchain with `CGO_ENABLED=0`,
reviewed as a static ELF artifact, and launched only after the native peer,
static-musl Bubblewrap closure and held-object mount seam pass independent
source and artifact admission. No live harness is enabled by this source.

The payload accepts only fixed canary selectors and, for `boundaries`, a strict
`/tmp/dc-axis-native-peer-<32 lowercase hex digits>/outside` fixture path. The
trusted harness must exclusively create and pin that private tree and both
outside canary files before launch; it never accepts a customer path. The
payload requires the private guest `/work` cwd, exact fixed seal, three supplied
environment entries and Bubblewrap's exact derived `PWD=/work` before any
mutation. Before its boundary selector writes, it also checks bounded seals
in both `/home` and `/tmp`. The trusted harness must verify the held identity
of each source. It tests literal arguments, binary input plus EOF, separate stderr,
exit 23, read-only/read-write/outside boundaries, and representative socket
and socketpair denial. The syscall filter's complete policy needs independent
source/artifact admission beyond these sampled live calls. Its negative access
probes only open and close nonblocking, nofollow handles: they never write,
truncate or create an ungranted target if containment is broken. Fixed seal
and read-only canary reads are bounded. Root writability and private device
writes are distinct from access to an outside host file. The boundary selector
requires the root mount's `ST_RDONLY` flag and writes positive canaries to all
three explicit private read-write directory grants. Its process tree includes
a grandchild in a separate session and fixed heartbeat
files for bounded cleanup observations. It never selects a host executable,
PATH entry, credential or arbitrary path.

The future trusted host harness must independently demonstrate host-positive
filesystem and loopback controls, one-use preparation, stale/renamed grant
refusal, timeout/cancel/EOF, parent death, and exact retained pidfd wait. The
heartbeat observation is supplemental; lack of writes alone does not prove
arbitrary descendant containment. Nested PID-namespace behavior and terminal
support require separate tests. Old Landlock/MXC probe pass results do not
qualify this new mount and process-custody posture.

No payload has been executed, and these files do not enable AXIS.

The separate [fixed host harness](harness/README.md) now supplies contributor-only
artifact admission, held synthetic grants and actual factory/protocol wiring
for the first argv/stdio/exit/boundary slice. Its source-controlled artifact
registry is closed pending independent peer/static-musl/payload artifact review;
default or explicit invocation cannot execute while it is closed. Its fake and
inert tests establish no native runtime or production launch-gate qualification.
