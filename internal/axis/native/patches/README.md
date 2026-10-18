<!-- Copyright 2026 Cisco Systems, Inc. and its affiliates -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Private owned-descriptor mount experiment

This is uncompiled contributor source. It is not an installed runtime or a
customer sandbox. No native execution is authorized by this directory.

`bwrap-owned-fds.patch` applies only to Bubblewrap 0.9.0 commit
`8e51677abd7e3338e4952370bf7d902e37d8cbb6`. It modifies only `bubblewrap.c`.
The patch remains LGPL-2.0-or-later, matching that source; `bwrap-COPYING`
retains the exact upstream license. The source and license Git blob identities
were independently matched to the upstream Git tree before authoring.

| Upstream file | Git blob | SHA256 |
| --- | --- | --- |
| bubblewrap.c | 9b78a9ae30dd8f3361f95ae0132d1c32a4ac3329 | 6a89bc9b7a794d19e2bdb1e139ab9d5bba84e807b330336f363f88f130cfeab6 |
| COPYING | 5bc8fb2c8f757e34a0d8f4644f589d57609e213f | b7993225104d90ddd8024fd838faf300bea5e83d91203eab98e29512acebd69c |

The stock [source](https://github.com/containers/bubblewrap/blob/8e51677abd7e3338e4952370bf7d902e37d8cbb6/bubblewrap.c)
resolves pathname bind sources with `realpath`. A `/proc/self/fd/N` pathname
therefore does not preserve source-object custody. `--ro-bind-data` copies file
contents; it is not a directory-descriptor bind operation.

The additive `--dc-bind-fd` / `--dc-ro-bind-fd` experiment retains each source
descriptor, creates a detached recursive mount clone with `open_tree`, sets
`NOSUID|NODEV` and (for read grants) recursive `RDONLY` on that detached clone,
then attaches it with `move_mount` to a held destination descriptor. It does
not reopen the source pathname or modify source-mount attributes.

Destination lookup is component-relative and rejects symbolic links. Missing
placeholders are created only on the new root's private tmpfs device. An
earlier grant covering a target parent permits only opening an existing target;
the extension never creates files through that source mount. Host source
symlinks such as a reviewed `/lib` alias are handled by the trusted factory's
held object, not by reopening a source string here.

Admission requires x86_64, a non-root unprivileged caller, fresh user/mount/PID/
network/IPC/UTS namespaces, and no joined user/PID namespace or setuid helper.
The original mount namespace remains held and must differ from the active one
before any destination mutation. Operation descriptors close after setup, and
original source descriptors are close-on-exec. No weakened or pathname fallback
exists. Mixed legacy setup operations refuse. Only synthetic `/dev` and `/proc`
roots may precede the held mounts; no held destination may cover those roots.
Missing syscalls, mount permissions, headers or mount attributes fail.

The contracts are the Linux man-pages for
[open_tree](https://man7.org/linux/man-pages/man2/open_tree.2.html),
[mount_setattr](https://man7.org/linux/man-pages/man2/mount_setattr.2.html) and
[move_mount](https://man7.org/linux/man-pages/man2/move_mount.2.html).
`open_tree`/`move_mount` require Linux 5.2; `mount_setattr` requires 5.12. These
version numbers are necessary floors, not sufficient capability admission.
Locked mount attributes and user-namespace restrictions can still refuse.

The pinned [Meson build](https://github.com/containers/bubblewrap/blob/8e51677abd7e3338e4952370bf7d902e37d8cbb6/meson.build)
requires a C compiler, Meson >=0.49, Ninja, Python3 and libcap development files.
SELinux is optional. A disposable build should disable SELinux, completions and
man-page generation explicitly and retain the exact source, patch, license,
compiler, flags and output hash. No install or privileged build is needed.

Before any use, a reviewed source build must compile this patch with strict
warnings, then qualify read/write grants, recursive submount attributes,
source-rename replacement, nested targets, missing targets, denied syscall /
namespace support, descriptor closure and parent-death containment. It must
prove that no source or foreign namespace was mutated. The private peer also
needs a reviewed static-musl loader/bwrap-image execution contract. ELF
`PT_INTERP`/`PT_DYNAMIC` absence alone does not prove that static glibc cannot
load NSS or other modules. Executing a sealed dynamic ELF alone does not pin its
interpreter or libraries.
