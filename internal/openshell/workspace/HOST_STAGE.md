<!-- Copyright 2026 Cisco Systems, Inc. and its affiliates -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Captured Windows host staging

`stageCapturedSHA1` is a private host staging engine used by `PrepareHostStage`.
It is not connected to `Stage`, a provider, a CLI flag, or agent execution. Its
controlled native fixtures establish the behavior they assert; they do not
qualify native Windows guest operations, AXIS, credentials, or a production
workspace import/export lifecycle.

The caller must retain the private captured-source, output and scratch
`os.Root` handles and clean them up on every refusal. The source has already
passed the NTFS/local-drive, private DACL, held-source, reparse/stream/hardlink,
case/name and complete-capture checks. Root identity and original policy
identity belong to that caller. The engine never rebinds policy to a temporary
capture, reopens a drive-letter path, or starts stock Git. `opts.Project` is a
name/policy fact, not an I/O path in this engine.

Private host preparation freezes operator line-ending fallback facts through
bounded nonfollowing held reads in `operatorConfigDirs` order: home `.gitconfig`
then XDG `git/config`. Missing parents/files are known absent through held
ancestors; unreadable, linked, streamed, oversized or include-based config
refuses. The engine merges local values from its exact captured `.git/config`
over those facts before validating transformations. Plain snapshots preserve
their existing raw-byte baseline and need no operator Git config. Unsupported
transformations refuse instead of silently changing snapshot bytes. Existing
POSIX staging and customer Windows platform availability are unchanged.

## Dependencies and call boundary

The optional implementation is compiled from go-git **v5.19.3** and its Billy
**v5.9.2** transitive dependency. Go module checksums pin source bytes in
`go.sum`. The reviewed module closure raises the existing `golang.org/x/crypto`
floor from v0.55.0 to v0.56.0 and `golang.org/x/exp` from
v0.0.0-20250305212735-054e65f0b394 to
v0.0.0-20260410095643-746e56fc9e2f.

Only plumbing object/hash, stream config/index/pack codecs and the ignore
matcher are used. `plumbing/object` transitively links go-git's config, storage
and Billy osfs packages. This is a linked dependency distinction: the engine
does **not** call ambient config loading, Billy/osfs, filesystem storage,
repository discovery, clone/fetch, transport, subprocess or mmap APIs. Every
actual filesystem access is relative to an already-held `os.Root`.

Review source and published advisories when changing either pin:

- [go-git v5.19.3](https://github.com/go-git/go-git/releases/tag/v5.19.3)
- [Billy v5.9.2](https://github.com/go-git/go-billy/releases/tag/v5.9.2)
- [go-git published security advisories](https://github.com/go-git/go-git/security/advisories)
- [Billy published security advisories](https://github.com/go-git/go-billy/security/advisories)

## Bounded accepted format

Limits refuse the entire candidate; selection is never silently truncated.

| Resource | Bound |
| --- | --- |
| Complete raw capture | Existing `MaxBytes`, 250,000 entries, 128 directory levels |
| Engine deadline | 5 minutes, respecting an earlier caller deadline |
| A decoded object or delta payload/result | 32 MiB |
| Aggregate inflated pack/loose payloads and reconstructed/generated objects | 512 MiB |
| Physical object entries and new distinct objects | 100,000 |
| Delta dependency depth | 64, including already-cached bases; cycles refuse |
| Index/packed refs/shallow input | 16 MiB per file |
| Repository config or an ignore/attributes file | 1 MiB per file |
| Relative path | 4,096 UTF-8 bytes; validated NTFS component names; 128 levels |
| Working path count and total path bytes | 100,000 and 16 MiB |
| Cumulative flattened tree entries and path bytes | 100,000 and 16 MiB |
| Commit metadata / parents | 1 MiB / 64 parents |
| Ignore pattern length / aggregate pattern+domain metadata | 4,096 bytes / 1 MiB |
| Ignore patterns / matching work | 100,000 / 10 million pattern-prefix comparisons, plus 4 Gi weighted pattern/path work units |
| Emitted files, complete host object store and guest metadata together | `MaxBytes` |

Pack/index counts, canonical index layout bounds and object lengths are checked
before codec allocations. Loose object headers are capped before parsing;
the upstream loose-reader's unbounded header API is not used. Delta source and
target sizes are checked before patch allocation. Dependency traversal retains
metadata rather than one payload per recursion level; the actual base, delta
and result each have the per-object bound, plus codec/allocator overhead.
Inflated packed entries spill into held private scratch, and a full entry is
reused rather than copied into a second decoded file. All compressed writes
count toward the output budget while writing, including headers and trailers.

The accepted format is SHA1 loose objects or PACK v2 with an accompanying IDX
v2; both indexed REF and OFS deltas are supported. Pack checksums, index
checksums, entry CRCs and reconstructed object IDs are verified. Missing/thin
bases refuse. Optional reverse-index, bitmap and keep sidecars are not used or
copied. A promisor source refuses because the capture may be incomplete.

Index v2/v3 regular/executable files are supported. Unmerged, intent-to-add,
sparse, split and v4 indexes refuse. SHA256, linked worktrees, alternates,
grafts/replacement refs, config includes, filters, attributes transformations,
submodules, symlinks and unsupported line-ending transforms refuse. Standard
repository `.gitignore` and `.git/info/exclude` rules are evaluated without
global config, matching the existing hardened Git command's private HOME and
hidden global configuration. Backslash-escaped, double-star, negated bracket
and POSIX character-class syntax explicitly refuse. Non-ASCII ignore patterns
and untracked Git paths also refuse because the pinned matcher uses runes
where Git wildmatch uses bytes. Tracked Unicode paths bypass ignore selection
and remain supported. The admitted ASCII literal/basic-glob/positive-range
subset uses ASCII case folding and is compared with native Git in fixtures;
there is no fallback to a broader or incomplete matcher.

Original reachable commits and trees retain their exact encoded bytes and
object IDs. The configured depth creates real shallow boundaries; the engine
does not flatten existing history. The baseline is a separate synthetic commit
parented by the original HEAD. Shared `selectFilesFrom`/`detectSecretsFrom`
decisions apply to the captured working files. A held tracked path retains
skip-worktree semantics. Captured candidate read/stat errors refuse the whole
selection, preserving the I/O cause before any selected file is emitted.
Historical secret-named/held blobs are excluded from
the guest promisor pack; public duplicate content needed at HEAD or baseline
remains. The full object store stays outside the guest tree in `.dc-objects`.
Only sanitized remote URLs, ordinary fetch refspecs and matching branch
tracking are copied into fresh config. Source hooks and executable config are
omitted.

## Focused native validation

Run sequentially on a native Windows host; fixture Git is required to create
and independently read the fixed synthetic compatibility repositories. It is
not called by the engine, which is also exercised with `PATH` empty.

```powershell
go test -race '-ldflags=-w -s' -p 1 ./internal/openshell/workspace -run '^Test(HostStageWindows|CapturedSHA1)' -count=1 -timeout=4m
go vet -p 1 ./internal/openshell/workspace
```

The two-commit fixture requires a real native Git pack containing deltas,
verifies unchanged commit bytes, baseline parentage, configured shallow depth,
tracked/untracked/nested ignores, history withholding and public duplicate
blobs. Other cases attack compressed/header expansion, index fanout allocation,
delta depth/cycles/cache depth, entry CRC/OID mismatch, thin bases, output
overflow, Windows metadata/casing, unsupported formats and matching work.

The private preparation fixtures also verify original source identity/unmask,
held-identity ancestry overlap in both directions, operator fallback/local
config precedence and refusal, raw plain CRLF bytes, DACL/reparse/hardlink/stream
boundaries, owner-lock custody and identity-bound cleanup. The guest Git oracle
runs only fixed commands under a bounded non-breakaway Job with bounded output
and `--no-lazy-fetch`/`GIT_NO_LAZY_FETCH=1`; missing objects cannot start a
promisor fetch. It reads public HEAD and baseline blobs from an independent copy
of the guest repo, with no sibling host `.dc-objects`, capture, scratch or
object alternates, and requires withheld object reads by path and OID to fail.
The engine runs with `PATH` empty for that fixture. A separate compatibility
read uses a held-identity-checked DOS spelling because Git for Windows may
normalize a volume-GUID cwd; that spelling is test-only and does not grant
production path authority.
