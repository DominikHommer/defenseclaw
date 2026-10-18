<!-- Copyright 2026 Cisco Systems, Inc. and its affiliates -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Fixed native application-path control

This is source-only contributor code. It has not launched Claude. No customer
provider, SDK, PSEC object, AXIS process, policy fallback or network rule is used.
Any later run is **uncontained** and requires independent source/build review and
one concrete root-owned invocation. This is a compatibility measurement, not an
agent or sandbox qualification.

The only selector is `--run-fixed`. The executable's already protected private
directory must contain `claude-2.1.292-root-image-review.json` with the exact
source-pinned independent receipt digest. That receipt cannot select another
image: image SHA256, 254,858,400-byte size, version and reviewed signature facts
are fixed in source. The image is hashed while held without write/delete sharing,
then copied into a fresh private `claude-path-control-fixture/bin`. All image
ancestors are retained with list-directory access and without delete sharing;
the leaf remains read-only with no write/delete sharing. Directory metadata and
contents are not immutable. The fresh fixture is retained on success or failure.
Existing directories, failed fixtures, profiles and ACLs are never repaired or
deleted.

Three application strings are derived from this same held image: volume GUID,
`GLOBALROOT` plus native volume-device name, and ordinary DOS spelling. Every
spelling must open to the same full 128-bit file ID and volume before any process
creation. These are three fixed observations; success never chooses a fallback.
The literal command line always contains the same quoted verbatim-DOS argv0 and
quoted `--version`, matching the reviewed downstream Rust encoder. Cwd is the
same canonical verbatim-DOS private workspace. Exactly eight environment values
are supplied: native canonical verbatim-DOS SYSTEMROOT/WINDIR plus private HOME,
USERPROFILE, APPDATA, LOCALAPPDATA, TEMP and TMP. No host environment or PATH is
inherited. This records supplied values, not realized child environment.

Each raw `CreateProcessW` call uses the same flags as the downstream pipe control:
SUSPENDED, UNICODE_ENVIRONMENT, EXTENDED_STARTUPINFO_PRESENT and NO_WINDOW. One
HANDLE_LIST attribute carries three anonymous-pipe handles; stdin is already at
EOF. Pipe handle values necessarily differ between fresh cases, while their
shape is fixed. Other startup fields, desktop and security-attribute pointers
are zero/null. There is no SECURITY_ENVIRONMENT attribute, reference PSEC object
or SDK normalization. This is not byte equality with an earlier process or its
different private path values. The only within-run intended input change is
lpApplicationName; per-case handles and mutable command buffers are newly owned.

Successful creation stays suspended until its retained process handle is in a
kill-on-close, nonbreakaway Job and `QueryFullProcessImageName` on that **same
handle** has been opened and matched to the held image's full file ID. A refusal
cannot reach ResumeThread. No PID reopening or PID-based termination is used.
The exact held root and its Job are stopped/waited on all post-creation error
paths; Job active-process accounting must reach zero. Each child has a five-second
deadline. Output has a 64 KiB aggregate budget over both streams and all cases;
only byte counts/digests, numeric diagnostics and exact version-output equality
are reported. Raw path/environment/handle/file-ID values are not printed.
The same-thread NTSTATUS sample may be stale and cannot establish a cause.
Reader completion timeout closes the exact owned pipe and bounded-joins its
worker. The timeout remains a failure even if cancellation then joins; no later
case starts. A failed close/join is explicit and leaves the independent outer
Job responsible, rather than claiming complete custody.

The independent outer controller MUST pin the reviewed helper image and enforce
a **30-second wall-clock deadline over the complete helper**, with owned Job
custody and bounded capture. The internal 25-second admission budget does not
make regular-file/NTFS setup syscalls interruptible. Same-user concurrent object
namespace mutation is not qualified by this synthetic control. Parent mount
validation and held ancestry are checks, not a general namespace isolation claim.

Build-only and pure/inert filesystem checks (never invoke `--run-fixed` here):

```powershell
go test -race -p 1 '-ldflags=-w -s' ./test/e2e/axis/windows/claude-path-control -count=1 -timeout=60s
go vet -p 1 ./test/e2e/axis/windows/claude-path-control
```

The tests exercise selector/receipt refusal, exact literal/environment shape,
identity-before-resume ordering with callbacks, aggregate output bounds, and
real fresh synthetic directory rename/read-only file custody and blocked-pipe
close/join cancellation. They do not
exercise CreateProcess, Job assignment, process-image querying or Claude.

Primary API contracts:
[CreateProcessW](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw),
[QueryFullProcessImageNameW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-queryfullprocessimagenamew),
[GetFinalPathNameByHandleW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfinalpathnamebyhandlew),
[Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects).
