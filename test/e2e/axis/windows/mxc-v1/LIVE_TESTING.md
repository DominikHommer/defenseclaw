<!-- Copyright 2026 Cisco Systems, Inc. and its affiliates -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Gated native Windows loader diagnostic

These helpers admit only the distinct `separate_std_loader_diagnostic` artifact
and its fixed `--loader-only` selector. They do not activate a provider or grant
production execution authority. This diagnostic reports a std-only payload's
marker, exit23, retained direct handle and fixture removal. It cannot report the
nine filesystem/environment/network boundary checks or Claude qualification.

The original locked build `215f3e98936b34279e31670a4fed14d5f47542c2`, run
`39112591970`, was independently verified and then failed before its payload
marker with `0xC0000142` (`DLL_INIT_FAILED`). The outer Job was empty and its
failed fixture retained. That historical artifact and its exact helper sources
are preserved; they cannot be accepted as the new diagnostic variant.

Before a diagnostic execution, independent source review and a fresh locked
build must finish. The combined lock remains the reviewed SHA256
`3b29ecb06dd2a81266c84712f8d6e088605290f386e87498bb7a7472a005af69`.
Both the SDK supervisor and separate std-only payload must appear in the exact
binary inventory with reviewed hashes. Inspect the new child's actual PE imports
before execution; absence of SDK references in source is not loader evidence.
No filesystem grant, network rule or UI restriction is relaxed for this test.

`verify_live_artifact.py` checks externally pinned archive/provenance digests,
the successful exact GitHub build/artifact API identities, packaged source Git
blobs, four SDK patch paths, the reviewed combined lock, upstream Git
locks/licenses, compiler identity, both native x64 PE headers and complete
bounded inventories. Only upstream lock/license CRLF-to-LF differences are
accepted. Verification never executes either binary.

Use the already downloaded source-bound archive/extraction and exact local Git
objects. Replace every placeholder with the independently reviewed value;
there is no latest-artifact or download default:

```powershell
python test/e2e/axis/windows/mxc-v1/verify_live_artifact.py `
  --artifact <absolute-extraction>/build-artifact --archive <absolute-extraction>/artifact.zip `
  --source-checkout <DefenseClaw-checkout> --axis-source <AXIS-checkout> --mxc-source <MXC-checkout> `
  --archive-sha256 <reviewed-archive-sha256> --provenance-sha256 <reviewed-provenance-sha256> `
  --build-commit <reviewed-build-commit> --build-run <successful-run-id> `
  --artifact-id <exact-artifact-id> --receipt <fresh-receipt.json>
```

Build the reviewed outer wrapper using the repository's Go toolchain and pinned
`x/sys` dependency. Its eight tests use only synthetic files/receipts and never
create a process or execute PSEC. Python tests are similarly inert:

```powershell
go vet test/e2e/axis/windows/mxc-v1/custody_windows.go test/e2e/axis/windows/mxc-v1/custody_windows_test.go
go test -race -p=1 test/e2e/axis/windows/mxc-v1/custody_windows.go test/e2e/axis/windows/mxc-v1/custody_windows_test.go -count=1
python -m unittest discover -s test/e2e/axis/windows/mxc-v1 -p 'test_*.py'
go build -trimpath -o <absolute-private-path>/psec-custody.exe test/e2e/axis/windows/mxc-v1/custody_windows.go
```

Record source revision/hashes, Go version and wrapper SHA256 beside the private
evidence. After independent artifact/import/source review, the explicit command
is:

```powershell
python test/e2e/axis/windows/mxc-v1/run_live.py --loader-only `
  --custody <absolute-private-path>/psec-custody.exe --custody-sha256 <reviewed-wrapper-sha256> `
  --receipt <fresh-receipt.json> --receipt-sha256 <reviewed-receipt-sha256> `
  --evidence <fresh-absolute-evidence-directory>
```

The wrapper pins both image files against writes/replacement through the run,
creates only the fixed supervisor suspended, assigns its owned kill-on-close
Job before resuming, and allows only three stdio handles to be inherited. No
breakaway flag is granted. The only child argument is `--loader-only`; the Rust
parent selects its exact sibling payload. Arbitrary environment is dropped.
Separate readers bound stdout/stderr, and owned native process/Job handles bound
failure cleanup. A timed-out read fails the observation and is left for CLI
process teardown, avoiding a potentially blocking concurrent close. No inferred
PID is signalled. The outer Python deadline retains the exact wrapper handle.

A passing diagnostic requires exactly the loader case and four-check summary,
the real marker and typed exit23, empty outer Job, assignment before resume,
no truncation/read error/deadline, and no retained owned Rust fixture. Failed
fixtures remain for inspection. The outer Job proves wrapper custody for this
fixed run, not independent SDK descendant cleanup or general PSEC resource
lifetime. Unique synthetic HOME/CWD paths make no Windows ACL confidentiality
claim. Filesystem/network boundaries, Internet/DNS, proxy, credentials, model
traffic, hooks, terminals and authenticated Claude remain separate gates.
No WSL, service, administrator, host ACL change, WFP installation or raw host
credential is used.
