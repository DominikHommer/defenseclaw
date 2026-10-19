# Windows integrated native peer attempts

These fixed contributor canaries have **not passed**. AXIS customer execution
remains unavailable. No attempt below observed Prepared, Started or a contained
payload marker. The earlier direct MXC SDK/Claude evidence is separate.

The peer is built from DefenseClaw d0723346, AXIS fb5fd5f0 and MXC v1.0.1
fda29ac6. Its image SHA256 is
`dbd6f9f1ba179b450c4928d66c09c929f7e2ff132f7ed2b0f0a6e9928b6a01a9`.
Three independent inert reviews checked the build and artifact before use.
The fixed payload SHA256 is
`37de1dd01607e830fc05a88b6105e386da0d3f8ebb83ca48dfbafad43999f40d`.

| Outer attempt | Fixed fixture | Result | Cleanup observation |
| --- | --- | --- | --- |
| 01 | Not created | Filesystem preflight refused before process creation | All allocated handles closed |
| 02 | canary-01, retained | Harness started; host network positive control failed before bridge Start | Root terminal, Job empty, all handles closed |
| 03 | canary-02, retained | TCP/UDP positive controls passed; bridge Start refused before Prepared | Native wait succeeded after initial Close error; root terminal, Job empty, all handles closed |
| 04 | canary-03, retained | TCP/UDP positive controls passed; Start diagnostic classified `process_admission` | Initial native Close succeeded; root terminal, Job empty, all handles closed |

The launcher admitted its exact held executable with ProcessImageFileMapping
class 44 before resume, assigned its Job atomically at creation, and retained
image views and handles until terminal observation. Attempts 02–04 observed
these controls. None hit its external 40-second subprocess runtime cutoff or
output cap. The cutoff begins after Python process creation, rather than being
a hard deadline on all Windows kernel calls.

Attempt 01 used filesystem query class 7 with a device-information buffer.
The correction uses FileFsDeviceInformation, class 4, matching the production
Go/Rust checks. Eight pure/mock tests passed after that test-custodian fix.
This was a contributor fixture error, not an MXC defect.

Attempt 02 exposed Winsock 10106 in the host harness's empty environment.
A separate fixed localhost probe failed with an empty environment and passed
both TCP and UDP with only SystemRoot obtained from GetSystemWindowsDirectoryW.
The revised outer source supplies that single trusted host-harness entry.
The production peer's explicit empty environment and the payload plan are
unchanged. Nine pure/mock tests passed for the revised outer source.

Attempt 03 exposed a separate partial-session cleanup defect: Session.Close
refused before a protocol owner existed despite retained native custody.
Commit ae5f6c8d corrects that path; three focused race tests passed. Attempt 04
then observed native cleanup without the initial Close failure. The backend
adapter correction in 9784ee8f passed four focused race tests. These fixes do
not resolve the Start refusal.

Attempt 04 used harness source06, with four pure/fake race tests passing and
zero failures/skips. Its failure-only diagnostics classify known errors and
numeric Win32 codes without formatting raw error text, paths or environment.
The rejected source05 UTF-8 editing error was corrected and independently
reviewed before any build or execution of that revision.

Saved outer stdout SHA256 values, in attempt order:

- 01: `83cbe6d6b7ca308c81e592c56189a087a985b38f11fe8f1017e3b9de450dfc2f`
- 02: `dfa83a4b85d1411ac1d887f1a4088bbbaa628bda3e739f3fa615f5a04c4b68ef`
- 03: `86dede9485bbc8b7f46d48123f86c54210a4ac04fac53d273dd12098d13ad114`
- 04: `4bcfb6debaad48d5b3c530419b42a86bfb215ad840ee8d8aca2c2bbe691c72b9`

The full failed records and retained public fixtures remain on the test host.
Native peer/workload execution, filesystem/network enforcement, real agent
authentication, hooks, terminal support and production qualification remain
unverified by these attempts.
