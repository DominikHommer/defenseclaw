# Shared sandbox contracts

DefenseClaw owns policy, approvals, agent hooks, credentials, workspace review
and audit. A runtime adapter supplies qualified execution and transport beneath
that control plane. The current OpenShell controller remains compatible;
these declarations do not enable AXIS or start background work.

`ResolveExecutionPolicy` accepts a stable validated configuration snapshot and
the existing pack resolver inputs. It projects common sandbox policy, applies
repository and administrative restrictions, then freezes every shared setting
and the resolved run into one immutable identity. Its host authority snapshot
ID and generation must rotate when broker routing or host facts change.

The private resolver remains the egress authority. Inspection JSON deliberately
omits host facts and cannot reconstruct an executable policy. An adapter must
route authorized traffic through DefenseClaw's broker; copying a flattened
allowlist into MXC does not reproduce approvals or administrative enforcement.
Explicit offline execution is separate from the `strict` profile.

Before execution, the host must independently qualify exact runtime and harness
artifacts and require the policy's capabilities. `AdmitPolicy` also requires a
trusted translation receipt bound to that runtime, harness, policy digest and
every policy component. Missing, duplicated, changed or unknown components
refuse admission. Evidence from a workload or API client is never authoritative.

A receipt checks structural consistency. It grants no process launch,
credential, workspace path or lifecycle authority. The controller must still
enforce session ownership, current policy generation, credential binding and
the adapter's actual enforcement evidence on every relevant operation. No
refusal may silently select a different backend or execute on the host.
