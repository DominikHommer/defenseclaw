# Spec 008 — Edge Connector Distribution and Fleet Provisioning

**Status:** Draft
**Author:** nghodki
**Date:** 2026-10-15

The Edge Connector is technically powerful but nearly impossible to deploy
at scale. A user targeting 100 Raspberry Pis must clone a 500MB repo,
cross-compile C on each device, hand-craft 8 environment variables, and
SSH into every device individually. There are no pre-built binaries, no
container images, no package manager integration, and no fleet provisioning
tooling.

This spec defines the distribution pipeline, installation experience, and
fleet provisioning workflow needed to make the Edge Connector deployable
by operations teams — not just embedded engineers.

## Current State (Pain Points)

| Area | Score | Issue |
|------|-------|-------|
| Binary distribution | 1/5 | Source-only; must compile on each device |
| Configuration | 1/5 | 8 env vars, no template, unforgiving key flow |
| Fleet deployment | 2/5 | SSH-only; no IaC, containers, or packages |
| Runtime management | 2/5 | Limited observability, no health endpoint |
| Documentation | 2/5 | Split across MDX, INSTALL.md, README.md |

## Target State

| Area | Target | How |
|------|--------|-----|
| Binary distribution | 4/5 | Pre-built binaries + container image + packages |
| Configuration | 4/5 | Template, validation, guided setup |
| Fleet deployment | 4/5 | Ansible playbook, bulk provisioning API |
| Runtime management | 4/5 | Health endpoint, status API, OTA updates |
| Documentation | 5/5 | Single unified install guide |

## Spec Files

- [Requirements](requirements.md) — 28 requirements across 7 areas
- [Design](design.md) — Architecture, APIs, packaging, fleet provisioning
- [Plan](plan.md) — 4-phase rollout with milestones
- [Tasks](tasks.md) — 22 ordered implementation tasks
