# Plan — Edge Connector Distribution and Fleet Provisioning

## Phase 1: Binary Distribution (1 week)

**Goal:** Users can install the Edge Connector without compiling from source.

### Deliverables
1. Cross-compilation CI workflow producing linux/{amd64,arm64,armhf} binaries
2. GitHub Release artifacts with SHA-256 checksums
3. One-liner install script (`curl | sh`)
4. Env template file shipped with binary
5. `--validate` flag for pre-start configuration checking

### Success Criteria
- `curl -fsSL https://get.defenseclaw.dev/edge | sh` installs on clean Pi OS
- `edge-connector --validate` reports all missing/invalid configuration
- Binary is <400KB statically linked with mbedTLS

### Risks
- musl cross-compilation may have mbedTLS compatibility issues
- ARM hardfloat vs softfloat ABI mismatch on older Pis

---

## Phase 2: Packaging and Containers (1 week)

**Goal:** Standard Linux package managers and container orchestrators work.

### Deliverables
1. DEB package for Debian/Ubuntu (arm64, armhf, amd64)
2. RPM package for RHEL/Fedora (aarch64, x86_64)
3. Multi-arch Docker image on GHCR
4. Dockerfile with HEALTHCHECK
5. Package postinst creates user, directories, enables systemd

### Success Criteria
- `apt-get install defenseclaw-edge-connector` works on Pi OS
- `docker run ghcr.io/cisco-ai-defense/edge-connector --version` works
- Package upgrade preserves /etc/defenseclaw/edge-connector.env

### Risks
- Package signing keys need provisioning
- ARM Docker builds are slow in CI (use QEMU or native runners)

---

## Phase 3: Fleet Provisioning (2 weeks)

**Goal:** Deploy to 100 devices in under 1 hour with zero manual steps per device.

### Deliverables
1. Bulk registration API endpoint
2. Device key retrieval API (admin-only)
3. Ansible role with full lifecycle
4. Batch CLI deploy (`--targets-file`)
5. `defenseclaw edge-connector init` guided setup
6. Fleet status CLI command

### Success Criteria
- Ansible playbook deploys to 10 Pis with zero manual steps
- Bulk registration creates 100 devices in <5 seconds
- `defenseclaw edge-connector status` shows all devices with health

### Risks
- SSH key management across fleet
- Network partitions during batch deployment
- Device ID assignment strategy for large fleets

---

## Phase 4: Observability and Updates (1 week)

**Goal:** Running devices are visible, healthy, and updatable.

### Deliverables
1. IPC health check endpoint
2. Optional HTTP /healthz for Kubernetes probes
3. Fleet dashboard API
4. Self-update mechanism (`--upgrade`)
5. Unified documentation (single install.mdx)

### Success Criteria
- Health check returns JSON with all fields within 100ms
- Self-update downloads, verifies, replaces, and restarts cleanly
- Single install guide covers all 5 installation methods

### Risks
- Self-update on constrained devices (disk space for two binaries)
- Health endpoint on devices without network (IPC-only)

---

## Timeline

```
Week 1:  Phase 1 — Binary distribution + install script
Week 2:  Phase 2 — DEB/RPM packages + container image
Week 3:  Phase 3a — Bulk API + Ansible role
Week 4:  Phase 3b — CLI batch deploy + guided init
Week 5:  Phase 4 — Health checks + self-update + docs
```

## Scope Boundaries

**In scope:**
- Linux targets only (amd64, arm64, armhf)
- Ansible as the IaC tool (most common for IoT)
- GitHub Releases as the distribution channel
- GHCR as the container registry

**Out of scope:**
- Windows/macOS Edge Connector builds
- Terraform provider (future spec)
- Puppet/Chef/Salt modules
- Custom APT/YUM repository hosting (use GitHub Releases)
- Kubernetes operator for edge connector fleet
- Secure boot chain verification

## Observability Plan

| Metric | Type | When |
|--------|------|------|
| `edge_install_total` | Counter | CLI install completes |
| `edge_install_duration_seconds` | Histogram | CLI install timing |
| `edge_validate_errors_total` | Counter | --validate finds issues |
| `edge_health_checks_total` | Counter | Health endpoint queries |
| `edge_upgrade_total` | Counter | Self-update attempts |
| `edge_bulk_register_total` | Counter | Bulk registration calls |
