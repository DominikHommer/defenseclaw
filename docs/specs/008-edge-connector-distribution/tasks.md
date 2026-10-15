# Tasks — Edge Connector Distribution and Fleet Provisioning

## Phase 1: Binary Distribution

### T-01: Cross-compilation CI workflow
**Maps to:** REQ-01, REQ-02
**Effort:** 2 days

Create `.github/workflows/edge-connector-release.yml` that:
- Installs musl cross-toolchains for amd64, arm64, armhf
- Builds mbedTLS 3.6 as a static library per architecture
- Compiles edge-connector with STANDARD profile and DEV_MODE=OFF
- Strips binaries
- Produces `edge-connector-linux-{arch}.tar.gz` artifacts

**Files:**
- `.github/workflows/edge-connector-release.yml` (new)
- `edge-connector/CMakeLists.txt` (add musl toolchain file include)
- `edge-connector/cmake/toolchain-*.cmake` (new, per arch)

**Test:** CI produces 3 binaries; arm64 binary runs on Pi 4.

---

### T-02: GitHub Release publishing
**Maps to:** REQ-03
**Effort:** 1 day

Add edge-connector artifacts to `.goreleaser.yaml` release flow:
- Upload tar.gz files to GitHub Releases
- Generate and upload `checksums.txt`
- Sign with Cosign

**Files:**
- `.goreleaser.yaml` (add edge-connector section)

**Test:** `gh release download v1.x --pattern 'edge-connector-*'` succeeds.

---

### T-03: Install script
**Maps to:** REQ-05
**Effort:** 1 day

Create `scripts/get-edge-connector.sh`:
- Detect architecture via `uname -m`
- Download correct binary from GitHub Releases
- Verify SHA-256 checksum
- Install to `/usr/local/bin/`
- Copy systemd service and env template
- Create defenseclaw user and directories

**Files:**
- `scripts/get-edge-connector.sh` (new)

**Test:** `curl -fsSL .../get-edge-connector.sh | sh` on clean Ubuntu arm64.

---

### T-04: Env template file
**Maps to:** REQ-07
**Effort:** 0.5 days

Create `/etc/defenseclaw/edge-connector.env.template` with all required and
optional variables, commented defaults, and generation instructions.

**Files:**
- `edge-connector/packaging/edge-connector.env.template` (new)

**Test:** Template contains all 8 required vars with help text.

---

### T-05: `--validate` flag
**Maps to:** REQ-08, REQ-09
**Effort:** 2 days

Add `--validate` to `edge-connector` main.c:
- Check all required env vars (format, non-empty)
- Verify DCLAW_FLASH_PATH is writable
- Verify DCLAW_BROKER_URL is reachable (TCP connect, optional TLS handshake)
- Verify IPC socket directory exists
- Print colored per-check results
- Exit 0 on all pass, exit 1 on any failure

**Files:**
- `edge-connector/src/main.c` (add validate mode)
- `edge-connector/src/validate.c` (new)
- `edge-connector/tests/test_validate.c` (new)

**Test:** `edge-connector --validate` with missing DCLAW_AUDIT_KEY prints specific error.

---

## Phase 2: Packaging

### T-06: DEB package
**Maps to:** REQ-06
**Effort:** 2 days

Create `edge-connector/packaging/debian/` with control, postinst, prerm,
conffiles. Build with `dpkg-deb` in CI.

**Files:**
- `edge-connector/packaging/debian/control` (new)
- `edge-connector/packaging/debian/postinst` (new)
- `edge-connector/packaging/debian/prerm` (new)
- `edge-connector/packaging/debian/conffiles` (new)
- `.github/workflows/edge-connector-release.yml` (add deb step)

**Test:** `dpkg -i defenseclaw-edge-connector_1.0.0_arm64.deb` on Pi OS.

---

### T-07: RPM package
**Maps to:** REQ-06
**Effort:** 1 day

Create `edge-connector/packaging/rpm/edge-connector.spec`. Build with
`rpmbuild` in CI.

**Files:**
- `edge-connector/packaging/rpm/edge-connector.spec` (new)

**Test:** `rpm -ivh defenseclaw-edge-connector-1.0.0.aarch64.rpm` on Fedora.

---

### T-08: Container image
**Maps to:** REQ-04
**Effort:** 1 day

Create multi-arch Dockerfile and add `docker buildx` step to CI.

**Files:**
- `edge-connector/Dockerfile` (new)
- `.github/workflows/edge-connector-release.yml` (add docker step)

**Test:** `docker run --rm ghcr.io/cisco-ai-defense/edge-connector --version`.

---

## Phase 3: Fleet Provisioning

### T-09: Bulk registration API
**Maps to:** REQ-12
**Effort:** 2 days

Add `POST /api/v1/fleet/devices/bulk-register` to `internal/fleet/api.go`.
Accept array of device descriptors, register all, return array of IDs+keys.
Cap at 1000 devices per request.

**Files:**
- `internal/fleet/api.go` (add handler)
- `internal/fleet/api_test.go` (add test)

**Test:** Register 100 devices in single request, verify all keys unique.

---

### T-10: Device key retrieval API
**Maps to:** REQ-11
**Effort:** 1 day

Make device key retrievable via `GET /api/v1/fleet/devices/{id}` when
authenticated as admin. Currently the key is only in the registration response.

**Files:**
- `internal/fleet/api.go` (modify getDevice handler)

**Test:** Register device, retrieve key via GET, keys match.

---

### T-11: Ansible role
**Maps to:** REQ-13
**Effort:** 3 days

Create `edge-connector/ansible/` with:
- `roles/defenseclaw-edge-connector/tasks/main.yml`
- `roles/defenseclaw-edge-connector/templates/edge-connector.env.j2`
- `roles/defenseclaw-edge-connector/defaults/main.yml`
- `roles/defenseclaw-edge-connector/handlers/main.yml`
- Example `inventory.ini` and `playbook.yml`

**Files:**
- `edge-connector/ansible/` (new directory, ~8 files)

**Test:** Deploy to 3 test Pis with `ansible-playbook -i inventory playbook.yml`.

---

### T-12: `defenseclaw edge-connector init`
**Maps to:** REQ-10
**Effort:** 2 days

Add guided setup command that generates keys, writes env file, registers
device, validates config, and starts service.

**Files:**
- `cli/defenseclaw/commands/cmd_edge_connector_cli.py` (add init subcommand)

**Test:** `defenseclaw edge-connector init --non-interactive` creates working device.

---

### T-13: Batch CLI deploy
**Maps to:** REQ-15
**Effort:** 2 days

Add `--targets-file` support to `defenseclaw edge-connector install` that
reads SSH targets from a file and deploys in parallel.

**Files:**
- `cli/defenseclaw/commands/cmd_edge_install.py` (add batch mode)

**Test:** Deploy to 5 targets from file with `--concurrency 3`.

---

### T-14: Fleet status CLI
**Maps to:** REQ-19
**Effort:** 1 day

Add `defenseclaw edge-connector status` that queries fleet API and displays
device table with health.

**Files:**
- `cli/defenseclaw/commands/cmd_edge_connector_cli.py` (add status subcommand)

**Test:** Shows table with device ID, status, policy version, last heartbeat.

---

## Phase 4: Observability and Updates

### T-15: IPC health check
**Maps to:** REQ-16
**Effort:** 2 days

Add `{"method":"health"}` handler to the IPC event loop in main.c.
Return JSON with version, uptime, policy, MQTT status, audit chain, cache stats.

**Files:**
- `edge-connector/src/main.c` (add health handler)
- `edge-connector/tests/test_health.c` (new)

**Test:** `echo '{"method":"health"}' | nc -U /run/defenseclaw/defenseclaw.sock` returns JSON.

---

### T-16: Optional HTTP health endpoint
**Maps to:** REQ-17
**Effort:** 1 day

When `DCLAW_HEALTH_PORT` is set, start a minimal HTTP listener that serves
`GET /healthz` using the same data as the IPC health check.

**Files:**
- `edge-connector/src/health_http.c` (new)
- `edge-connector/CMakeLists.txt` (add source)

**Test:** `curl http://localhost:9090/healthz` returns 200 with JSON.

---

### T-17: Fleet dashboard API
**Maps to:** REQ-25
**Effort:** 1 day

Add `GET /api/v1/fleet/dashboard` that aggregates device metrics from
heartbeats into a single summary.

**Files:**
- `internal/fleet/api.go` (add handler)

**Test:** Dashboard shows correct totals for 10 devices with mixed status.

---

### T-18: Device status API
**Maps to:** REQ-18
**Effort:** 1 day

Add `GET /api/v1/fleet/devices/{id}/status` that returns detailed device
health from the last heartbeat.

**Files:**
- `internal/fleet/api.go` (add handler)

**Test:** Returns online/offline, last heartbeat, policy version, counters.

---

### T-19: Self-update mechanism
**Maps to:** REQ-20
**Effort:** 2 days

Add `--upgrade` flag to edge-connector that:
1. Queries GitHub Releases API for latest version
2. Compares with current version
3. Downloads platform-specific binary
4. Verifies checksum
5. Atomic rename to replace current binary
6. Triggers systemd restart

**Files:**
- `edge-connector/src/upgrade.c` (new)
- `edge-connector/tests/test_upgrade.c` (new)

**Test:** `edge-connector --upgrade` from v1.0.0 to v1.0.1 succeeds.

---

### T-20: Unified documentation
**Maps to:** REQ-26, REQ-27, REQ-28
**Effort:** 2 days

Rewrite `docs-site/content/docs/edge-connector/install.mdx` as the single
source of truth. Add quickstart section (5 minutes), production section,
fleet provisioning section. Make INSTALL.md and README redirect to it.

**Files:**
- `docs-site/content/docs/edge-connector/install.mdx` (rewrite)
- `edge-connector/INSTALL.md` (redirect)
- `edge-connector/README.md` (redirect)
- `edge-connector/README-RASPBERRY-PI.md` (redirect)

**Test:** New user follows quickstart → working device in <5 minutes.

---

### T-21: Bulk key rotation API
**Maps to:** REQ-21, REQ-22
**Effort:** 2 days

Add `POST /api/v1/fleet/devices/rotate-keys` that rotates keys for
a list of device IDs and delivers new keys via MQTT.

**Files:**
- `internal/fleet/api.go` (add handler)
- `edge-connector/src/comms/ota_receiver.c` (add key rotation handler)

**Test:** Rotate keys for 10 devices, all acknowledge within 30 seconds.

---

### T-22: Prometheus metrics export
**Maps to:** REQ-24
**Effort:** 1 day

When `DCLAW_HEALTH_PORT` is set, serve `GET /metrics` in Prometheus
exposition format alongside `/healthz`.

**Files:**
- `edge-connector/src/health_http.c` (add /metrics handler)

**Test:** Prometheus can scrape `http://device:9090/metrics`.

---

## Summary

| Phase | Tasks | Effort | Deliverables |
|-------|-------|--------|--------------|
| 1 | T-01 to T-05 | 6.5 days | Binaries, install script, validate, env template |
| 2 | T-06 to T-08 | 4 days | DEB, RPM, container image |
| 3 | T-09 to T-14 | 11 days | Bulk API, Ansible, CLI init/batch/status |
| 4 | T-15 to T-22 | 12 days | Health, dashboard, self-update, docs, metrics |
| **Total** | **22 tasks** | **~33.5 days** | **Full distribution pipeline** |
