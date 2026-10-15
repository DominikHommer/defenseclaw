# Requirements — Edge Connector Distribution and Fleet Provisioning

## 1. Binary Distribution

**REQ-01:** The CI pipeline SHALL produce pre-built Edge Connector binaries for
linux/amd64, linux/arm64, and linux/armhf on every tagged release.

**REQ-02:** Each release binary SHALL be stripped, statically linked (musl libc),
and include the STANDARD profile with mbedTLS for production TLS.

**REQ-03:** Release binaries SHALL be published to GitHub Releases with SHA-256
checksums and Cosign signatures.

**REQ-04:** A container image SHALL be published to GitHub Container Registry
(ghcr.io) containing the Edge Connector binary, policy compiler, and a minimal
Alpine base. Multi-arch (amd64, arm64, armhf).

**REQ-05:** An install script SHALL be provided that detects the platform,
downloads the correct binary, verifies the checksum, and installs to
`/usr/local/bin/edge-connector`.

```bash
curl -fsSL https://get.defenseclaw.dev/edge | sh
```

**REQ-06:** DEB and RPM packages SHALL be produced for Debian/Ubuntu (arm64,
armhf, amd64) and RHEL/Fedora (aarch64, x86_64). Packages SHALL include the
systemd service unit, env template, and policy compiler.

## 2. Configuration

**REQ-07:** The release SHALL include an env template file at
`/etc/defenseclaw/edge-connector.env.template` with commented defaults for
every required and optional environment variable.

**REQ-08:** The Edge Connector binary SHALL support a `--validate` flag that
checks all required environment variables, file paths, key formats, MQTT
connectivity, and IPC socket creation without starting the daemon. Exit 0 on
success, exit 1 with specific error messages on failure.

**REQ-09:** The `--validate` output SHALL name each missing or invalid variable
with its expected format, e.g.:
```
ERROR: DCLAW_AUDIT_KEY is not set. Generate with: python3 -c "import secrets; print(secrets.token_hex(32))"
ERROR: DCLAW_BROKER_URL must use mqtts:// in production mode.
OK: DCLAW_FLASH_PATH=/var/lib/defenseclaw/flash (writable)
```

**REQ-10:** A `defenseclaw edge-connector init` CLI command SHALL generate all
required keys, write the env file, create directories, and register the device
with the fleet API in a single interactive or non-interactive flow.

**REQ-11:** Device keys returned by the fleet registration API SHALL be
retrievable via `GET /api/v1/fleet/devices/{id}` with admin credentials, not
limited to the one-time registration response.

## 3. Fleet Provisioning

**REQ-12:** A bulk provisioning API endpoint SHALL accept a list of device
descriptors and return device IDs + keys for all of them in a single request:
```
POST /api/v1/fleet/devices/bulk-register
[{tenant_id, fleet_id, device_id, hw_profile, ...}, ...]
→ [{device_id, device_key}, ...]
```

**REQ-13:** An Ansible role SHALL be provided that installs the Edge Connector
on a fleet of Linux devices. The role SHALL support:
- Binary installation (from package or direct download)
- Key generation and env file provisioning
- Device registration with the fleet API
- Systemd service enablement
- Smoke test (validate flag)

**REQ-14:** A Terraform provider or provisioner SHALL be provided for
infrastructure-as-code deployments that creates fleet devices and outputs
device keys for injection into VM/container provisioning.

**REQ-15:** The `defenseclaw edge-connector install` CLI command SHALL support
batch mode: `--targets-file hosts.txt` that reads a list of SSH targets and
deploys to all of them in parallel (configurable concurrency).

## 4. Runtime Management

**REQ-16:** The Edge Connector SHALL expose a health check endpoint on the IPC
socket that returns JSON with version, uptime, policy version, MQTT connection
status, audit chain integrity, and last heartbeat timestamp.

```json
{"status":"healthy","version":"1.0.0","uptime_sec":3600,
 "policy_version":3,"mqtt_connected":true,"audit_chain_valid":true,
 "last_heartbeat":"2026-10-15T10:00:00Z"}
```

**REQ-17:** The health check SHALL be queryable via:
- IPC socket: `echo '{"method":"health"}' | nc -U /run/defenseclaw/defenseclaw.sock`
- HTTP (optional, configurable): `GET http://localhost:9090/healthz`

**REQ-18:** The fleet API SHALL expose a device status endpoint that aggregates
health from heartbeats: `GET /api/v1/fleet/devices/{id}/status` returning
online/offline, last heartbeat, policy version, denied/allowed counts, and
any active alerts.

**REQ-19:** A `defenseclaw edge-connector status` CLI command SHALL query the
fleet API and display a table of all devices with their health status, policy
version, and last heartbeat age.

**REQ-20:** The Edge Connector SHALL support in-place binary updates via a
new `--upgrade` flag that downloads the latest binary for the current platform,
verifies the checksum, replaces itself, and restarts the systemd service.

## 5. OTA and Key Management

**REQ-21:** Device key rotation SHALL be triggerable via the fleet API
(`POST /api/v1/fleet/devices/{id}/rotate-key`) and the new key SHALL be
delivered to the device via MQTT. The device SHALL accept the new key and
acknowledge within 30 seconds.

**REQ-22:** Bulk key rotation SHALL be supported:
`POST /api/v1/fleet/devices/rotate-keys` with a list of device IDs.

**REQ-23:** OTA policy updates SHALL include a rollback sequence number so
devices can detect and report missed updates, and the fleet manager can
re-push missing versions.

## 6. Observability

**REQ-24:** The Edge Connector SHALL export Prometheus metrics at
`GET /metrics` (optional HTTP listener) or via the heartbeat payload:
- `edge_connector_verdicts_total{action}` — allow/block/warn counts
- `edge_connector_latency_seconds` — verdict latency histogram
- `edge_connector_cache_hit_ratio` — verdict cache effectiveness
- `edge_connector_mqtt_reconnects_total` — MQTT stability

**REQ-25:** The fleet API SHALL expose a fleet-wide dashboard endpoint
`GET /api/v1/fleet/dashboard` that aggregates device metrics for Grafana
without requiring per-device scraping.

## 7. Documentation

**REQ-26:** A single unified installation guide SHALL exist at
`docs-site/content/docs/edge-connector/install.mdx` that covers source build,
binary install, container, package, and fleet provisioning. INSTALL.md and
README-RASPBERRY-PI.md SHALL redirect to this single source.

**REQ-27:** The install guide SHALL include a "5-minute quickstart" section
that gets a user from zero to a working device with the minimum viable
configuration (dev mode, local Mosquitto, no TLS).

**REQ-28:** The install guide SHALL include a "production deployment" section
that covers TLS, key management, systemd hardening, and fleet provisioning
with Ansible.

## Acceptance Criteria

| AC | Requirement | Verification |
|----|-------------|--------------|
| AC-01 | REQ-01,02,03 | `gh release download v1.x --pattern 'edge-connector-*'` succeeds for 3 platforms |
| AC-02 | REQ-04 | `docker run ghcr.io/cisco-ai-defense/edge-connector --version` prints version |
| AC-03 | REQ-05 | `curl ... \| sh` installs on a clean Ubuntu 22.04 arm64 |
| AC-04 | REQ-06 | `apt-get install defenseclaw-edge-connector` works on Pi OS |
| AC-05 | REQ-07,08,09 | `edge-connector --validate` reports missing DCLAW_AUDIT_KEY |
| AC-06 | REQ-10 | `defenseclaw edge-connector init --non-interactive` creates all files |
| AC-07 | REQ-12 | Bulk register 100 devices in <5 seconds |
| AC-08 | REQ-13 | Ansible playbook deploys to 10 Pis with zero manual steps |
| AC-09 | REQ-16,17 | Health check returns JSON with all fields |
| AC-10 | REQ-20 | `edge-connector --upgrade` replaces binary and restarts |
| AC-11 | REQ-26,27 | New user follows quickstart → working device in <5 minutes |
| AC-12 | REQ-28 | Ops team follows production guide → 100 devices in <1 hour |
