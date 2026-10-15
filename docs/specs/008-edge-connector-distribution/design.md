# Design — Edge Connector Distribution and Fleet Provisioning

## 1. Architecture Overview

```
┌──────────────────────────────────────────────────────────────────┐
│                    CI/CD Pipeline (GitHub Actions)                │
│                                                                  │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────────────┐  │
│  │ Cross-compile│  │ Package      │  │ Publish                │  │
│  │ C binary     │  │ DEB/RPM/     │  │ GitHub Releases        │  │
│  │ (musl libc)  │  │ Container    │  │ GHCR container         │  │
│  │              │  │              │  │ APT/YUM repo           │  │
│  │ Platforms:   │  │ Includes:    │  │                        │  │
│  │  linux/amd64 │  │  binary      │  │ Artifacts:             │  │
│  │  linux/arm64 │  │  systemd svc │  │  edge-connector-{os}-  │  │
│  │  linux/armhf │  │  env template│  │   {arch}.tar.gz        │  │
│  │              │  │  policy_comp │  │  checksums.txt          │  │
│  │              │  │  man page    │  │  checksums.txt.sig     │  │
│  └─────────────┘  └──────────────┘  └────────────────────────┘  │
└──────────────────────────────────────────────────────────────────┘
         │                    │                     │
         ▼                    ▼                     ▼
┌──────────────────────────────────────────────────────────────────┐
│                    Installation Methods                           │
│                                                                  │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────────────┐  │
│  │ One-liner    │  │ Package mgr  │  │ Container              │  │
│  │ curl | sh    │  │ apt/yum      │  │ docker run             │  │
│  │              │  │              │  │ k3s/podman             │  │
│  │ Detects arch │  │ Auto-updates │  │                        │  │
│  │ Checksums    │  │ Dependencies │  │ Multi-arch             │  │
│  │ Install bin  │  │ systemd      │  │ /healthz built-in     │  │
│  └─────────────┘  └──────────────┘  └────────────────────────┘  │
│                                                                  │
│  ┌─────────────┐  ┌──────────────┐  ┌────────────────────────┐  │
│  │ Ansible role │  │ CLI install  │  │ Source build           │  │
│  │ (fleet)      │  │ (single dev) │  │ (development)          │  │
│  │              │  │              │  │                        │  │
│  │ hosts.ini    │  │ --target ssh │  │ cmake && make          │  │
│  │ group_vars   │  │ --batch file │  │                        │  │
│  │ register API │  │              │  │                        │  │
│  └─────────────┘  └──────────────┘  └────────────────────────┘  │
└──────────────────────────────────────────────────────────────────┘
         │
         ▼
┌──────────────────────────────────────────────────────────────────┐
│                    Fleet Provisioning                             │
│                                                                  │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │ Gateway Fleet API                                           │ │
│  │                                                             │ │
│  │ POST /devices/bulk-register  ──▶ [{id, key}, ...]          │ │
│  │ GET  /devices/{id}           ──▶ {status, key, health}     │ │
│  │ GET  /devices/{id}/status    ──▶ {online, heartbeat, ...}  │ │
│  │ POST /devices/rotate-keys    ──▶ bulk key rotation         │ │
│  │ GET  /fleet/dashboard        ──▶ aggregated fleet metrics  │ │
│  └─────────────────────────────────────────────────────────────┘ │
│                                                                  │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────────────────┐ │
│  │ Device init   │  │ Health check │  │ OTA update             │ │
│  │ edge-connector│  │ /healthz     │  │ --upgrade              │ │
│  │   init        │  │ IPC health   │  │ fleet push             │ │
│  │   --validate  │  │ heartbeat    │  │ key rotation           │ │
│  └──────────────┘  └──────────────┘  └────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
```

## 2. Cross-Compilation Pipeline

### 2.1 Build Matrix

| Target | Toolchain | mbedTLS | Libc | Binary Size |
|--------|-----------|---------|------|-------------|
| linux/amd64 | x86_64-linux-musl-gcc | 3.6.x (static) | musl | ~350KB |
| linux/arm64 | aarch64-linux-musl-gcc | 3.6.x (static) | musl | ~320KB |
| linux/armhf | arm-linux-musleabihf-gcc | 3.6.x (static) | musl | ~310KB |

### 2.2 CI Workflow

```yaml
# .github/workflows/edge-connector-release.yml
jobs:
  build-edge-connector:
    strategy:
      matrix:
        include:
          - os: linux
            arch: amd64
            cc: x86_64-linux-musl-gcc
          - os: linux
            arch: arm64
            cc: aarch64-linux-musl-gcc
          - os: linux
            arch: armhf
            cc: arm-linux-musleabihf-gcc
    steps:
      - uses: actions/checkout@v5
      - name: Install musl cross toolchain
        run: |
          sudo apt-get install -y musl-tools gcc-aarch64-linux-gnu gcc-arm-linux-gnueabihf
      - name: Build mbedTLS (static)
        run: |
          cmake -S third_party/mbedtls -B mbedtls-build \
            -DCMAKE_C_COMPILER=${{ matrix.cc }} \
            -DCMAKE_BUILD_TYPE=Release \
            -DENABLE_TESTING=OFF -DENABLE_PROGRAMS=OFF
          cmake --build mbedtls-build -j$(nproc)
      - name: Build Edge Connector
        run: |
          cmake -S edge-connector -B build \
            -DCMAKE_C_COMPILER=${{ matrix.cc }} \
            -DCMAKE_BUILD_TYPE=Release \
            -DDCLAW_PROFILE=STANDARD \
            -DDCLAW_DEV_MODE=OFF \
            -DCMAKE_PREFIX_PATH=$(pwd)/mbedtls-build
          cmake --build build -j$(nproc)
          strip build/edge-connector
      - name: Package
        run: |
          tar -czf edge-connector-${{ matrix.os }}-${{ matrix.arch }}.tar.gz \
            -C build edge-connector \
            -C ../edge-connector/packaging edge-connector.service \
            -C ../edge-connector/tools policy_compiler.py
          sha256sum *.tar.gz > checksums.txt
```

### 2.3 Container Image

```dockerfile
# edge-connector/Dockerfile
FROM alpine:3.20 AS base
RUN addgroup -S defenseclaw && adduser -S defenseclaw -G defenseclaw

COPY --chown=defenseclaw:defenseclaw edge-connector /usr/local/bin/
COPY --chown=defenseclaw:defenseclaw policy_compiler.py /usr/local/lib/defenseclaw/
COPY --chown=defenseclaw:defenseclaw edge-connector.env.template /etc/defenseclaw/

RUN mkdir -p /var/lib/defenseclaw && chown defenseclaw:defenseclaw /var/lib/defenseclaw

USER defenseclaw
EXPOSE 9090
HEALTHCHECK --interval=30s --timeout=5s \
  CMD echo '{"method":"health"}' | nc -U /run/defenseclaw/defenseclaw.sock || exit 1

ENTRYPOINT ["/usr/local/bin/edge-connector"]
```

Multi-arch build via `docker buildx`:
```bash
docker buildx build --platform linux/amd64,linux/arm64,linux/arm/v7 \
  -t ghcr.io/cisco-ai-defense/edge-connector:1.0.0 --push .
```

## 3. Installation Methods

### 3.1 One-Liner Install Script

```bash
#!/bin/sh
# get-edge-connector.sh
set -eu

VERSION="${DCLAW_VERSION:-latest}"
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64)  ARCH="amd64" ;;
  aarch64) ARCH="arm64" ;;
  armv7l)  ARCH="armhf" ;;
  *) echo "Unsupported architecture: $ARCH" >&2; exit 1 ;;
esac

DOWNLOAD_URL="https://github.com/cisco-ai-defense/defenseclaw/releases/${VERSION}/download/edge-connector-linux-${ARCH}.tar.gz"
CHECKSUM_URL="https://github.com/cisco-ai-defense/defenseclaw/releases/${VERSION}/download/checksums.txt"

echo "Downloading edge-connector for linux/${ARCH}..."
curl -fsSL "$DOWNLOAD_URL" -o /tmp/edge-connector.tar.gz
curl -fsSL "$CHECKSUM_URL" -o /tmp/checksums.txt

echo "Verifying checksum..."
cd /tmp && sha256sum --check --ignore-missing checksums.txt

echo "Installing..."
sudo tar -xzf /tmp/edge-connector.tar.gz -C /usr/local/bin/ edge-connector
sudo install -m 644 /tmp/edge-connector.service /etc/systemd/system/
sudo install -m 600 /tmp/edge-connector.env.template /etc/defenseclaw/edge-connector.env
sudo mkdir -p /var/lib/defenseclaw
sudo useradd -r -s /usr/sbin/nologin defenseclaw 2>/dev/null || true
sudo chown defenseclaw:defenseclaw /var/lib/defenseclaw

echo "Installed edge-connector $(edge-connector --version)"
echo ""
echo "Next steps:"
echo "  1. Edit /etc/defenseclaw/edge-connector.env"
echo "  2. Run: edge-connector --validate"
echo "  3. Run: sudo systemctl enable --now edge-connector"
```

### 3.2 DEB Package Structure

```
defenseclaw-edge-connector_1.0.0_arm64.deb
├── DEBIAN/
│   ├── control
│   ├── postinst     # Create user, directories, enable systemd
│   ├── prerm        # Stop service
│   └── conffiles    # Mark /etc/defenseclaw/edge-connector.env as conffile
├── usr/local/bin/edge-connector
├── usr/local/lib/defenseclaw/policy_compiler.py
├── etc/defenseclaw/edge-connector.env.template
├── etc/systemd/system/edge-connector.service
└── usr/share/doc/defenseclaw-edge-connector/
    └── README.md
```

### 3.3 Env Template

```bash
# /etc/defenseclaw/edge-connector.env.template
#
# Copy to /etc/defenseclaw/edge-connector.env and fill in values.
# Generate keys with: python3 -c "import secrets; print(secrets.token_hex(32))"
#

# --- Required ---
DCLAW_AUDIT_KEY=           # 32-byte hex HMAC key for tamper-evident audit chain
DCLAW_OTA_KEY=             # 32-byte hex key for OTA policy signature verification
DCLAW_DEVICE_KEY=          # 32-byte hex per-device key (from fleet registration)
DCLAW_BROKER_URL=          # mqtts://broker:8883 (TLS required in production)

# --- Device Identity ---
DCLAW_TENANT_ID=1          # Tenant identifier
DCLAW_FLEET_ID=1           # Fleet identifier
DCLAW_DEVICE_ID=           # Unique device ID (integer)

# --- Optional ---
# DCLAW_EMERGENCY_KEY=     # Separate key for emergency commands (defaults to OTA key)
# DCLAW_FLASH_PATH=/var/lib/defenseclaw/flash
# DCLAW_IPC_SOCKET_PATH=/run/defenseclaw/defenseclaw.sock
# DCLAW_LOG_LEVEL=1        # 0=error, 1=warn, 2=info, 3=debug
```

## 4. Configuration Validation

### 4.1 `--validate` Flag

```
$ edge-connector --validate

DefenseClaw Edge Connector v1.0.0 — Configuration Validation

  ✓ DCLAW_AUDIT_KEY          32-byte hex key loaded
  ✓ DCLAW_OTA_KEY            32-byte hex key loaded
  ✓ DCLAW_DEVICE_KEY         32-byte hex key loaded
  ✓ DCLAW_BROKER_URL         mqtts://broker.example.com:8883
  ✗ DCLAW_BROKER_URL         TLS connection failed: certificate verify failed
  ✓ DCLAW_TENANT_ID          1
  ✓ DCLAW_FLEET_ID           1
  ✓ DCLAW_DEVICE_ID          42
  ✓ DCLAW_FLASH_PATH         /var/lib/defenseclaw/flash (writable)
  ✓ IPC socket               /run/defenseclaw/defenseclaw.sock (directory exists)
  ✓ Systemd service          edge-connector.service (enabled)

  Result: 1 error — fix DCLAW_BROKER_URL TLS configuration
```

### 4.2 `defenseclaw edge-connector init`

Interactive guided setup:

```
$ defenseclaw edge-connector init

DefenseClaw Edge Connector Setup
═════════════════════════════════

Fleet API endpoint: http://gateway.example.com:18970
Fleet API token: ****

Generating cryptographic keys...
  ✓ Audit key:     a1b2c3d4... (written to /etc/defenseclaw/edge-connector.env)
  ✓ OTA key:       e5f6a7b8... (written to /etc/defenseclaw/edge-connector.env)

MQTT broker URL: mqtts://broker.example.com:8883

Device identity:
  Tenant ID [1]: 1
  Fleet ID  [1]: 1
  Device ID: 42

Registering device with fleet API...
  ✓ Device 42 registered (key: c9d0e1f2...)
  ✓ Device key written to /etc/defenseclaw/edge-connector.env

Validating configuration...
  ✓ All checks passed

Start the service now? [Y/n] y
  ✓ edge-connector.service enabled and started
  ✓ First heartbeat sent

Done! Your device is now protected by DefenseClaw.
```

## 5. Fleet Provisioning

### 5.1 Bulk Registration API

```
POST /api/v1/fleet/devices/bulk-register
Content-Type: application/json
Authorization: Bearer <admin-token>
X-DefenseClaw-Client: ansible

[
  {"tenant_id":1, "fleet_id":1, "device_id":1, "hw_profile":"rpi4"},
  {"tenant_id":1, "fleet_id":1, "device_id":2, "hw_profile":"rpi4"},
  ...
  {"tenant_id":1, "fleet_id":1, "device_id":100, "hw_profile":"rpi4"}
]

→ 201 Created
{
  "registered": 100,
  "devices": [
    {"device_id": 281479271677953, "device_key": "a1b2..."},
    {"device_id": 281479271677954, "device_key": "c3d4..."},
    ...
  ]
}
```

### 5.2 Ansible Role

```yaml
# roles/defenseclaw-edge-connector/tasks/main.yml
---
- name: Install edge-connector
  ansible.builtin.apt:
    name: defenseclaw-edge-connector
    state: present
  when: ansible_os_family == "Debian"

- name: Generate device keys
  ansible.builtin.command:
    cmd: python3 -c "import secrets; print(secrets.token_hex(32))"
  register: audit_key
  changed_when: false

- name: Register device with fleet
  ansible.builtin.uri:
    url: "{{ defenseclaw_fleet_api }}/api/v1/fleet/devices"
    method: POST
    headers:
      Authorization: "Bearer {{ defenseclaw_fleet_token }}"
      Content-Type: application/json
      X-DefenseClaw-Client: ansible
    body_format: json
    body:
      tenant_id: "{{ defenseclaw_tenant_id }}"
      fleet_id: "{{ defenseclaw_fleet_id }}"
      device_id: "{{ defenseclaw_device_id }}"
      hw_profile: "{{ ansible_machine }}"
  register: registration

- name: Write env file
  ansible.builtin.template:
    src: edge-connector.env.j2
    dest: /etc/defenseclaw/edge-connector.env
    owner: defenseclaw
    group: defenseclaw
    mode: '0600'

- name: Enable and start service
  ansible.builtin.systemd:
    name: edge-connector
    enabled: true
    state: started

- name: Validate installation
  ansible.builtin.command:
    cmd: edge-connector --validate
  register: validation
  failed_when: validation.rc != 0
```

### 5.3 Batch CLI Deploy

```bash
# Deploy to 100 devices from a hosts file
defenseclaw edge-connector install \
  --targets-file hosts.txt \
  --concurrency 10 \
  --fleet-api http://gateway:18970 \
  --fleet-token "$DCLAW_FLEET_API_TOKEN" \
  --tenant-id 1 \
  --fleet-id 1 \
  --broker-url mqtts://broker:8883

# hosts.txt format:
# user@192.168.1.101
# user@192.168.1.102
# ...
```

## 6. Health Check and Monitoring

### 6.1 IPC Health Check

```json
// Request via IPC socket
{"jsonrpc":"2.0","method":"health","id":1}

// Response
{
  "jsonrpc": "2.0",
  "result": {
    "status": "healthy",
    "version": "1.0.0",
    "profile": "STANDARD",
    "uptime_sec": 86400,
    "policy_version": 3,
    "mqtt": {
      "connected": true,
      "broker": "mqtts://broker:8883",
      "last_heartbeat": "2026-10-15T10:00:00Z"
    },
    "audit": {
      "chain_valid": true,
      "entries": 1247,
      "flash_writes": 89
    },
    "cache": {
      "size": 42,
      "hit_ratio": 0.73
    },
    "verdicts": {
      "allowed": 4521,
      "blocked": 23,
      "warned": 7
    }
  },
  "id": 1
}
```

### 6.2 Optional HTTP Health Endpoint

When `DCLAW_HEALTH_PORT` is set, expose `GET /healthz` for Kubernetes
liveness/readiness probes:

```
GET http://localhost:9090/healthz → 200 OK {"status":"healthy"}
GET http://localhost:9090/healthz → 503 Service Unavailable {"status":"degraded","reason":"mqtt_disconnected"}
```

### 6.3 Fleet Dashboard API

```
GET /api/v1/fleet/dashboard
→ {
    "total_devices": 100,
    "online": 95,
    "offline": 3,
    "degraded": 2,
    "policy_versions": {"3": 93, "2": 7},
    "avg_cache_hit_ratio": 0.71,
    "total_blocked_24h": 142,
    "total_allowed_24h": 45210,
    "alerts_active": 2
  }
```

## 7. Self-Update Mechanism

```bash
# Device-initiated update
edge-connector --upgrade

# Flow:
# 1. GET https://api.github.com/repos/.../releases/latest
# 2. Compare current version vs latest
# 3. Download platform-specific binary
# 4. Verify SHA-256 checksum
# 5. Replace /usr/local/bin/edge-connector (atomic rename)
# 6. systemctl restart edge-connector
# 7. Verify new version started successfully
# 8. Report upgrade via heartbeat
```

## 8. Security Considerations

| Threat | Mitigation |
|--------|------------|
| Tampered binary download | SHA-256 checksum + Cosign signature verification |
| Env file credential exposure | 0600 permissions, owned by defenseclaw user |
| Bulk registration abuse | Rate limit + admin-only token required |
| Health endpoint information leak | IPC socket only (no network by default) |
| Self-update MITM | HTTPS + checksum verification |
| Ansible credential in playbook | Vault-encrypted group_vars |

## 9. Tradeoffs

| Decision | Alternative | Why This Choice |
|----------|-------------|-----------------|
| Static musl linking | Dynamic glibc | Portable across distros without dependency hell |
| DEB+RPM (not snap/flatpak) | Snap Store | IoT devices run minimal OS without snap |
| Ansible role (not Puppet/Chef) | Multi-tool | Ansible is dominant in IoT/edge fleet management |
| IPC health (not HTTP default) | Always-on HTTP | Reduces attack surface on constrained devices |
| Self-update via GitHub | Custom update server | Simplicity; can switch to custom server later |
