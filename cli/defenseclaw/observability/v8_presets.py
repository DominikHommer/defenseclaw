# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Small v8-only helpers shared by destination setup commands.

This module resolves authored preset inputs into canonical destination fields;
it never reads or writes a released 0.8.x observability block.
"""

from __future__ import annotations

import os
import re
from typing import Any
from urllib.parse import urlparse

from defenseclaw.file_permissions import MAX_DOTENV_BYTES, read_regular_file_no_follow
from defenseclaw.observability.presets import SPLUNK_HEC, Preset
from defenseclaw.observability.v8_activation import update_private_file
from defenseclaw.safety import sanitize_dotenv_value

DESTINATION_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
DOTENV_FILE_NAME = ".env"


def resolve_inputs(preset: Preset, inputs: dict[str, str]) -> dict[str, str]:
    resolved: dict[str, str] = {}
    for flag_name, _placeholder, _description, default in preset.prompts:
        value = inputs.get(flag_name, "") or default
        if not value:
            raise ValueError(f"preset {preset.id!r}: missing required input {flag_name!r} (no default provided)")
        resolved[flag_name] = value
    resolved.update({key: value for key, value in inputs.items() if key not in resolved})
    return resolved


def destination_name(preset: Preset, override: str | None, inputs: dict[str, str]) -> str:
    if override:
        return override
    if preset.id in {"splunk-hec", "splunk-enterprise"}:
        host = inputs.get("host", "localhost")
        endpoint = inputs.get("endpoint", "")
        if endpoint:
            parsed = urlparse(endpoint if "://" in endpoint else f"//{endpoint}")
            host = parsed.hostname or host
        return f"{preset.id}-{_slug(host)}"
    if preset.id == "webhook":
        parsed = urlparse(inputs.get("url", ""))
        return f"webhook-{_slug(parsed.hostname or 'webhook')}"
    if preset.id == "otlp":
        endpoint = inputs.get("endpoint", "")
        parsed = urlparse(endpoint if "://" in endpoint else "//" + endpoint)
        return f"otlp-{_slug(parsed.hostname or 'otlp')}"
    if preset.id == "local-otlp":
        return "local-observability"
    return preset.id


def render_template(template: str, inputs: dict[str, str]) -> str:
    try:
        return template.format(**inputs)
    except KeyError as exc:
        raise ValueError(f"endpoint template {template!r} references unknown input {exc.args[0]!r}") from exc


def render_header_template(template: str, inputs: dict[str, str]) -> str:
    """Render preset placeholders while preserving ``${ENV_VAR}`` references."""

    def replace(match: re.Match[str]) -> str:
        key = match.group(1)
        if key not in inputs:
            raise ValueError(f"header template {template!r} references unknown input {key!r}")
        return inputs[key]

    return re.sub(r"(?<!\$)\{([a-zA-Z_][a-zA-Z0-9_]*)\}", replace, template)


def adapter_destination_fields(preset: Preset, inputs: dict[str, str]) -> dict[str, Any]:
    """Return canonical fields for a non-OTLP destination preset."""

    if preset.adapter_kind == "splunk_hec":
        endpoint = inputs.get("endpoint", "").strip()
        if not endpoint:
            host = inputs.get("host", "localhost")
            port = inputs.get("port", "8088")
            endpoint = f"https://{host}:{port}/services/collector/event"
        if not endpoint.lower().startswith(("http://", "https://")):
            raise ValueError(f"Splunk HEC endpoint must start with http:// or https:// (got {endpoint!r})")
        fields: dict[str, Any] = {
            "kind": "splunk_hec",
            "endpoint": endpoint,
            "token_env": preset.token_env,
            "index": inputs.get("index", "defenseclaw"),
            "source": inputs.get("source", "defenseclaw"),
            "sourcetype": inputs.get("sourcetype", "_json"),
        }
        # GAP-0208: every HEC preset verifies TLS and stays off private
        # networks unless the operator opts out (--no-verify-tls,
        # --allow-private-networks), as splunk-enterprise and otlp do.
        # Skipping certificate checks only means something over https: on an
        # http:// endpoint the config check refused tls.insecure_skip_verify with a
        # JSON path and an error code (GAP-0209), so plain http (the local Splunk
        # bridge, --no-verify-tls) gets no tls block.
        insecure = "verify_tls" in inputs and not parse_bool(inputs["verify_tls"])
        if insecure and not endpoint.lower().startswith("http://"):
            fields["tls"] = {"insecure_skip_verify": True}
        return fields
    if preset.adapter_kind == "http_jsonl":
        endpoint = inputs.get("url", "").strip()
        if not endpoint.lower().startswith(("http://", "https://")):
            raise ValueError(f"HTTP JSONL endpoint must start with http:// or https:// (got {endpoint!r})")
        method = (inputs.get("method") or "POST").upper()
        if method not in {"POST", "PUT", "PATCH"}:
            raise ValueError(f"HTTP JSONL method must be POST/PUT/PATCH (got {method!r})")
        fields = {"kind": "http_jsonl", "endpoint": endpoint, "method": method}
        if preset.token_env:
            fields["bearer_env"] = preset.token_env
        return fields
    raise ValueError(f"preset {preset.id!r} does not define a canonical adapter kind")


def apply_secret(
    data_dir: str,
    preset: Preset,
    secret_value: str | None,
    *,
    dry_run: bool,
) -> list[str]:
    if not preset.token_env:
        return []
    if preset.adapter_kind == "splunk_hec":
        _validate_splunk_credential_isolation(data_dir, preset, secret_value)
    path = os.path.join(data_dir, DOTENV_FILE_NAME)
    if not secret_value:
        existing: dict[str, str] = {}

        def inspect(payload: bytes) -> None:
            existing.update(_load_dotenv(payload))
            return None

        update_private_file(
            path,
            owner_directory=data_dir,
            transform=inspect,
        )
        if preset.token_env not in existing and not os.environ.get(preset.token_env):
            return [f"{preset.token_env}: not set — destination authentication will fail"]
        return []
    # Dry runs must reject exactly the same unsafe values as real writes.
    # Do not include the rendered value in the preview or diagnostics.
    sanitize_dotenv_value(secret_value, key=preset.token_env)
    if dry_run:
        return [f"{preset.token_env}: (would write to {path})"]

    def merge(payload: bytes) -> bytes:
        existing = _load_dotenv(payload)
        existing[preset.token_env] = secret_value
        return _write_dotenv(existing)

    update_private_file(
        path,
        owner_directory=data_dir,
        transform=merge,
    )
    os.environ[preset.token_env] = secret_value
    return [f"{preset.token_env}: written to {path}"]


_LOCAL_SPLUNK_BRIDGE_ENV = os.path.join("splunk-bridge", "env", ".env")
NATIVE_LOCAL_SPLUNK_DESTINATION = "local-splunk"


def local_splunk_destination_name(hec_url: str) -> str:
    """Return the name the macOS and Linux local setup gives the sink it owns.

    The setup and the credential check both call this, so the check always
    finds the destination the setup wrote, on any bridge host name.
    """

    parsed = urlparse(hec_url if "://" in hec_url else f"//{hec_url}")
    return destination_name(SPLUNK_HEC, None, {"host": parsed.hostname or "127.0.0.1", "endpoint": hec_url})


def _local_splunk_state(data_dir: str) -> tuple[set[str], dict[str, str], set[str]]:
    """Return the local Splunk credentials, the saved .env values and the owned sink names."""

    from defenseclaw.observability.local_splunk import DEFAULT_HEC_URL, LOCAL_TOKEN_ENV

    local_tokens = {os.environ.get(LOCAL_TOKEN_ENV, "")}
    saved: dict[str, str] = {}
    owned = {NATIVE_LOCAL_SPLUNK_DESTINATION, local_splunk_destination_name(DEFAULT_HEC_URL)}
    for relative in (DOTENV_FILE_NAME, _LOCAL_SPLUNK_BRIDGE_ENV):
        try:
            payload = read_regular_file_no_follow(os.path.join(data_dir, relative), max_bytes=MAX_DOTENV_BYTES)
            values = _load_dotenv(payload)
        except FileNotFoundError:
            continue
        except (OSError, ValueError) as exc:
            raise ValueError(
                "Cannot verify Splunk credential isolation; repair the private Splunk .env files, "
                "then rerun defenseclaw setup splunk --enterprise."
            ) from exc
        if relative == DOTENV_FILE_NAME:
            saved = values
            local_tokens.add(values.get(LOCAL_TOKEN_ENV, ""))
        else:
            local_tokens.update(
                values.get(key, "") for key in ("DEFENSECLAW_HEC_TOKEN", "SPLUNK_HEC_TOKEN", LOCAL_TOKEN_ENV)
            )
            if values.get("DEFENSECLAW_HEC_URL"):
                owned.add(local_splunk_destination_name(values["DEFENSECLAW_HEC_URL"]))
    local_tokens.discard("")
    return local_tokens, saved, owned


def local_splunk_sink_shares_reference(data_dir: str, token_env: str, destinations) -> bool:
    """Return whether a DefenseClaw-managed local sink in *destinations* still uses *token_env*.

    Earlier Unix local setups saved the generated local credential under the
    remote reference; writing a remote token there would break that sink. The
    sink is the destination local setup owns (the name it writes) while the
    reference still holds the private bridge credential. Neither alone marks
    it: an older remote destination can keep the old local credential after
    the local sink moved to its own reference, and a remote Splunk reached
    through an SSH tunnel is loopback too, even on the port of a stopped local
    stack.
    """

    sharing = {
        destination.get("name")
        for destination in destinations
        if destination.get("kind") == "splunk_hec" and destination.get("token_env") == token_env
    }
    if not sharing:
        return False
    local_tokens, saved, owned = _local_splunk_state(data_dir)
    if not sharing & owned:
        return False
    return bool({saved.get(token_env, ""), os.environ.get(token_env, "")} & local_tokens)


def _validate_splunk_credential_isolation(data_dir: str, preset: Preset, supplied: str | None) -> None:
    from defenseclaw.observability.local_splunk import LOCAL_TOKEN_ENV

    if preset.token_env == LOCAL_TOKEN_ENV:
        return
    # Earlier Unix local setups used the remote name. A saved or ambient
    # value is not a remote credential if it belongs to the local container.
    local_tokens, saved, _owned = _local_splunk_state(data_dir)
    token = supplied or os.environ.get(preset.token_env) or saved.get(preset.token_env)
    if token and token in local_tokens:
        raise ValueError(
            "A local Splunk credential cannot authenticate a remote destination. Set "
            "DEFENSECLAW_SETUP_SPLUNK_HEC_TOKEN to the remote collector's token, then rerun "
            "defenseclaw setup splunk --enterprise."
        )


def restore_secret(
    data_dir: str, key: str, previous: str | None, previous_environ: str | None, written: str
) -> None:
    """Restore our write only if a newer setup has not replaced its value."""

    def merge(payload: bytes) -> bytes:
        existing = _load_dotenv(payload)
        if existing.get(key) != written:
            return payload
        if previous is None:
            existing.pop(key, None)
        else:
            existing[key] = previous
        return _write_dotenv(existing)

    update_private_file(os.path.join(data_dir, DOTENV_FILE_NAME), owner_directory=data_dir, transform=merge)
    if os.environ.get(key) == written:
        if previous_environ is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = previous_environ


def secret_note_is_info(preset: Preset, message: str) -> bool:
    """Whether an :func:`apply_secret` message reports a write, not a problem."""

    return bool(preset.token_env) and message.startswith(
        (f"{preset.token_env}: written to ", f"{preset.token_env}: (would write to ")
    )


def parse_bool(value: str) -> bool:
    normalized = str(value).strip().lower()
    if normalized in {"1", "true", "yes", "y", "on"}:
        return True
    if normalized in {"0", "false", "no", "n", "off"}:
        return False
    raise ValueError("verify_tls must be a boolean value (true/false)")


def _slug(value: str) -> str:
    normalized = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return normalized[:40] or "default"


def _load_dotenv(payload: bytes) -> dict[str, str]:
    result: dict[str, str] = {}
    for raw_line in payload.decode("utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        if key.strip():
            result[key.strip()] = value
    return result


def _write_dotenv(entries: dict[str, str]) -> bytes:
    # Validate and render every value before the secure transaction stages any
    # bytes. Rejected values leave the exact snapshotted file untouched.
    return "".join(f"{key}={sanitize_dotenv_value(value, key=key)}\n" for key, value in sorted(entries.items())).encode(
        "utf-8"
    )


__all__ = [
    "DESTINATION_NAME_RE",
    "adapter_destination_fields",
    "apply_secret",
    "destination_name",
    "local_splunk_destination_name",
    "local_splunk_sink_shares_reference",
    "parse_bool",
    "render_header_template",
    "render_template",
    "resolve_inputs",
    "restore_secret",
    "secret_note_is_info",
]
