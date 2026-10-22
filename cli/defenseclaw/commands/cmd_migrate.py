# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

"""defenseclaw migrate — bring config and data to this version's schema.

The installer runs this from the version it just installed, with the gateway
stopped. Operators rarely need it directly; it is safe to re-run.

Exit codes: 0 done (or nothing to do), 1 a step failed, 2 the configuration
was written by a newer DefenseClaw than this one, 3 (--check only) an upgrade
that swaps hooks installed open from a release whose hooks read
DEFENSECLAW_FAIL_MODE, without --accept-fail-mode-change.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import sys

import click

from defenseclaw import ux

EXIT_FAILED = 1
EXIT_CONFIG_TOO_NEW = 2
# Only --check returns it, after every other check passed: the installers run
# that check before the swap and ask, or stop an unattended upgrade.
EXIT_FAIL_MODE_CHANGE_NOT_ACCEPTED = 3


def _default_data_dir() -> str:
    # The same resolution every other command uses (DEFENSECLAW_HOME, sudo).
    from defenseclaw.config import default_data_path

    return str(default_data_path())


def _validate_from_version(_ctx, _param, value):
    # GAP-1449: any string used to be accepted. Installer values are package
    # versions (0.8.10, 1.0.1.dev3, 0.8.10+local), so only the X.Y.Z prefix
    # is required.
    if value is None or re.match(r"v?\d+\.\d+\.\d+", value.strip()):
        return value
    raise click.BadParameter(
        f"{value!r} is not a release version; use X.Y.Z, for example 0.8.10",
    )


@click.command("migrate")
@click.option(
    "--check",
    is_flag=True,
    help=(
        "List pending steps without changing anything. Exit 0 when they can be applied "
        "(pending or not), 1 when they cannot, 2 when the config is from a newer release, "
        "3 when the upgrade changes the outage behavior of hooks installed open "
        "(see --accept-fail-mode-change)."
    ),
)
@click.option(
    "--from-version",
    default=None,
    metavar="X.Y.Z",
    callback=_validate_from_version,
    help="Version that wrote the data (0.x imports).",
)
@click.option("--data-dir", default=None, type=click.Path(file_okay=False), help="Data directory to migrate.")
@click.option("--openclaw-home", default=None, type=click.Path(file_okay=False), help="OpenClaw home directory.")
@click.option("--gateway-binary", default=None, type=click.Path(dir_okay=False), help="Gateway used by --check.")
@click.option(
    "--accept-fail-mode-change",
    is_flag=True,
    help=(
        "With --check: pass an upgrade from 0.8.10 or 1.0.0-1.0.3 whose hooks are installed open. "
        "The upgraded hooks stay open while the gateway is down even for an agent started with "
        "DEFENSECLAW_FAIL_MODE=closed."
    ),
)
@click.option("--json", "as_json", is_flag=True, help="Print the result as JSON.")
def migrate_cmd(check, from_version, data_dir, openclaw_home, gateway_binary, accept_fail_mode_change, as_json) -> None:
    """Bring config and data to this version's schema."""
    from defenseclaw.migrations import ConfigTooNewError, MigrationError, display_step_name, migrate

    # A --from-version newer than this release is warned about where it is
    # read: a 0.x config without a cursor (migrations._warn_from_version_newer).
    # The installer passes the release it replaces, newer on a downgrade.

    # With --json, stdout carries only the JSON document; step progress goes to stderr.
    progress = contextlib.redirect_stdout(sys.stderr) if as_json else contextlib.nullcontext()
    try:
        with progress:
            result = migrate(
                data_dir or _default_data_dir(),
                openclaw_home=openclaw_home,
                from_version=from_version,
                check=check,
                gateway_binary=gateway_binary,
            )
    except ConfigTooNewError as exc:
        ux.err(str(exc))
        raise SystemExit(EXIT_CONFIG_TOO_NEW) from None
    except MigrationError as exc:
        ux.err(str(exc))
        raise SystemExit(EXIT_FAILED) from None

    # Notices that hold whatever this process's environment is: --check (the
    # installer runs it before the swap) names them before the hooks are
    # replaced, and --json lists them under "warnings". An upgrade notice
    # about hooks installed open also stops --check unless the change is
    # accepted (GAP-0361): the installers ask, and an unattended upgrade
    # must not make it silently.
    with progress:
        warnings, needs_acceptance = _process_fail_mode_notices(data_dir or _default_data_dir(), from_version, result)
    refused = check and needs_acceptance and not accept_fail_mode_change
    if as_json:
        # In check mode nothing ran: list the steps under "pending" and keep
        # "applied" empty so a script never mistakes a dry run for a migration.
        click.echo(
            json.dumps(
                {
                    "from_config_version": result.from_config_version,
                    "to_config_version": result.to_config_version,
                    "applied": [] if check else result.applied,
                    "pending": result.applied if check else [],
                    "changed": result.changed,
                    "check": check,
                    "fail_mode_change_not_accepted": refused,
                    "warnings": warnings,
                },
                sort_keys=True,
            )
        )
    elif result.from_config_version is None:
        ux.ok("No configuration yet; nothing to migrate.")
    elif not result.applied:
        ux.ok(f"Configuration is current (config_version {result.to_config_version}).")
    elif check:
        # Pending is not success: a neutral marker, the step names, and how
        # they get applied (the installer and upgrade run them as well).
        ux.echo(
            f"  {ux.bold('•')} {len(result.applied)} migration step(s) pending "
            f"(config_version {result.from_config_version} -> {result.to_config_version}):"
        )
        for step in result.applied:
            ux.echo(f"    → {display_step_name(step)}")
        ux.subhead("Nothing was changed. 'defenseclaw migrate' (or the upgrade) applies them.")
    else:
        ux.ok(f"Migrated to config_version {result.to_config_version} ({len(result.applied)} step(s)).")
    if not check and not as_json and _upgraded_from_0x(result):
        _report_hook_fail_mode_changes(data_dir or _default_data_dir())
        _report_ignored_dotenv_keys(data_dir or _default_data_dir())
    with progress:
        for notice in warnings:
            ux.warn(notice)
        if refused:
            ux.err(
                "This upgrade needs your consent before it replaces these hooks: save closed first as shown, "
                "or accept the change at the installer's prompt or with --accept-fail-mode-change "
                "(-AcceptFailModeChange in install.ps1). Nothing was changed."
            )
    if refused:
        raise SystemExit(EXIT_FAIL_MODE_CHANGE_NOT_ACCEPTED)


# The first release whose hooks run only the fail mode installed with them
# (GAP-0315): the hooks of every earlier release (0.8.10, 1.0.0-1.0.3) read
# DEFENSECLAW_FAIL_MODE from the agent's environment.
_FIRST_INSTALLED_FAIL_MODE_RELEASE = (1, 0, 4)


def _previous_hooks_read_process_fail_mode(from_version: str | None, from_config_version: int | None) -> bool:
    """Whether the install being upgraded has hooks that read DEFENSECLAW_FAIL_MODE.

    The installers pass the release they replace as --from-version; without
    it, only a 0.x config (below config_version 8) proves an older release.
    """
    match = re.match(r"v?(\d+)\.(\d+)\.(\d+)", (from_version or "").strip())
    if match:
        return tuple(int(part) for part in match.groups()) < _FIRST_INSTALLED_FAIL_MODE_RELEASE
    return from_config_version is not None and from_config_version < _FIRST_1X_CONFIG_VERSION


def _process_fail_mode_notices(data_dir: str, from_version: str | None, result) -> tuple[list[str], bool]:
    """The DEFENSECLAW_FAIL_MODE notices of this run (GAP-0361), and whether the upgrade needs consent.

    An upgrade from a release whose hooks read the variable names each
    connector installed open, whatever the upgrade's environment is: the
    agent that set the variable runs elsewhere. Such an upgrade needs
    consent (``migrate --check`` exits 3 without --accept-fail-mode-change):
    the old hooks blocked during an outage for an agent started with
    DEFENSECLAW_FAIL_MODE=closed and the upgraded ones let the call through.
    A config that cannot be read, or a notice that cannot be worked out,
    needs consent too. Otherwise a variable this process sets is named, as
    doctor does, and nothing needs consent.
    """
    if result.from_config_version is None:
        return [], False
    try:
        from defenseclaw.config import load

        cfg = load(data_dir=data_dir)
    except Exception:  # noqa: BLE001 - an unreadable config still gets the upgrade notice
        cfg = None
    from defenseclaw.fail_mode import ignored_process_fail_mode, process_fail_mode_upgrade_notice

    if _previous_hooks_read_process_fail_mode(from_version, result.from_config_version):
        try:
            notice = process_fail_mode_upgrade_notice(cfg, from_version)
        except Exception:  # noqa: BLE001 - not knowing which hooks are open is not consent
            notice = process_fail_mode_upgrade_notice(None, from_version)
        if notice:
            return [notice], True
    try:
        detail = ignored_process_fail_mode(cfg) if cfg is not None else None
    except Exception:  # noqa: BLE001 - this notice must never fail the migration
        return [], False
    return ([detail] if detail else []), False


def _report_ignored_dotenv_keys(data_dir: str) -> None:
    """Name each 0.x .env control key this release no longer reads (GAP-0387)."""
    from defenseclaw.config import ignored_dotenv_control_keys

    keys = ignored_dotenv_control_keys(data_dir)
    if not keys:
        return
    env_path = os.path.join(data_dir, ".env")
    ux.warn(f"{env_path} sets {len(keys)} variable(s) DefenseClaw no longer reads from .env:")
    for entry in keys:
        ux.subhead(entry, indent="    ")
    ux.subhead(f"Then remove those lines from {env_path}; 'defenseclaw doctor' lists them until then.", indent="    ")


# The first config_version a 1.x release wrote: below it is a 0.x config,
# whose hooks 0.8.x sealed with the global fail mode.
_FIRST_1X_CONFIG_VERSION = 8


def _upgraded_from_0x(result) -> bool:
    """Whether this run migrated a 0.x config, the one upgrade that changes the fail mode.

    A same-release reinstall or a 1.x upgrade printed the fail-open notice
    too, about a connector already in action mode (GAP-0276): the gateway had
    rewritten its hooks since, and this check reads the config by Python's
    rules, not the gateway's.
    """
    source = result.from_config_version
    return bool(result.applied) and source is not None and source < _FIRST_1X_CONFIG_VERSION


def _report_hook_fail_mode_changes(data_dir: str) -> None:
    """Name each connector whose hooks change from fail-closed to fail-open.

    0.8.x sealed the global fail mode into the hooks of observe-mode
    connectors. This release applies the documented rule that observe-mode
    hooks fail open, so say so before the gateway rewrites the hooks.
    """
    try:
        with open(os.path.join(data_dir, "hook_contract_lock.json"), encoding="utf-8") as stream:
            lock = json.load(stream)
        from defenseclaw.config import load

        guardrail = load(data_dir=data_dir).guardrail
    except Exception:  # noqa: BLE001 - a notice must never fail the migration
        return
    connectors = lock.get("connectors") if isinstance(lock, dict) else None
    if not isinstance(connectors, dict):
        return
    for name, entry in sorted(connectors.items()):
        sealed = str(entry.get("hook_fail_mode", "")).strip().lower() if isinstance(entry, dict) else ""
        if (
            sealed != "closed"
            or guardrail.effective_mode(name).strip().lower() != "observe"
            or guardrail.effective_hook_fail_mode(name) != "open"
        ):
            continue
        ux.warn(
            f"{name} hooks now fail open: in observe mode they let a call through when "
            "inspection is unavailable, where the previous release blocked it."
        )
        ux.subhead(f"To block such calls, enforce policy: defenseclaw setup {name} --mode action", indent="    ")
