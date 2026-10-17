"""#1164: an enrolled user's MCP server on managed Windows starts as the user.

The managed scanner runtime starts the gateway's relay in place of the
server; the hook enumerator starts the published definition as the user.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from defenseclaw.config import MCPScannerConfig, MCPServerEntry
from defenseclaw.scanner import mcp


def _relay(tmp_path: Path) -> tuple[str, ...]:
    gateway = tmp_path / "defenseclaw-gateway.exe"
    gateway.write_text("fixture", encoding="utf-8")
    return (os.fspath(gateway), "enterprise", "windows", "mcp-relay", "--request", "abc")


def test_relay_plan_starts_the_relay_not_the_server(tmp_path: Path) -> None:
    relay = _relay(tmp_path)
    entry = MCPServerEntry(name="notes", command="npx", args=["-y", ".", "--config", r".\srv.json"],
                           env={"NOTES_TOKEN": "x"})
    plan = mcp._as_user_relay_plan(entry, relay)
    assert plan.command == relay[0]
    assert plan.args == relay[1:]
    assert plan.launcher == "npx"
    assert plan.cwd is None
    # The server's env goes nowhere near the relay; the enumerator applies it.
    assert "NOTES_TOKEN" not in plan.env
    uvx = mcp._as_user_relay_plan(MCPServerEntry(name="t", command="uvx", args=["mcp-server-time"]), relay)
    assert uvx.launcher == "uvx"


@pytest.mark.parametrize(
    "command,args",
    [
        ("node", ["server.js"]),
        ("cmd.exe", ["/c", "calc"]),
    ],
)
def test_relay_plan_refuses_other_launchers(tmp_path: Path, command: str, args: list[str]) -> None:
    with pytest.raises(mcp.MCPStdioLaunchError, match="only through npx or uvx"):
        mcp._as_user_relay_plan(MCPServerEntry(name="s", command=command, args=args), _relay(tmp_path))


def test_relay_plan_refuses_npx_metacharacters(tmp_path: Path) -> None:
    with pytest.raises(mcp.MCPStdioLaunchError, match="metacharacter"):
        mcp._as_user_relay_plan(MCPServerEntry(name="s", command="npx", args=["pkg&calc"]), _relay(tmp_path))


def test_relay_plan_needs_an_installed_relay(tmp_path: Path) -> None:
    entry = MCPServerEntry(name="s", command="npx", args=["pkg"])
    for relay in [(), ("relative.exe",), (os.fspath(tmp_path / "missing.exe"),)]:
        with pytest.raises(mcp.MCPStdioLaunchError, match="not an installed executable"):
            mcp._as_user_relay_plan(entry, relay)


def test_scanner_wrapper_has_no_relay_by_default() -> None:
    assert mcp.MCPScannerWrapper(MCPScannerConfig()).stdio_relay == ()
