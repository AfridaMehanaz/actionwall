"""MCP server exposing guarded shell, file and HTTP tools.

Point an agent at these instead of a raw shell, and every action it takes is
checked against policy, taint-tracked and written to the audit log.

    ACTIONWALL_WORKSPACE   directory the agent may work in (default: cwd)
    ACTIONWALL_POLICY      path to a policy YAML (default: built-in policy)
    ACTIONWALL_AUDIT       audit log path (default: <workspace>/.actionwall/audit.jsonl)
    ACTIONWALL_AUDIT_KEY   optional HMAC key for the audit chain
"""

from __future__ import annotations

import os
from pathlib import Path

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from . import __version__
from .actions import ActionBlocked
from .audit import AuditLog
from .executor import GuardedExecutor
from .guard import Guard
from .policy import Policy

INSTRUCTIONS = """Every action you take through these tools passes through actionwall, a policy firewall.
Blocked actions return the rule that stopped them. Do not try to work around a block by rephrasing,
encoding or splitting the action; explain to the user what you wanted to do and why it was blocked.
Actions marked as needing approval cannot be approved from inside this session."""


def _blocked(e: ActionBlocked) -> ToolError:
    return ToolError(f"BLOCKED by actionwall ({e.decision.verdict.value}): {e.decision.reason}")


def build_server(executor: GuardedExecutor) -> MCPServer:
    server = MCPServer("actionwall", instructions=INSTRUCTIONS, version=__version__)

    @server.tool(description="Run a shell command in the workspace. Output is returned; secrets in the environment are removed.")
    def run_command(command: str) -> str:
        try:
            return str(executor.run_shell(command)) or "(no output)"
        except ActionBlocked as e:
            raise _blocked(e) from None

    @server.tool(description="Read a text file (path relative to the workspace).")
    def read_file(path: str) -> str:
        try:
            return executor.read_file(path)
        except ActionBlocked as e:
            raise _blocked(e) from None
        except OSError as e:
            raise ToolError(str(e)) from None

    @server.tool(description="Write a text file inside the workspace, creating parent directories.")
    def write_file(path: str, content: str) -> str:
        try:
            n = executor.write_file(path, content)
            return f"wrote {n} characters to {path}"
        except ActionBlocked as e:
            raise _blocked(e) from None

    @server.tool(description="HTTP request to an allowlisted domain. Returns the response body (truncated).")
    def http_fetch(url: str, method: str = "GET", body: str = "") -> str:
        try:
            return executor.http_request(url, method, body)
        except ActionBlocked as e:
            raise _blocked(e) from None
        except OSError as e:
            raise ToolError(f"request failed: {e}") from None

    return server


def executor_from_env() -> GuardedExecutor:
    workspace = Path(os.environ.get("ACTIONWALL_WORKSPACE", os.getcwd())).resolve()
    policy = Policy.load(os.environ.get("ACTIONWALL_POLICY"), workspace=workspace)
    audit = AuditLog(os.environ.get("ACTIONWALL_AUDIT", workspace / ".actionwall" / "audit.jsonl"),
                     key=os.environ.get("ACTIONWALL_AUDIT_KEY"))
    return GuardedExecutor(Guard(policy, audit))


def main() -> None:
    build_server(executor_from_env()).run("stdio")
