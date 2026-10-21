import asyncio

import pytest
from mcp.server.mcpserver.exceptions import ToolError

from actionwall import AuditLog, Guard, GuardedExecutor, verify
from actionwall.mcp_server import build_server


@pytest.fixture
def server(policy, ws):
    return build_server(GuardedExecutor(Guard(policy, AuditLog(ws / ".actionwall" / "audit.jsonl"))))


def call(server, name, **args):
    return asyncio.run(server.call_tool(name, args))


def text(result):
    return result.content[0].text


def test_lists_guarded_tools(server):
    names = {t.name for t in asyncio.run(server.list_tools())}
    assert names == {"run_command", "read_file", "write_file", "http_fetch"}
    assert "actionwall" in server.instructions


def test_allowed_actions_work(server):
    assert text(call(server, "write_file", path="a.txt", content="hi")) == "wrote 2 characters to a.txt"
    assert text(call(server, "read_file", path="a.txt")) == "hi"
    assert "app.py" in text(call(server, "run_command", command="ls src"))


def test_blocked_actions_explain_why(server):
    with pytest.raises(ToolError, match=r"BLOCKED by actionwall \(deny\).*fs.read_deny"):
        call(server, "read_file", path=".env")


def test_agent_cannot_tamper_with_audit_log(server, ws):
    call(server, "run_command", command="ls")
    with pytest.raises(ToolError, match="fs.write_deny"):
        call(server, "run_command", command=": > .actionwall/audit.jsonl")
    with pytest.raises(ToolError):
        call(server, "write_file", path=".actionwall/audit.jsonl", content="")
    assert verify(ws / ".actionwall" / "audit.jsonl").ok
