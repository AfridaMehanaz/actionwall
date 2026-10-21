"""Run actions only after the Guard allows them."""

from __future__ import annotations

import json
import os
import subprocess
import urllib.request
from dataclasses import dataclass

from .actions import Action, ActionBlocked, Kind
from .guard import Guard

# Variables an agent's shell never needs and an attacker always wants.
SCRUBBED_ENV = ("KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL", "AWS_", "GITHUB_", "ANTHROPIC", "OPENAI")


@dataclass
class ShellResult:
    exit_code: int
    stdout: str
    stderr: str

    def __str__(self) -> str:
        return (self.stdout + (f"\n[stderr]\n{self.stderr}" if self.stderr.strip() else "")
                + (f"\n[exit {self.exit_code}]" if self.exit_code else "")).strip()


class GuardedExecutor:
    """File, shell and HTTP primitives that are checked, audited and taint-tracked."""

    def __init__(self, guard: Guard, timeout: float = 60.0, max_output: int = 20_000):
        self.guard = guard
        self.timeout = timeout
        self.max_output = max_output

    @property
    def workspace(self):
        return self.guard.policy.workspace

    def _enforce(self, action: Action) -> None:
        decision = self.guard.check(action)
        if not decision.allowed:
            raise ActionBlocked(action, decision)

    def run_shell(self, command: str) -> ShellResult:
        action = Action(Kind.SHELL, command)
        self._enforce(action)
        env = {k: v for k, v in os.environ.items() if not any(s in k.upper() for s in SCRUBBED_ENV)}
        try:
            p = subprocess.run(command, shell=True, cwd=self.workspace, env=env, capture_output=True,
                               text=True, timeout=self.timeout)
            result = ShellResult(p.returncode, p.stdout[-self.max_output:], p.stderr[-self.max_output:])
        except subprocess.TimeoutExpired:
            result = ShellResult(124, "", f"timed out after {self.timeout}s")
        self.guard.observe(action, result.stdout + result.stderr)
        return result

    def read_file(self, path: str) -> str:
        action = Action(Kind.READ, path)
        self._enforce(action)
        text = self.guard.policy.resolve(path).read_text(errors="replace")[: self.max_output * 5]
        self.guard.observe(action, text)
        return text

    def write_file(self, path: str, content: str) -> int:
        action = Action(Kind.WRITE, path, content)
        self._enforce(action)
        p = self.guard.policy.resolve(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        return p.write_text(content)

    def http_request(self, url: str, method: str = "GET", body: str = "", headers: dict | None = None) -> str:
        action = Action(Kind.HTTP, url, body, {"method": method.upper()})
        self._enforce(action)
        req = urllib.request.Request(url, data=body.encode() if body else None, method=method.upper(),
                                     headers={"User-Agent": "actionwall", **(headers or {})})
        # Redirects could leave the allowlist, so re-check every hop.
        opener = urllib.request.build_opener(_GuardedRedirects(self.guard))
        with opener.open(req, timeout=self.timeout) as resp:
            text = resp.read(self.max_output).decode(errors="replace")
        self.guard.observe(action, text)
        return text


class _GuardedRedirects(urllib.request.HTTPRedirectHandler):
    def __init__(self, guard: Guard):
        self.guard = guard

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        action = Action(Kind.HTTP, newurl, meta={"method": "GET", "redirect_from": req.full_url})
        decision = self.guard.check(action)
        if not decision.allowed:
            raise ActionBlocked(action, decision)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def tool_payload(args: tuple, kwargs: dict) -> str:
    return json.dumps({"args": list(args), "kwargs": kwargs}, default=str, sort_keys=True)
