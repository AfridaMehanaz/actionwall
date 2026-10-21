"""The vocabulary: what an agent tries to do, and what the wall decides."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Kind(str, Enum):
    SHELL = "shell"  # target = command line
    READ = "read"    # target = path
    WRITE = "write"  # target = path, payload = content
    HTTP = "http"    # target = url, payload = body, meta.method
    TOOL = "tool"    # target = tool name, payload = JSON arguments


class Verdict(str, Enum):
    ALLOW = "allow"
    ASK = "ask"      # needs a human
    DENY = "deny"

    @property
    def severity(self) -> int:
        return {"allow": 0, "ask": 1, "deny": 2}[self.value]


@dataclass
class Action:
    kind: Kind
    target: str
    payload: str = ""
    meta: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = {"kind": self.kind.value, "target": self.target}
        if self.payload:
            d["payload"] = self.payload
        if self.meta:
            d["meta"] = self.meta
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Action":
        return cls(Kind(d["kind"]), d["target"], d.get("payload", ""), d.get("meta", {}))


@dataclass
class Finding:
    """One reason behind a decision, tied to the rule that produced it."""

    verdict: Verdict
    rule: str
    reason: str

    def __str__(self) -> str:
        return f"[{self.rule}] {self.reason}"


@dataclass
class Decision:
    verdict: Verdict
    findings: list[Finding] = field(default_factory=list)

    @property
    def allowed(self) -> bool:
        return self.verdict is Verdict.ALLOW

    @property
    def reason(self) -> str:
        decisive = [f for f in self.findings if f.verdict is self.verdict] or self.findings
        return "; ".join(str(f) for f in decisive) or "no rule matched"

    @classmethod
    def combine(cls, findings: list[Finding], default: Verdict = Verdict.ALLOW) -> "Decision":
        """The strictest finding wins: deny > ask > allow."""
        verdict = max((f.verdict for f in findings), key=lambda v: v.severity, default=default)
        return cls(verdict, findings)


class ActionBlocked(Exception):
    def __init__(self, action: Action, decision: Decision):
        super().__init__(f"{action.kind.value} blocked ({decision.verdict.value}): {decision.reason}")
        self.action = action
        self.decision = decision
