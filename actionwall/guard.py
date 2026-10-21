"""The Guard: one decision point for every action an agent takes."""

from __future__ import annotations

from collections import Counter
from typing import Callable

from .actions import Action, Decision, Finding, Kind, Verdict
from .audit import AuditLog
from .policy import Policy
from .shell import parse_shell
from .taint import TaintTracker

# Called when a decision is ASK. Return True to allow. Default: nobody is there to ask, so deny.
Approver = Callable[[Action, Decision], bool]

FILE_FLAGS = {"-T", "--upload-file", "--post-file", "--body-file"}  # flags whose next arg is a file to send


def deny_all(action: Action, decision: Decision) -> bool:
    return False


class Guard:
    def __init__(self, policy: Policy | None = None, audit: AuditLog | None = None,
                 approver: Approver = deny_all, taint: TaintTracker | None = None):
        self.policy = policy or Policy.load()
        self.audit = audit
        self.approver = approver
        taint_cfg = self.policy.data["taint"]
        self.taint = taint or (TaintTracker(taint_cfg["min_secret_length"]) if taint_cfg["enabled"] else None)
        self.counts: Counter[str] = Counter()

    # -- decisions ----------------------------------------------------------------
    def evaluate(self, action: Action) -> Decision:
        """Policy decision without a human in the loop or an audit entry."""
        findings = self._limits(action)
        p = self.policy
        if action.kind is Kind.SHELL:
            findings += p.check_shell(action.target)
            if self.taint:
                findings += self.taint.check_outbound(action.target, "shell command")
                findings += self._uploaded_files(action.target)
        elif action.kind is Kind.READ:
            findings += p.check_read(action.target)
        elif action.kind is Kind.WRITE:
            findings += p.check_write(action.target)
        elif action.kind is Kind.HTTP:
            findings += p.check_url(action.target)
            if self.taint:
                findings += self.taint.check_outbound(f"{action.target}\n{action.payload}", "HTTP request")
        elif action.kind is Kind.TOOL:
            findings += p.check_tool(action.target)
            if self.taint:
                findings += self.taint.check_outbound(action.payload, f"tool {action.target} arguments")
        return Decision.combine(_dedupe(findings))

    def check(self, action: Action) -> Decision:
        """Decide, consult a human on ASK, count, and audit."""
        decision = self.evaluate(action)
        approved_by_human = None
        if decision.verdict is Verdict.ASK:
            approved_by_human = bool(self.approver(action, decision))
            verdict = Verdict.ALLOW if approved_by_human else Verdict.DENY
            note = "approved by human" if approved_by_human else "approval required; not granted"
            decision = Decision(verdict, decision.findings + [Finding(verdict, "human", note)])
        if decision.allowed:
            self.counts["actions"] += 1
            self.counts[action.kind.value] += 1
        self._record(action, decision, approved_by_human)
        return decision

    def observe(self, action: Action, result: str) -> None:
        """Feed the output of an executed action back so secrets it revealed become tainted."""
        if self.taint and result:
            label = f"{action.kind.value}:{action.target}"[:120]
            new = self.taint.observe(result, label)
            if new and self.audit:
                self.audit.append({"event": "taint", "source": label, "new_secrets": len(new)})

    # -- internals ----------------------------------------------------------------
    def _limits(self, action: Action) -> list[Finding]:
        lim = self.policy.data["limits"]
        out = []
        if self.counts["actions"] >= lim["max_actions"]:
            out.append(Finding(Verdict.DENY, "limits.actions", f"action budget of {lim['max_actions']} exhausted"))
        if action.kind is Kind.WRITE and self.counts["write"] >= lim["max_writes"]:
            out.append(Finding(Verdict.DENY, "limits.writes", f"write budget of {lim['max_writes']} exhausted"))
        if action.kind is Kind.HTTP and self.counts["http"] >= lim["max_network"]:
            out.append(Finding(Verdict.DENY, "limits.network", f"network budget of {lim['max_network']} exhausted"))
        return out

    def _uploaded_files(self, command: str) -> list[Finding]:
        """curl -d @config.yaml https://allowed.com: the secret is in the file, not the command."""
        findings: list[Finding] = []
        parsed = parse_shell(command)
        net = set(self.policy.data["shell"]["network_programs"])
        for cmd in parsed.commands:
            if cmd.program not in net:
                continue
            for i, a in enumerate(cmd.args):
                path = None
                if a.startswith("@") and len(a) > 1:
                    path = a[1:]
                elif "=@" in a:  # -F file=@path
                    path = a.split("=@", 1)[1]
                elif a in FILE_FLAGS and i + 1 < len(cmd.args):
                    path = cmd.args[i + 1]
                if path and path != "-":
                    try:
                        content = self.policy.resolve(path).read_text(errors="ignore")
                    except OSError:
                        continue
                    # Learn from the file too: the agent never "read" it, but the command would send it.
                    self.taint.observe(content, f"upload:{path}")
                    findings += self.taint.check_outbound(content, f"upload of {path}")
        return findings

    def _record(self, action: Action, decision: Decision, approved: bool | None) -> None:
        if not self.audit:
            return
        a = action.to_dict()
        if self.taint:  # never write the secrets we are protecting into the log
            a = {k: self.taint.scrub(v) if isinstance(v, str) else v for k, v in a.items()}
        if "payload" in a and len(a["payload"]) > 500:
            a["payload"] = a["payload"][:500] + "…"
        self.audit.append({
            "event": "decision",
            "action": a,
            "verdict": decision.verdict.value,
            "rules": sorted({f.rule for f in decision.findings}),
            "reason": decision.reason,
            **({"human_approved": approved} if approved is not None else {}),
        })


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen, out = set(), []
    for f in findings:
        key = (f.verdict, f.rule, f.reason)
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


def describe(action: Action) -> str:
    """One-line human-readable summary, used by approvers."""
    if action.kind is Kind.SHELL:
        return f"$ {action.target}"
    if action.kind is Kind.HTTP:
        return f"{action.meta.get('method', 'GET')} {action.target}"
    return f"{action.kind.value} {action.target}"

