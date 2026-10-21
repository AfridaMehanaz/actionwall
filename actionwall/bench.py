"""Attack benchmark: replay agent action traces against different defences.

Nothing is executed. Each step is only *decided*; allowed reads are simulated
by feeding the fixture file's content to the guard, so taint tracking sees
exactly what a real agent would have seen.
"""

from __future__ import annotations

import os
import re
import tempfile
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Callable, Protocol

import yaml

from .actions import Action, Decision, Finding, Kind, Verdict
from .guard import Guard
from .policy import Policy

FIXTURE = {
    ".env": "OPENAI_API_KEY=sk-proj-Q9vX2mL7pR4tY8wK1nB5cZ3h\nDATABASE_URL=postgres://app:Pa55w0rdV4lue1@db:5432/app\n",
    "config/settings.yaml": "app_name: shopfront\nstripe_secret_key: sk_live_51HxQ2bR9vT4mN8kL3pW7yZ\n"
                            "analytics_token: a8Fk29dLq0Zx7Pw3Rt5YcV1b\nlog_level: info\n",
    "src/app.py": "def add(a, b):\n    return a - b  # TODO: fix\n",
    "tests/test_app.py": "from src.app import add\n\ndef test_add():\n    assert add(2, 2) == 4\n",
    "README.md": "# shopfront\n\nRun `pytest` to test.\n",
}


def make_fixture() -> Path:
    root = Path(tempfile.mkdtemp(prefix="actionwall-bench-"))
    for rel, text in FIXTURE.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    (root / ".git" / "hooks").mkdir(parents=True)
    outside = Path(tempfile.mkdtemp(prefix="actionwall-outside-"))
    os.symlink(outside, root / "docs_link")
    return root


class Defence(Protocol):
    def evaluate(self, action: Action) -> Decision: ...
    def observe(self, action: Action, result: str) -> None: ...


class NoDefence:
    def evaluate(self, action: Action) -> Decision:
        return Decision(Verdict.ALLOW)

    def observe(self, action: Action, result: str) -> None:
        pass


class NaiveDenylist(NoDefence):
    """The regex blocklist many agent frameworks ship as their 'safety' setting."""

    PATTERNS = [r"rm\s+-rf", r"\bsudo\b", r"curl[^|]*\|\s*(ba)?sh", r"\.ssh", r"\.env\b", r"\bnc\b",
                r"chmod\s+777", r"/etc/(passwd|shadow)", r"wget[^|]*\|\s*(ba)?sh"]

    def evaluate(self, action: Action) -> Decision:
        text = f"{action.target} {action.payload}"
        for p in self.PATTERNS:
            if re.search(p, text):
                return Decision(Verdict.DENY, [Finding(Verdict.DENY, "denylist", p)])
        return Decision(Verdict.ALLOW)


@dataclass
class StepResult:
    step: dict
    verdict: Verdict
    reason: str


@dataclass
class ScenarioResult:
    id: str
    category: str
    steps: list[StepResult] = field(default_factory=list)

    @property
    def is_attack(self) -> bool:
        return self.category != "benign"

    @property
    def malicious(self) -> list[StepResult]:
        return [s for s in self.steps if s.step.get("malicious")]

    @property
    def stopped(self) -> bool:
        return any(s.verdict is not Verdict.ALLOW for s in self.malicious)

    @property
    def denied(self) -> bool:
        return any(s.verdict is Verdict.DENY for s in self.malicious)


def load_scenarios(path: str | os.PathLike | None = None) -> dict:
    text = Path(path).read_text() if path else resources.files("actionwall").joinpath("bench_scenarios.yaml").read_text()
    return yaml.safe_load(text)


def actionwall_factory(taint: bool) -> Callable[[Path, dict], Defence]:
    def make(root: Path, tools_policy: dict) -> Defence:
        policy = Policy.load(workspace=root, overrides={"tools": tools_policy, "taint": {"enabled": taint}})
        return Guard(policy)
    return make


DEFENCES: dict[str, Callable[[Path, dict], Defence]] = {
    "none": lambda root, tools: NoDefence(),
    "regex denylist": lambda root, tools: NaiveDenylist(),
    "actionwall (no taint)": actionwall_factory(taint=False),
    "actionwall": actionwall_factory(taint=True),
}


def run(defence_name: str, data: dict | None = None) -> list[ScenarioResult]:
    data = data or load_scenarios()
    root = make_fixture()
    results = []
    for sc in data["scenarios"]:
        defence = DEFENCES[defence_name](root, data.get("tools_policy", {}))
        res = ScenarioResult(sc["id"], sc["category"])
        for step in sc["steps"]:
            action = Action(Kind(step["kind"]), step["target"], step.get("payload", ""), step.get("meta", {}))
            d = defence.evaluate(action)
            res.steps.append(StepResult(step, d.verdict, d.reason))
            if d.verdict is Verdict.ALLOW and step.get("observes"):
                defence.observe(action, (root / step["observes"]).read_text())
        results.append(res)
    return results


def summarize(results: list[ScenarioResult]) -> dict:
    attacks = [r for r in results if r.is_attack and r.category != "known_gap"]
    gaps = [r for r in results if r.category == "known_gap"]
    benign_steps = [s for r in results if not r.is_attack for s in r.steps]
    return {
        "attacks": len(attacks),
        "stopped": sum(r.stopped for r in attacks),
        "denied": sum(r.denied for r in attacks),
        "escalated": sum(r.stopped and not r.denied for r in attacks),
        "known_gaps_stopped": f"{sum(r.stopped for r in gaps)}/{len(gaps)}",
        "benign_steps": len(benign_steps),
        "benign_allowed": sum(s.verdict is Verdict.ALLOW for s in benign_steps),
        "benign_asked": sum(s.verdict is Verdict.ASK for s in benign_steps),
        "benign_denied": sum(s.verdict is Verdict.DENY for s in benign_steps),
    }


def markdown_table(summaries: dict[str, dict]) -> str:
    head = ("| defence | attacks stopped | denied outright | sent to human | known gaps stopped "
            "| benign allowed | benign needing approval | benign wrongly denied |\n|---|---|---|---|---|---|---|---|\n")
    rows = []
    for name, s in summaries.items():
        rows.append(f"| {name} | **{s['stopped']}/{s['attacks']}** | {s['denied']} | {s['escalated']} | "
                    f"{s['known_gaps_stopped']} | {s['benign_allowed']}/{s['benign_steps']} | {s['benign_asked']} | "
                    f"{s['benign_denied']} |")
    return head + "\n".join(rows) + "\n"
