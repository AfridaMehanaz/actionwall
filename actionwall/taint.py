"""Secret taint tracking.

Domain allowlists stop an agent from talking to evil.com. They don't stop a
prompt-injected agent from pasting your API key into a GitHub gist, which is
an allowed domain. So the wall remembers every secret the agent has *seen*
(file reads, tool output, environment dumps) and blocks any outbound action
that carries one, including the usual disguises: base64, hex, URL-encoding,
reversal, and DNS-label splitting.
"""

from __future__ import annotations

import base64
import binascii
import math
import re
from dataclasses import dataclass, field
from urllib.parse import quote, unquote

from .actions import Finding, Verdict

KNOWN_TOKENS = [
    ("anthropic_key", re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}")),
    ("openai_key", re.compile(r"sk-(?:proj-)?[A-Za-z0-9_-]{20,}")),
    ("github_token", re.compile(r"(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})")),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("slack_token", re.compile(r"xox[abprs]-[A-Za-z0-9-]{10,}")),
    ("stripe_key", re.compile(r"\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}")),
    ("google_api_key", re.compile(r"AIza[0-9A-Za-z_-]{35}")),
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
]
SECRET_KEY_NAME = re.compile(r"(?i)(secret|token|password|passwd|pwd|api[_-]?key|access[_-]?key|private[_-]?key|credential|auth)")
ASSIGNMENT = re.compile(r"""(?m)^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)\s*[:=]\s*["']?([^\s"'#]+)""")


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {c: s.count(c) for c in set(s)}
    return -sum(n / len(s) * math.log2(n / len(s)) for n in counts.values())


def _variants(secret: str) -> dict[str, str]:
    """The disguises an exfiltrating agent is most likely to use."""
    b = secret.encode()
    v = {
        "raw": secret,
        "base64": base64.b64encode(b).decode().rstrip("="),
        "base64url": base64.urlsafe_b64encode(b).decode().rstrip("="),
        "base32": base64.b32encode(b).decode().rstrip("="),
        "hex": binascii.hexlify(b).decode(),
        "urlencoded": quote(secret, safe=""),
        "reversed": secret[::-1],
    }
    return {k: s for k, s in v.items() if len(s) >= 8}


@dataclass
class TaintTracker:
    min_length: int = 12
    secrets: dict[str, str] = field(default_factory=dict)  # secret -> where it was seen

    # -- learning ---------------------------------------------------------------
    def observe(self, text: str, source: str) -> list[str]:
        """Record secrets in content the agent has read. Returns the new ones."""
        found: list[str] = []
        for _, pat in KNOWN_TOKENS:
            found += pat.findall(text)
        for key, value in ASSIGNMENT.findall(text):
            if SECRET_KEY_NAME.search(key) and len(value) >= self.min_length:
                found.append(value)
        for tok in re.findall(r"[A-Za-z0-9+/_=-]{24,}", text):  # high-entropy blobs
            if shannon_entropy(tok) >= 4.0 and re.search(r"\d", tok) and re.search(r"[A-Za-z]", tok):
                found.append(tok)
        new = [s for s in dict.fromkeys(found) if s not in self.secrets and len(s) >= self.min_length]
        for s in new:
            self.secrets[s] = source
        return new

    # -- enforcement ------------------------------------------------------------
    def check_outbound(self, text: str, channel: str) -> list[Finding]:
        """Deny if text leaving the sandbox carries a tracked secret or a recognisable token."""
        findings: list[Finding] = []
        haystacks = {text, unquote(text)}
        dns_joined = re.sub(r"[.\-]", "", text)  # secrets split across DNS labels: ab12.cd34.evil.com
        for secret, source in self.secrets.items():
            for name, form in _variants(secret).items():
                if any(form in h for h in haystacks) or (name == "raw" and secret in dns_joined):
                    findings.append(Finding(
                        Verdict.DENY, "taint.exfiltration",
                        f"{channel} carries a secret first seen in {source}" + ("" if name == "raw" else f" ({name}-encoded)")))
                    break
        if not findings:
            for name, pat in KNOWN_TOKENS:
                if pat.search(text):
                    findings.append(Finding(Verdict.DENY, "taint.token_pattern", f"{channel} contains a {name}"))
        return findings

    def scrub(self, text: str) -> str:
        """Mask tracked secrets, e.g. before writing them to the audit log."""
        for secret in sorted(self.secrets, key=len, reverse=True):
            text = text.replace(secret, "[SECRET]")
        for name, pat in KNOWN_TOKENS:
            text = pat.sub(f"[{name.upper()}]", text)
        return text
