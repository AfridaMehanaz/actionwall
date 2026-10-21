"""Tamper-evident audit log.

Each JSONL entry embeds the hash of the previous one, so editing, deleting or
reordering any past entry breaks the chain from that point on. With a key,
entries are HMAC'd, so an attacker who can write the file still can't forge
a valid chain.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

GENESIS = "0" * 64


def _digest(body: dict, key: bytes | None) -> str:
    data = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    if key:
        return hmac.new(key, data, hashlib.sha256).hexdigest()
    return hashlib.sha256(data).hexdigest()


@dataclass
class VerifyResult:
    ok: bool
    entries: int
    broken_at: int | None = None  # 1-based line number of the first bad entry
    reason: str = ""


class AuditLog:
    def __init__(self, path: str | os.PathLike, key: bytes | str | None = None):
        self.path = Path(path)
        self.key = key.encode() if isinstance(key, str) else key
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._prev, self._seq = self._tail()

    def _tail(self) -> tuple[str, int]:
        if not self.path.exists():
            return GENESIS, 0
        last = None
        seq = 0
        with self.path.open() as f:
            for line in f:
                if line.strip():
                    last = line
                    seq += 1
        return (json.loads(last)["hash"], seq) if last else (GENESIS, 0)

    def append(self, event: dict) -> dict:
        with self._lock:
            body = {
                "seq": self._seq + 1,
                "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
                "prev": self._prev,
                **event,
            }
            entry = {**body, "hash": _digest(body, self.key)}
            with self.path.open("a") as f:
                f.write(json.dumps(entry, sort_keys=True) + "\n")
            self._prev, self._seq = entry["hash"], body["seq"]
            return entry


def verify(path: str | os.PathLike, key: bytes | str | None = None) -> VerifyResult:
    key = key.encode() if isinstance(key, str) else key
    prev, n = GENESIS, 0
    with Path(path).open() as f:
        for lineno, line in enumerate(f, start=1):
            if not line.strip():
                continue
            n += 1
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                return VerifyResult(False, n, lineno, "not valid JSON")
            claimed = entry.pop("hash", None)
            if entry.get("prev") != prev:
                return VerifyResult(False, n, lineno, "chain broken: entry does not follow the previous one")
            if entry.get("seq") != n:
                return VerifyResult(False, n, lineno, f"sequence gap: expected {n}, found {entry.get('seq')}")
            if claimed != _digest(entry, key):
                return VerifyResult(False, n, lineno, "hash mismatch: entry was modified")
            prev = claimed
    return VerifyResult(True, n)
