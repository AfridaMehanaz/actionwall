import json

from actionwall.audit import AuditLog, verify


def write_log(path, n=3, key=None):
    log = AuditLog(path, key=key)
    for i in range(n):
        log.append({"event": "decision", "i": i})
    return log


def test_intact_chain_verifies(tmp_path):
    p = tmp_path / "a.jsonl"
    write_log(p)
    r = verify(p)
    assert r.ok and r.entries == 3


def test_reopening_continues_the_chain(tmp_path):
    p = tmp_path / "a.jsonl"
    write_log(p, 2)
    write_log(p, 2)
    assert verify(p).entries == 4 and verify(p).ok


def test_edit_is_detected(tmp_path):
    p = tmp_path / "a.jsonl"
    write_log(p)
    lines = p.read_text().splitlines()
    e = json.loads(lines[1])
    e["i"] = 99
    lines[1] = json.dumps(e)
    p.write_text("\n".join(lines) + "\n")
    r = verify(p)
    assert not r.ok and r.broken_at == 2 and "modified" in r.reason


def test_deletion_is_detected(tmp_path):
    p = tmp_path / "a.jsonl"
    write_log(p)
    lines = p.read_text().splitlines()
    p.write_text(lines[0] + "\n" + lines[2] + "\n")
    assert verify(p).broken_at == 2


def test_rehashed_forgery_fails_with_key(tmp_path):
    """An attacker who recomputes plain SHA-256 hashes cannot forge an HMAC'd log."""
    import hashlib

    p = tmp_path / "a.jsonl"
    write_log(p, 1, key="k")
    e = json.loads(p.read_text())
    e.pop("hash")
    e["i"] = 42
    e["hash"] = hashlib.sha256(json.dumps(e, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    p.write_text(json.dumps(e) + "\n")
    assert verify(p).ok              # without the key the forgery looks fine...
    assert not verify(p, key="k").ok  # ...with it, it doesn't
