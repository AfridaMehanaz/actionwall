import json

from actionwall.audit import AuditLog
from actionwall.cli import main


def test_check_exit_codes(ws, capsys):
    assert main(["check", "shell", "pytest -q", "--workspace", str(ws)]) == 0
    assert main(["check", "shell", "git push origin main", "--workspace", str(ws)]) == 2
    assert main(["check", "shell", "cat ~/.ssh/id_rsa", "--workspace", str(ws)]) == 1


def test_check_json(ws, capsys):
    main(["check", "http", "https://webhook.site/x", "--json", "--workspace", str(ws)])
    out = json.loads(capsys.readouterr().out)
    assert out["verdict"] == "deny" and out["findings"][0]["rule"] == "net.deny_domain"


def test_verify(tmp_path, capsys):
    p = tmp_path / "a.jsonl"
    AuditLog(p).append({"event": "x"})
    assert main(["verify", str(p)]) == 0
    p.write_text(p.read_text().replace('"x"', '"y"'))
    assert main(["verify", str(p)]) == 1
    assert "TAMPERED" in capsys.readouterr().out


def test_policy_prints_yaml(capsys):
    main(["policy"])
    assert "allow_domains" in capsys.readouterr().out


def test_bench_prints_table(capsys):
    main(["bench"])
    assert "| actionwall |" in capsys.readouterr().out
