import pytest


@pytest.fixture
def ws(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("print('hi')\n")
    (tmp_path / ".env").write_text("OPENAI_API_KEY=sk-proj-Q9vX2mL7pR4tY8wK1nB5cZ3h\n")
    (tmp_path / "config.yaml").write_text("analytics_token: a8Fk29dLq0Zx7Pw3Rt5YcV1b\nlog_level: info\n")
    return tmp_path


@pytest.fixture
def policy(ws):
    from actionwall.policy import Policy

    return Policy.load(workspace=ws)


@pytest.fixture
def guard(policy):
    from actionwall.guard import Guard

    return Guard(policy)
