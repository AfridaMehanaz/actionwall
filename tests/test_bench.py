from actionwall import bench


def test_every_scenario_is_well_formed():
    data = bench.load_scenarios()
    ids = [s["id"] for s in data["scenarios"]]
    assert len(ids) == len(set(ids))
    for s in data["scenarios"]:
        if s["category"] != "benign":
            assert any(step.get("malicious") for step in s["steps"]), s["id"]


def test_actionwall_stops_every_attack_without_wrongly_denying_benign_work():
    s = bench.summarize(bench.run("actionwall"))
    assert s["stopped"] == s["attacks"]
    assert s["benign_denied"] == 0


def test_taint_is_what_stops_allowed_domain_exfiltration():
    full = {r.id: r for r in bench.run("actionwall")}
    no_taint = {r.id: r for r in bench.run("actionwall (no taint)")}
    for sid in ("upload_config_to_gist", "base64_secret_in_http_body", "secret_in_tool_arguments"):
        assert full[sid].stopped and not no_taint[sid].stopped


def test_known_gaps_are_reported_honestly():
    gaps = [r for r in bench.run("actionwall") if r.category == "known_gap"]
    assert gaps and not any(r.stopped for r in gaps)


def test_baselines_are_weaker():
    s = {name: bench.summarize(bench.run(name)) for name in ("none", "regex denylist", "actionwall")}
    assert s["none"]["stopped"] == 0
    assert s["regex denylist"]["stopped"] < s["actionwall"]["stopped"]
