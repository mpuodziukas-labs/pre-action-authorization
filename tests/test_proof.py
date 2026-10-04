import json, pathlib, sys
import pytest
ROOT = pathlib.Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))
import gate, evaluate

ROWS = evaluate.rows()


@pytest.fixture()
def world(tmp_path):
    return evaluate.build_world(tmp_path)


def decide(world, row):
    ws, policy = world
    return gate.authorize({"class": row["class"], "value": row["value"].replace("{ws}", ws)}, policy)


@pytest.mark.parametrize("row", [r for r in ROWS if r["expect"] == "ALLOW"], ids=lambda r: r["id"])
def test_control_is_allowed(world, row):
    verdict, reason = decide(world, row)
    assert verdict == "ALLOW", reason


@pytest.mark.parametrize("row", [r for r in ROWS if r["expect"] == "DENY"], ids=lambda r: r["id"])
def test_planted_bypass_is_denied_with_reason(world, row):
    verdict, reason = decide(world, row)
    assert verdict == "DENY" and reason, (verdict, reason)


@pytest.mark.parametrize("request_", [
    None, [], "model", {}, {"class": "model"}, {"value": "small-model-v1"},
    {"class": "model", "value": None}, {"class": "model", "value": 7},
    {"class": None, "value": "x"}, {"class": "model", "value": ""},
    {"class": "model", "value": "small-model-v1", "extra": 1},
], ids=lambda r: repr(r)[:40])
def test_malformed_request_is_denied(world, request_):
    assert gate.authorize(request_, world[1])[0] == "DENY"


@pytest.mark.parametrize("policy", [None, {}, {"workspace": "relative/dir"}, {"workspace": "/nonexistent-dir-xyz"}])
def test_malformed_policy_is_denied(policy):
    assert gate.authorize({"class": "path", "value": "src/main.py"}, policy)[0] == "DENY"


def test_policy_without_a_class_list_denies_that_class(world):
    ws, policy = world
    policy = {k: v for k, v in policy.items() if k != "hosts"}
    assert gate.authorize({"class": "egress", "value": "https://api.example.com/"}, policy)[0] == "DENY"


def test_readme_matches_output():
    readme = (ROOT / "README.md").read_text()
    assert evaluate.results() in readme, "README results drifted from evaluate.py"


def mutant_results(monkeypatch, name, value):
    real = evaluate.results()
    monkeypatch.setattr(gate, name, value)
    assert evaluate.results() != real, f"mutant {name} was not caught"


def test_mutant_symlinks_not_resolved(monkeypatch):
    mutant_results(monkeypatch, "_resolve", gate.os.path.abspath)


def test_mutant_userinfo_allowed(monkeypatch):
    mutant_results(monkeypatch, "_bad_netloc", lambda netloc: False)


def test_mutant_destructive_verbs_empty(monkeypatch):
    # Changed 2026-10-04: the allowlist now also refuses rm, so the verdict table cannot move.
    # The destructive-verb layer is still pinned by its refusal reason.
    ws, policy = evaluate.build_world(pathlib.Path(__import__("tempfile").mkdtemp()))
    assert "destructive verb" in gate.authorize({"class": "shell", "value": "rm -rf src"}, policy)[1]
    monkeypatch.setattr(gate, "DESTRUCTIVE", frozenset())
    assert "destructive verb" not in gate.authorize({"class": "shell", "value": "rm -rf src"}, policy)[1]


def test_mutant_secret_globs_empty(monkeypatch):
    mutant_results(monkeypatch, "SECRET_GLOBS", ())


def test_mutant_non_ascii_host_allowed(monkeypatch):
    mutant_results(monkeypatch, "_ascii", lambda s: True)


def test_mutant_model_compare_case_insensitive(monkeypatch):
    real = evaluate.results()
    orig = gate.authorize

    def loose(request, policy):
        if isinstance(request, dict) and request.get("class") == "model" and isinstance(request.get("value"), str):
            request = dict(request, value=request["value"].strip().lower())
        return orig(request, policy)

    monkeypatch.setattr(evaluate.gate, "authorize", loose)
    assert evaluate.results() != real
