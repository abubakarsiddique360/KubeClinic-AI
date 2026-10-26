from __future__ import annotations

import json
from pathlib import Path

from kubeclinic.cli import main

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def test_scan_broken_exits_one(capsys) -> None:
    assert main(["scan", str(EXAMPLES / "broken")]) == 1
    out = capsys.readouterr().out
    assert "ERROR" in out
    assert "privileged-container" in out


def test_scan_healthy_passes(capsys) -> None:
    assert main(["scan", str(EXAMPLES / "healthy")]) == 0
    assert "resource(s) scanned" in capsys.readouterr().out


def test_scan_json(capsys) -> None:
    assert main(["scan", str(EXAMPLES / "broken"), "--json"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "fail"
    assert payload["findings"][0]["severity"] == "error"
    assert payload["resources"]


def test_min_severity_filters_warnings(capsys) -> None:
    assert main(["scan", str(EXAMPLES / "healthy"), "--min-severity", "error"]) == 0
    assert "WARNING" not in capsys.readouterr().out


def test_rules_listing(capsys) -> None:
    assert main(["rules"]) == 0
    out = capsys.readouterr().out
    assert "privileged-container" in out
    assert "rule(s)" in out


def test_explain_rule(capsys) -> None:
    assert main(["explain", "missing-probes"]) == 0
    out = capsys.readouterr().out
    assert "severity" in out
    assert "readiness/liveness" in out


def test_explain_unknown_rule(capsys) -> None:
    assert main(["explain", "nope"]) == 2
    assert "unknown rule" in capsys.readouterr().err


def test_missing_path_exits_two(tmp_path, capsys) -> None:
    assert main(["scan", str(tmp_path / "nope")]) == 2
    assert "error" in capsys.readouterr().err
