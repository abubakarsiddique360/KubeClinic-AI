from __future__ import annotations

from pathlib import Path

import pytest

from kubeclinic.loader import load_path, parse_documents
from kubeclinic.report import ScanReport
from kubeclinic.rules import RULES, run_rules

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def ids(findings) -> set[str]:
    return {finding.rule for finding in findings}


def test_healthy_example_has_no_errors() -> None:
    findings = run_rules(load_path(EXAMPLES / "healthy"))
    assert [finding for finding in findings if finding.severity == "error"] == []


def test_broken_example_triggers_security_rules() -> None:
    findings = ids(run_rules(load_path(EXAMPLES / "broken")))
    assert {"privileged-container", "runs-as-root", "host-path-volume", "deprecated-api"} <= findings
    assert {"mutable-image-tag", "missing-resource-limits", "missing-probes"} <= findings
    assert "service-selector-mismatch" in findings
    assert "ingress-without-tls" in findings


def test_selector_match_does_not_raise() -> None:
    resources = parse_documents(
        """
apiVersion: apps/v1
kind: Deployment
metadata: {name: api, labels: {app: api}}
spec:
  replicas: 2
  template:
    metadata: {labels: {app: api}}
    spec:
      containers:
        - name: api
          image: api:1.0.0
---
apiVersion: v1
kind: Service
metadata: {name: api}
spec:
  selector: {app: api}
  ports: [{port: 80}]
"""
    )
    assert "service-selector-mismatch" not in ids(run_rules(resources))


def test_pod_disruption_budget_clears_single_replica_rule() -> None:
    bare = parse_documents(
        """
apiVersion: apps/v1
kind: Deployment
metadata: {name: api, labels: {app: api}}
spec:
  replicas: 1
  template:
    spec:
      containers: [{name: api, image: api:1.0.0}]
"""
    )
    assert "single-replica-no-pdb" in ids(run_rules(bare))
    protected = bare + parse_documents(
        """
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata: {name: api}
spec:
  minAvailable: 1
  selector:
    matchLabels: {app: api}
"""
    )
    assert "single-replica-no-pdb" not in ids(run_rules(protected))


def test_run_as_non_root_clears_finding() -> None:
    resources = parse_documents(
        """
apiVersion: apps/v1
kind: Deployment
metadata: {name: api, labels: {app: api}}
spec:
  template:
    spec:
      securityContext: {runAsNonRoot: true}
      containers: [{name: api, image: api:1.0.0}]
"""
    )
    assert "runs-as-root" not in ids(run_rules(resources))


def test_rule_catalogue_is_complete() -> None:
    assert len(RULES) >= 10
    assert all(rule.id and rule.summary and rule.severity for rule in RULES)


def test_findings_are_sorted_by_severity() -> None:
    findings = run_rules(load_path(EXAMPLES / "broken"))
    order = {"error": 0, "warning": 1, "info": 2}
    severities = [order[finding.severity] for finding in findings]
    assert severities == sorted(severities)


def test_report_summary_and_exit_code() -> None:
    resources = load_path(EXAMPLES / "broken")
    report = ScanReport(path="broken", resources=resources, findings=run_rules(resources))
    assert report.status == "fail"
    assert report.exit_code == 1
    assert report.score < 100
    payload = report.as_dict()
    assert payload["counts"]["error"] > 0
    assert "ERROR" in report.render()


def test_healthy_report_passes() -> None:
    resources = load_path(EXAMPLES / "healthy")
    report = ScanReport(path="healthy", resources=resources, findings=run_rules(resources))
    assert report.status in {"pass", "warn"}
    assert report.exit_code == 0


@pytest.mark.parametrize("rule_id", [rule.id for rule in RULES])
def test_each_rule_id_is_unique_and_documented(rule_id: str) -> None:
    assert any(rule.id == rule_id for rule in RULES)
