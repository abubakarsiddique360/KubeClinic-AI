from __future__ import annotations

import pytest

from kubeclinic.loader import ManifestError, load_path, parse_documents, workloads

MULTI = """\
apiVersion: v1
kind: Service
metadata:
  name: web
spec:
  selector:
    app: web
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: shop
  labels:
    app: web
spec:
  template:
    spec:
      containers:
        - name: web
          image: nginx:1.27
"""


def test_parse_documents_splits_multi_doc() -> None:
    resources = parse_documents(MULTI)
    assert [resource.kind for resource in resources] == ["Service", "Deployment"]
    assert resources[1].namespace == "shop"


def test_list_kind_is_flattened() -> None:
    text = """
apiVersion: v1
kind: List
items:
  - apiVersion: v1
    kind: ConfigMap
    metadata:
      name: a
  - apiVersion: v1
    kind: Secret
    metadata:
      name: b
"""
    assert [resource.kind for resource in parse_documents(text)] == ["ConfigMap", "Secret"]


def test_documents_without_kind_are_skipped() -> None:
    assert parse_documents("foo: bar") == []


def test_invalid_yaml_raises_with_source() -> None:
    with pytest.raises(ManifestError, match="invalid YAML"):
        parse_documents("apiVersion: [", source="broken.yaml")


def test_pod_template_reads_deployment_and_cronjob() -> None:
    deployment = parse_documents(MULTI)[1]
    assert deployment.pod_template()["containers"][0]["name"] == "web"

    cron = parse_documents(
        """
apiVersion: batch/v1
kind: CronJob
metadata: {name: nightly}
spec:
  jobTemplate:
    spec:
      template:
        spec:
          containers:
            - name: job
              image: busybox:1.36
"""
    )[0]
    assert cron.containers()[0]["name"] == "job"


def test_workloads_filter() -> None:
    resources = parse_documents(MULTI)
    assert [resource.kind for resource in workloads(resources)] == ["Deployment"]


def test_load_path_reads_directory(tmp_path) -> None:
    (tmp_path / "a.yaml").write_text(MULTI, encoding="utf-8")
    (tmp_path / "nested").mkdir()
    (tmp_path / "nested" / "b.yml").write_text(MULTI, encoding="utf-8")
    assert len(load_path(tmp_path)) == 4


def test_load_path_missing_raises(tmp_path) -> None:
    with pytest.raises(ManifestError, match="not found"):
        load_path(tmp_path / "nope")
