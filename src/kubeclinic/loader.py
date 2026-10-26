"""Load Kubernetes YAML into a flat list of resources.

Multi-document files, ``kind: List`` bundles and directory trees are all accepted,
so a single scan can cover an entire ``k8s/`` folder.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

WORKLOAD_KINDS = {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Pod", "Job", "CronJob"}


class ManifestError(ValueError):
    """Raised when a manifest file cannot be parsed."""


@dataclass(frozen=True)
class Resource:
    kind: str
    name: str
    namespace: str = "default"
    api_version: str = ""
    body: dict = field(default_factory=dict)
    source: str = ""

    @property
    def labels(self) -> dict:
        meta = self.body.get("metadata") or {}
        return meta.get("labels") or {}

    def pod_template(self) -> dict:
        """Return the pod spec for a workload, or ``{}`` when not applicable."""

        if self.kind == "Pod":
            return self.body.get("spec") or {}
        if self.kind == "CronJob":
            job = (self.body.get("spec") or {}).get("jobTemplate") or {}
            template = (job.get("spec") or {}).get("template") or {}
        else:
            template = (self.body.get("spec") or {}).get("template") or {}
        return template.get("spec") or {}

    def containers(self) -> list[dict]:
        spec = self.pod_template()
        return list(spec.get("containers") or []) + list(spec.get("initContainers") or [])


def parse_documents(text: str, source: str = "<string>") -> list[Resource]:
    try:
        documents = list(yaml.safe_load_all(text))
    except yaml.YAMLError as exc:
        raise ManifestError(f"{source}: invalid YAML: {exc}") from exc

    resources: list[Resource] = []
    for document in documents:
        if not isinstance(document, dict):
            continue
        kind = str(document.get("kind", "")).strip()
        if not kind:
            continue
        if kind == "List":
            for item in document.get("items") or []:
                if isinstance(item, dict) and item.get("kind"):
                    resources.append(_to_resource(item, source))
            continue
        resources.append(_to_resource(document, source))
    return resources


def _to_resource(document: dict, source: str) -> Resource:
    metadata = document.get("metadata") or {}
    return Resource(
        kind=str(document.get("kind")),
        name=str(metadata.get("name") or "<unnamed>"),
        namespace=str(metadata.get("namespace") or "default"),
        api_version=str(document.get("apiVersion") or ""),
        body=document,
        source=source,
    )


def load_path(path: Path | str) -> list[Resource]:
    root = Path(path)
    if not root.exists():
        raise ManifestError(f"path not found: {root}")
    files = [root] if root.is_file() else sorted(root.rglob("*.y*ml"))
    resources: list[Resource] = []
    for file in files:
        resources.extend(parse_documents(file.read_text(encoding="utf-8"), source=str(file)))
    return resources


def workloads(resources: list[Resource]) -> list[Resource]:
    return [resource for resource in resources if resource.kind in WORKLOAD_KINDS]
