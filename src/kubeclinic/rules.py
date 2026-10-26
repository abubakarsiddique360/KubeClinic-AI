"""The diagnostic rules.

Each rule is a pure function over the scanned resource set, so a finding can always
be traced to a few lines of Python and a manifest.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from kubeclinic.loader import Resource, workloads

ERROR = "error"
WARNING = "warning"
INFO = "info"
SEVERITY_ORDER = {ERROR: 0, WARNING: 1, INFO: 2}

DEPRECATED_APIS = {
    "extensions/v1beta1": "removed in Kubernetes 1.16",
    "apps/v1beta1": "removed in Kubernetes 1.16",
    "apps/v1beta2": "removed in Kubernetes 1.16",
    "policy/v1beta1": "removed in Kubernetes 1.25",
    "autoscaling/v2beta1": "removed in Kubernetes 1.25",
}


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str
    resource: str
    message: str
    fix: str = ""

    def as_dict(self) -> dict:
        return {
            "rule": self.rule,
            "severity": self.severity,
            "resource": self.resource,
            "message": self.message,
            "fix": self.fix,
        }


@dataclass(frozen=True)
class Rule:
    id: str
    severity: str
    summary: str
    check: Callable[[list[Resource]], list[Finding]]


def _ref(resource: Resource) -> str:
    return f"{resource.kind}/{resource.name}"


def rule_missing_limits(resources: list[Resource]) -> list[Finding]:
    findings = []
    for resource in workloads(resources):
        for container in resource.containers():
            limits = (container.get("resources") or {}).get("limits") or {}
            if not limits.get("cpu") or not limits.get("memory"):
                findings.append(
                    Finding(
                        rule="missing-resource-limits",
                        severity=WARNING,
                        resource=_ref(resource),
                        message=f"container '{container.get('name', '?')}' has no CPU and memory limits",
                        fix="set resources.limits.cpu and resources.limits.memory",
                    )
                )
    return findings


def rule_latest_tag(resources: list[Resource]) -> list[Finding]:
    findings = []
    for resource in workloads(resources):
        for container in resource.containers():
            image = str(container.get("image", ""))
            if not image:
                continue
            tag = image.rsplit("/", 1)[-1].split(":")[-1] if ":" in image.rsplit("/", 1)[-1] else ""
            if not tag or tag == "latest":
                findings.append(
                    Finding(
                        rule="mutable-image-tag",
                        severity=WARNING,
                        resource=_ref(resource),
                        message=f"container '{container.get('name', '?')}' uses a mutable image tag: {image}",
                        fix="pin an immutable tag or the image digest",
                    )
                )
    return findings


def rule_missing_probes(resources: list[Resource]) -> list[Finding]:
    findings = []
    for resource in workloads(resources):
        if resource.kind in {"Job", "CronJob"}:
            continue
        for container in resource.containers():
            if not container.get("livenessProbe") and not container.get("readinessProbe"):
                findings.append(
                    Finding(
                        rule="missing-probes",
                        severity=WARNING,
                        resource=_ref(resource),
                        message=f"container '{container.get('name', '?')}' defines no readiness or liveness probe",
                        fix="add readinessProbe and livenessProbe endpoints",
                    )
                )
    return findings


def rule_privileged(resources: list[Resource]) -> list[Finding]:
    findings = []
    for resource in workloads(resources):
        for container in resource.containers():
            context = container.get("securityContext") or {}
            if context.get("privileged") is True:
                findings.append(
                    Finding(
                        rule="privileged-container",
                        severity=ERROR,
                        resource=_ref(resource),
                        message=f"container '{container.get('name', '?')}' runs privileged",
                        fix="remove securityContext.privileged",
                    )
                )
    return findings


def rule_runs_as_root(resources: list[Resource]) -> list[Finding]:
    findings = []
    for resource in workloads(resources):
        spec_context = (resource.pod_template().get("securityContext")) or {}
        if spec_context.get("runAsNonRoot") is True:
            continue
        for container in resource.containers():
            context = container.get("securityContext") or {}
            user = context.get("runAsUser", spec_context.get("runAsUser"))
            if context.get("runAsNonRoot") is True or (isinstance(user, int) and user > 0):
                continue
            findings.append(
                Finding(
                    rule="runs-as-root",
                    severity=ERROR,
                    resource=_ref(resource),
                    message=f"container '{container.get('name', '?')}' may run as root",
                    fix="set runAsNonRoot: true and a non-zero runAsUser",
                )
            )
    return findings


def rule_host_path(resources: list[Resource]) -> list[Finding]:
    findings = []
    for resource in workloads(resources):
        for volume in resource.pod_template().get("volumes") or []:
            if "hostPath" in volume:
                findings.append(
                    Finding(
                        rule="host-path-volume",
                        severity=ERROR,
                        resource=_ref(resource),
                        message=f"volume '{volume.get('name', '?')}' mounts a host path",
                        fix="use a PersistentVolumeClaim or a projected volume",
                    )
                )
    return findings


def rule_deprecated_api(resources: list[Resource]) -> list[Finding]:
    findings = []
    for resource in resources:
        note = DEPRECATED_APIS.get(resource.api_version)
        if note:
            findings.append(
                Finding(
                    rule="deprecated-api",
                    severity=ERROR,
                    resource=_ref(resource),
                    message=f"apiVersion {resource.api_version} is {note}",
                    fix="move to the current stable API group",
                )
            )
    return findings


def rule_single_replica_without_pdb(resources: list[Resource]) -> list[Finding]:
    findings = []
    protected = {
        (resource.body.get("spec") or {}).get("selector", {}).get("matchLabels", {}).get("app")
        for resource in resources
        if resource.kind == "PodDisruptionBudget"
    }
    for resource in resources:
        if resource.kind not in {"Deployment", "StatefulSet"}:
            continue
        replicas = (resource.body.get("spec") or {}).get("replicas", 1)
        if isinstance(replicas, int) and replicas < 2 and resource.labels.get("app") not in protected:
            findings.append(
                Finding(
                    rule="single-replica-no-pdb",
                    severity=WARNING,
                    resource=_ref(resource),
                    message="single replica with no PodDisruptionBudget",
                    fix="run at least two replicas and add a PodDisruptionBudget",
                )
            )
    return findings


def rule_service_selector(resources: list[Resource]) -> list[Finding]:
    findings = []
    label_sets = [resource.labels for resource in workloads(resources) if resource.labels]
    for resource in resources:
        if resource.kind != "Service":
            continue
        selector = (resource.body.get("spec") or {}).get("selector") or {}
        if not selector:
            continue
        if not any(all(labels.get(key) == value for key, value in selector.items()) for labels in label_sets):
            findings.append(
                Finding(
                    rule="service-selector-mismatch",
                    severity=ERROR,
                    resource=_ref(resource),
                    message=f"selector {selector} matches no workload in this scan",
                    fix="align Service spec.selector with the workload pod labels",
                )
            )
    return findings


def rule_ingress_tls(resources: list[Resource]) -> list[Finding]:
    findings = []
    for resource in resources:
        if resource.kind != "Ingress":
            continue
        if not (resource.body.get("spec") or {}).get("tls"):
            findings.append(
                Finding(
                    rule="ingress-without-tls",
                    severity=WARNING,
                    resource=_ref(resource),
                    message="Ingress has no TLS block",
                    fix="add spec.tls with the host and secretName",
                )
            )
    return findings


def rule_missing_app_labels(resources: list[Resource]) -> list[Finding]:
    findings = []
    for resource in workloads(resources):
        if "app" not in resource.labels and "app.kubernetes.io/name" not in resource.labels:
            findings.append(
                Finding(
                    rule="missing-app-label",
                    severity=INFO,
                    resource=_ref(resource),
                    message="workload has no app label",
                    fix="add metadata.labels.app (or app.kubernetes.io/name)",
                )
            )
    return findings


RULES: tuple[Rule, ...] = (
    Rule("privileged-container", ERROR, "container is privileged", rule_privileged),
    Rule("runs-as-root", ERROR, "container may run as root", rule_runs_as_root),
    Rule("host-path-volume", ERROR, "host path volume mounted", rule_host_path),
    Rule("deprecated-api", ERROR, "apiVersion removed from Kubernetes", rule_deprecated_api),
    Rule("service-selector-mismatch", ERROR, "Service selects nothing", rule_service_selector),
    Rule("missing-resource-limits", WARNING, "no CPU/memory limits", rule_missing_limits),
    Rule("mutable-image-tag", WARNING, "image tag is mutable", rule_latest_tag),
    Rule("missing-probes", WARNING, "no readiness/liveness probe", rule_missing_probes),
    Rule(
        "single-replica-no-pdb",
        WARNING,
        "single replica, no disruption budget",
        rule_single_replica_without_pdb,
    ),
    Rule("ingress-without-tls", WARNING, "Ingress without TLS", rule_ingress_tls),
    Rule("missing-app-label", INFO, "workload without app label", rule_missing_app_labels),
)


def run_rules(resources: list[Resource]) -> list[Finding]:
    findings: list[Finding] = []
    for rule in RULES:
        findings.extend(rule.check(resources))
    findings.sort(key=lambda finding: (SEVERITY_ORDER[finding.severity], finding.resource, finding.rule))
    return findings


def rule_catalogue() -> list[dict]:
    return [
        {
            "id": rule.id,
            "severity": rule.severity,
            "summary": rule.summary,
            "check": f"{rule.check.__module__}.{rule.check.__name__}",
        }
        for rule in RULES
    ]
