"""Aggregate findings into a scan report."""

from __future__ import annotations

from dataclasses import dataclass, field

from kubeclinic.loader import Resource
from kubeclinic.rules import ERROR, INFO, SEVERITY_ORDER, WARNING, Finding

PENALTY = {ERROR: 20, WARNING: 5, INFO: 1}


@dataclass
class ScanReport:
    path: str
    resources: list[Resource] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    def by_severity(self) -> dict[str, list[Finding]]:
        grouped: dict[str, list[Finding]] = {ERROR: [], WARNING: [], INFO: []}
        for finding in self.findings:
            grouped.setdefault(finding.severity, []).append(finding)
        return grouped

    @property
    def score(self) -> int:
        penalty = sum(PENALTY.get(finding.severity, 0) for finding in self.findings)
        return max(0, 100 - penalty)

    @property
    def status(self) -> str:
        if any(finding.severity == ERROR for finding in self.findings):
            return "fail"
        if any(finding.severity == WARNING for finding in self.findings):
            return "warn"
        return "pass"

    @property
    def exit_code(self) -> int:
        return 1 if self.status == "fail" else 0

    def as_dict(self) -> dict:
        counts = {severity: len(items) for severity, items in self.by_severity().items()}
        return {
            "path": self.path,
            "status": self.status,
            "score": self.score,
            "exit_code": self.exit_code,
            "resources": [f"{resource.kind}/{resource.name}" for resource in self.resources],
            "counts": counts,
            "findings": [finding.as_dict() for finding in self.findings],
        }

    def render(self) -> str:
        lines: list[str] = []
        for severity in sorted(self.by_severity(), key=lambda value: SEVERITY_ORDER[value]):
            items = self.by_severity()[severity]
            if not items:
                continue
            lines.append(f"{severity.upper()} ({len(items)})")
            for finding in items:
                lines.append(f"  {finding.resource:<38} {finding.rule}")
                lines.append(f"  {'':38} {finding.message}")
                if finding.fix:
                    lines.append(f"  {'':38} fix: {finding.fix}")
            lines.append("")
        if not self.findings:
            lines.append("No findings. Manifests look healthy.")
            lines.append("")
        counts = self.by_severity()
        lines.append(
            f"{len(self.resources)} resource(s) scanned · "
            f"{len(counts[ERROR])} error(s), {len(counts[WARNING])} warning(s), "
            f"{len(counts[INFO])} note(s) · score {self.score}/100 · {self.status.upper()}"
        )
        return "\n".join(lines)
