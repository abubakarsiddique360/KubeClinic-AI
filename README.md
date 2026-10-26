# KubeClinic AI

**Paste a manifests folder, get a diagnosis: what will break, what is unsafe, and the exact line to change.**

Cluster-side tools tell you a pod failed. KubeClinic reads the manifests *before*
they are applied and reports the problems that cause those failures — privileged
containers, root users, `:latest` images, missing limits and probes, host path
mounts, Service selectors that match nothing, deprecated APIs, single replicas
without a disruption budget.

[![CI](https://github.com/abubakarsiddique360/KubeClinic-AI/actions/workflows/ci.yml/badge.svg)](https://github.com/abubakarsiddique360/KubeClinic-AI/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.12-blue)](pyproject.toml)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

## Quick start

```bash
git clone https://github.com/abubakarsiddique360/KubeClinic-AI.git
cd KubeClinic-AI
python -m venv .venv
# Windows: .venv\Scripts\activate     macOS/Linux: source .venv/bin/activate
pip install -e ".[dev]"

kubeclinic scan examples/broken
kubeclinic scan examples/healthy
kubeclinic rules
```

```
ERROR (4)
  Deployment/checkout                    privileged-container
                                         container 'api' runs privileged
                                         fix: remove securityContext.privileged
  Deployment/checkout                    runs-as-root
                                         container 'api' may run as root
                                         fix: set runAsNonRoot: true and a non-zero runAsUser
  ...
3 resource(s) scanned · 4 error(s), 6 warning(s), 0 note(s) · score 0/100 · FAIL
```

Exit code is `1` when any error-severity finding exists, so `kubeclinic scan` works
as a pre-commit or CI gate.

## Rules

| Rule | Severity | Catches |
| --- | --- | --- |
| `privileged-container` | error | `securityContext.privileged: true` |
| `runs-as-root` | error | no `runAsNonRoot` and no non-zero `runAsUser` |
| `host-path-volume` | error | volumes mounting a host path (docker socket, `/etc`, …) |
| `deprecated-api` | error | `extensions/v1beta1`, `apps/v1beta1`, `policy/v1beta1`, … |
| `service-selector-mismatch` | error | a Service whose selector matches no workload in the scan |
| `missing-resource-limits` | warning | containers without CPU **and** memory limits |
| `mutable-image-tag` | warning | untagged images or `:latest` |
| `missing-probes` | warning | no readiness and no liveness probe |
| `single-replica-no-pdb` | warning | `replicas < 2` with no PodDisruptionBudget |
| `ingress-without-tls` | warning | Ingress without a `spec.tls` block |
| `missing-app-label` | info | workload without `app` / `app.kubernetes.io/name` |

`kubeclinic explain <rule>` prints the implementation path, so a finding can always
be traced back to the code that produced it.

## What it scans

- Files and directories (`examples/`, `deploy/k8s/`, a single `deployment.yaml`)
- Multi-document YAML and `kind: List` bundles
- Workloads (`Deployment`, `StatefulSet`, `DaemonSet`, `ReplicaSet`, `Pod`, `Job`,
  `CronJob`) plus `Service`, `Ingress` and `PodDisruptionBudget` for cross-resource
  checks

## JSON output

```bash
kubeclinic scan deploy/ --json | jq '.findings[] | select(.severity=="error") | {resource, rule}'
```

```json
{
  "status": "fail",
  "score": 0,
  "exit_code": 1,
  "counts": { "error": 4, "warning": 6, "info": 0 },
  "findings": [
    { "rule": "privileged-container", "severity": "error", "resource": "Deployment/checkout",
      "message": "container 'api' runs privileged", "fix": "remove securityContext.privileged" }
  ]
}
```

## Project layout

```text
src/kubeclinic/
├── loader.py    multi-doc YAML → flat resource list
├── rules.py     11 checks, each a pure function
├── report.py    severity counts, score, table + JSON
└── cli.py       scan · rules · explain
examples/        one broken and one healthy stack
tests/           36 pytest cases
```

## Design notes

- **Findings, not exceptions.** A malformed file fails the scan with exit `2`; a
  bad manifest is a *finding*, so one problem never hides the others.
- **Cross-resource checks.** The selector rule and the PDB rule need the whole
  scan, which is why rules receive the full resource list rather than one document.
- **Severity means something.** Errors block a deploy, warnings inform review,
  notes are style. `--min-severity` narrows the output without changing the verdict.
- **No cluster access.** Nothing here talks to the Kubernetes API; it reads files.

## Limitations

- Static only: it cannot see defaulted values, admission controllers, or cluster
  state, so a clean scan is not proof a manifest will run.
- The rule set is opinionated and finite. Treat it as a floor, not a policy engine —
  pair it with OPA/Kyverno for organisation-specific rules.
- No schema validation against the Kubernetes OpenAPI spec; use `kubeconform` for that.

## License

[MIT](LICENSE) © 2026 **ABU BAKAR SIDDIQUE**
