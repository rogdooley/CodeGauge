from __future__ import annotations

from collections import Counter
from collections.abc import Sequence

from ...domain.models import Finding, ScanResult
from ...scoring.models import NormalizedMetric
from .base import FindingMetricProvider, MetricProvider, ScalarMetricProvider
from .fingerprint import finding_fingerprint


class MetricsExtractor:
    """Orchestrates metric providers across scanner results."""

    def __init__(self, providers: Sequence[MetricProvider] | None = None) -> None:
        self.providers: list[MetricProvider] = list(
            providers
            or [
                FindingMetricProvider(
                    scanner_names={
                        "ruff",
                        "bandit",
                        "pyright",
                        "vulture",
                        "spotbugs",
                        "pmd",
                        "checkstyle",
                        "errorprone",
                        "dependency_check",
                        "opengrep_java",
                        "opengrep_infra",
                        "dockerfile_scan",
                        "compose_scan",
                        "quadlet_scan",
                        "reverse_proxy_scan",
                        "terraform_scan",
                        "shellcheck",
                        "django_check_deploy",
                        "django_settings_scan",
                        "django_template_scan",
                        "django_orm_health",
                        "eslint",
                        "typescript_diagnostics",
                        "npm_audit",
                        "opengrep_js",
                    }
                ),
                ScalarMetricProvider(
                    scanner_names={
                        "coverage",
                        "radon",
                        "jacoco",
                        "pmd",
                        "js_coverage",
                        "dockerfile_scan",
                        "compose_scan",
                        "quadlet_scan",
                        "reverse_proxy_scan",
                        "terraform_scan",
                    }
                ),
                FindingMetricProvider(),
            ]
        )
        self.last_duplicate_metadata: dict[str, object] = {"suppressed_count": 0, "suppressed": []}
        self.last_unique_finding_count: int = 0

    def dedupe_scan_results(self, results: Sequence[ScanResult]) -> list[ScanResult]:
        seen_keys: dict[str, dict[str, object]] = {}
        suppressed: list[dict[str, object]] = []
        per_scanner_suppressed: Counter[str] = Counter()
        deduped_results: list[ScanResult] = []
        total_findings = 0
        unique_count = 0

        for result in results:
            if not result.success:
                deduped_results.append(result)
                continue
            total_findings += len(result.findings)
            deduped, suppressed_now, unique_now = self._dedupe_findings(result, seen_keys)
            unique_count += unique_now
            suppressed.extend(suppressed_now)
            per_scanner_suppressed.update(entry["tool"] for entry in suppressed_now)
            deduped_results.append(deduped)

        self.last_duplicate_metadata = {
            "total_findings": total_findings,
            "suppressed_count": len(suppressed),
            "net_findings": unique_count,
            "suppressed_per_scanner": dict(sorted(per_scanner_suppressed.items())),
            "suppressed": suppressed,
        }
        self.last_unique_finding_count = unique_count
        return deduped_results

    def extract_from_scan_results(self, results: Sequence[ScanResult], *, dedupe: bool = True) -> list[NormalizedMetric]:
        effective_results = self.dedupe_scan_results(results) if dedupe else list(results)
        metrics: list[NormalizedMetric] = []
        for result in effective_results:
            if not result.success:
                continue
            matched = [provider for provider in self.providers if provider.supports(result.scanner_name)]
            if not matched:
                continue
            if len(matched) > 1:
                # Allow explicit scalar + findings providers, but avoid duplicate generic extraction.
                has_scalar = any(isinstance(provider, ScalarMetricProvider) for provider in matched)
                has_finding = any(isinstance(provider, FindingMetricProvider) for provider in matched)
                if has_scalar and has_finding:
                    selected = []
                    scalar_added = False
                    finding_added = False
                    for provider in matched:
                        if isinstance(provider, ScalarMetricProvider) and not scalar_added:
                            selected.append(provider)
                            scalar_added = True
                        elif isinstance(provider, FindingMetricProvider) and not finding_added:
                            selected.append(provider)
                            finding_added = True
                    matched = selected
                else:
                    matched = [matched[0]]
            for provider in matched:
                metrics.extend(provider.extract(result))
        return metrics

    def _dedupe_findings(
        self,
        result: ScanResult,
        seen_keys: dict[str, dict[str, object]],
    ) -> tuple[ScanResult, list[dict[str, object]], int]:
        deduped_findings: list[Finding] = []
        suppressed: list[dict[str, object]] = []
        unique_count = 0
        for finding in result.findings:
            dedupe_key = finding_fingerprint(finding, include_tool=False)
            full_fingerprint = finding_fingerprint(finding, include_tool=True)
            if dedupe_key in seen_keys:
                original = seen_keys[dedupe_key]
                if original["tool"] == finding.tool:
                    deduped_findings.append(finding)
                    unique_count += 1
                    continue
                suppressed.append(
                    {
                        "tool": finding.tool,
                        "full_fingerprint": full_fingerprint,
                        "dedupe_key": dedupe_key,
                        "duplicate_of": original["full_fingerprint"],
                        "rule_id": finding.rule_id,
                        "file": str(finding.file),
                        "line": finding.line,
                    }
                )
                continue
            seen_keys[dedupe_key] = {
                "full_fingerprint": full_fingerprint,
                "tool": finding.tool,
            }
            deduped_findings.append(finding)
            unique_count += 1
        return result.model_copy(update={"findings": deduped_findings}), suppressed, unique_count
