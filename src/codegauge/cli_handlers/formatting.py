from __future__ import annotations

from pathlib import Path

import typer


def render_scan_human_summary(*, project_name: str, results, summary, report_root: Path) -> None:
    score_card = summary.score_card if isinstance(summary.score_card, dict) else {}
    policy_payload = summary.policy if isinstance(summary.policy, dict) else {}
    typer.echo(
        f"Ran {len(results)} scanners for {project_name} "
        f"({sum(1 for r in results if r.success)} succeeded, {sum(1 for r in results if not r.success)} failed)"
    )
    typer.echo(f"Overall score: {float(score_card.get('overall_score', 0.0) or 0.0):.2f}")
    typer.echo(f"Grade: {score_card.get('grade', 'N/A')}")
    typer.echo(f"Policy status: {str(policy_payload.get('status', 'unknown')).upper()}")
    baseline_stats = score_card.get("baseline", {}) if isinstance(score_card, dict) else {}
    dedupe_stats = score_card.get("dedupe", {}) if isinstance(score_card, dict) else {}
    typer.echo(
        "Debt summary: "
        f"gross={int(baseline_stats.get('gross_findings', 0))}, "
        f"scored={int(baseline_stats.get('scored_findings', 0))}, "
        f"accepted={int(baseline_stats.get('accepted_debt', 0))}, "
        f"new={int(baseline_stats.get('new_findings', 0))}, "
        f"resolved={int(baseline_stats.get('resolved_findings', 0))}, "
        f"suppressed_duplicates={int(dedupe_stats.get('suppressed_count', 0))}"
    )
    java_cache = score_card.get("java_cache", {}) if isinstance(score_card, dict) else {}
    java_hits = int(java_cache.get("cache_hits", 0) or 0)
    java_misses = int(java_cache.get("cache_misses", 0) or 0)
    if (java_hits + java_misses) > 0:
        typer.echo(f"Java cache: {java_hits} hits / {java_misses} misses")
        reason_counts = java_cache.get("miss_reason_counts", {})
        if isinstance(reason_counts, dict) and reason_counts:
            compact = " ".join(f"{reason}={count}" for reason, count in sorted(reason_counts.items()))
            typer.echo(f"Miss reasons: {compact}")
    if str(policy_payload.get("status")) in {"warn", "fail"}:
        raw_reasons = policy_payload.get("reasons")
        reasons = raw_reasons if isinstance(raw_reasons, list) else []
        typer.echo(f"Policy reasons: {', '.join(str(reason) for reason in reasons)}")
    typer.echo(f"Report portal: {report_root / 'index.html'}")
