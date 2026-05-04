from __future__ import annotations

import json
from pathlib import Path

from codegauge.scanners.django_template_scan_scanner import DjangoTemplateScanScanner


def _run(project: Path) -> list[dict]:
    result = DjangoTemplateScanScanner().execute(project)
    payload = json.loads(result.stdout)
    return payload["findings"]


def test_flags_post_form_without_csrf(tmp_path: Path) -> None:
    project = tmp_path / "repo"
    template_dir = project / "templates" / "app"
    template_dir.mkdir(parents=True)
    (template_dir / "form.html").write_text(
        '<form method="post"><input name="name"></form>',
        encoding="utf-8",
    )

    findings = _run(project)
    assert any(item["rule_id"] == "DJG.TPL.CSRF_TOKEN_MISSING" for item in findings)


def test_does_not_flag_post_form_with_hidden_csrf_input(tmp_path: Path) -> None:
    project = tmp_path / "repo"
    template_dir = project / "templates" / "app"
    template_dir.mkdir(parents=True)
    (template_dir / "form.html").write_text(
        '<form method="post"><input type="hidden" name="csrf_token" value="x"></form>',
        encoding="utf-8",
    )

    findings = _run(project)
    assert not any(item["rule_id"] == "DJG.TPL.CSRF_TOKEN_MISSING" for item in findings)


def test_does_not_flag_post_form_with_csrf_macro_helper(tmp_path: Path) -> None:
    project = tmp_path / "repo"
    template_dir = project / "templates" / "app"
    template_dir.mkdir(parents=True)
    (template_dir / "form.html").write_text(
        '<form method="post">{{ csrf_input() }}</form>',
        encoding="utf-8",
    )

    findings = _run(project)
    assert not any(item["rule_id"] == "DJG.TPL.CSRF_TOKEN_MISSING" for item in findings)


def test_does_not_flag_get_form(tmp_path: Path) -> None:
    project = tmp_path / "repo"
    template_dir = project / "templates" / "app"
    template_dir.mkdir(parents=True)
    (template_dir / "form.html").write_text(
        '<form method="get"><input name="q"></form>',
        encoding="utf-8",
    )

    findings = _run(project)
    assert not any(item["rule_id"] == "DJG.TPL.CSRF_TOKEN_MISSING" for item in findings)


def test_does_not_flag_docs_and_tests_templates(tmp_path: Path) -> None:
    project = tmp_path / "repo"
    docs_dir = project / "templates" / "docs"
    test_dir = project / "templates" / "tests"
    docs_dir.mkdir(parents=True)
    test_dir.mkdir(parents=True)
    (docs_dir / "example.html").write_text('<form method="post"></form>', encoding="utf-8")
    (test_dir / "fixture.html").write_text('<form method="post"></form>', encoding="utf-8")

    findings = _run(project)
    assert not any(item["rule_id"] == "DJG.TPL.CSRF_TOKEN_MISSING" for item in findings)
