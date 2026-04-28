from __future__ import annotations

from pathlib import Path

import pytest

from codegauge.domain.models import Category, Severity
from codegauge.parsers.base import ScannerOutputInvalidError
from codegauge.parsers.pyright_parser import PyrightParser


def test_pyright_parser_parses_diagnostics() -> None:
    parser = PyrightParser()
    project = Path.cwd()
    stdout = (
        '{"generalDiagnostics":['
        '{"file":"src/app.py","severity":"error","message":"Cannot find name x",'
        '"rule":"reportUndefinedVariable","range":{"start":{"line":2,"character":4},"end":{"line":2,"character":5}}},'
        '{"file":"src/app.py","severity":"warning","message":"Type unknown",'
        '"rule":"reportUnknownVariableType","range":{"start":{"line":5,"character":0},"end":{"line":5,"character":3}}},'
        '{"file":"src/app.py","severity":"information","message":"Hint",'
        '"rule":"reportGeneralTypeIssues","range":{"start":{"line":7,"character":1},"end":{"line":7,"character":2}}}'
        ']}'
    )
    findings = parser.parse(stdout, "", project)
    assert len(findings) == 3
    assert findings[0].severity == Severity.high
    assert findings[0].category == Category.typing
    assert findings[0].line == 3
    assert findings[0].column == 5
    assert findings[1].severity == Severity.medium
    assert findings[2].severity == Severity.info


def test_pyright_parser_rejects_invalid_structure() -> None:
    parser = PyrightParser()
    with pytest.raises(ScannerOutputInvalidError):
        parser.parse('{"generalDiagnostics":{}}', "", Path.cwd())
