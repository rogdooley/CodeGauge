from __future__ import annotations

from pathlib import Path

from codegauge.domain.models import Category, Severity
from codegauge.parsers import (
    CheckstyleParser,
    DependencyCheckParser,
    JaCoCoParser,
    OpenGrepJavaParser,
    PMDParser,
    SpotBugsParser,
)


def test_spotbugs_parser_parses_xml() -> None:
    stdout = """
    <BugCollection>
      <BugInstance type="NP_NULL_ON_SOME_PATH" rank="4">
        <LongMessage>Possible null pointer dereference</LongMessage>
        <SourceLine sourcepath="src/main/java/com/acme/App.java" start="12" />
      </BugInstance>
    </BugCollection>
    """
    findings = SpotBugsParser().parse(stdout, "", Path.cwd())
    assert len(findings) == 1
    assert findings[0].severity == Severity.high
    assert findings[0].file.as_posix().endswith("src/main/java/com/acme/App.java")


def test_checkstyle_parser_parses_xml() -> None:
    stdout = """
    <checkstyle version="10.0">
      <file name="src/main/java/com/acme/App.java">
        <error line="5" column="2" severity="warning" message="unused import" source="UnusedImports" />
      </file>
    </checkstyle>
    """
    findings = CheckstyleParser().parse(stdout, "", Path.cwd())
    assert len(findings) == 1
    assert findings[0].category == Category.dead_code
    assert findings[0].severity == Severity.low


def test_pmd_parser_parses_json_and_metadata() -> None:
    stdout = """
    {
      "files": [
        {
          "filename": "src/main/java/com/acme/App.java",
          "violations": [
            {
              "rule": "CyclomaticComplexity",
              "description": "Avoid high complexity",
              "beginline": 10,
              "begincolumn": 3,
              "priority": 2
            }
          ]
        }
      ],
      "duplication": { "percentDuplicatedLines": 12.5 }
    }
    """
    parser = PMDParser()
    findings = parser.parse(stdout, "", Path.cwd())
    metadata = parser.parse_metadata(stdout, "", Path.cwd())
    assert len(findings) == 1
    assert findings[0].category == Category.complexity
    assert metadata["scalar_metrics"]["duplication_percent"] == 12.5


def test_jacoco_parser_extracts_scalars() -> None:
    stdout = """
    <report name="demo">
      <counter type="LINE" missed="20" covered="80" />
      <counter type="BRANCH" missed="10" covered="30" />
      <counter type="CLASS" missed="2" covered="18" />
      <counter type="METHOD" missed="10" covered="90" />
    </report>
    """
    metadata = JaCoCoParser().parse_metadata(stdout, "", Path.cwd())
    metrics = metadata["scalar_metrics"]
    assert metrics["coverage_percent"] == 80.0
    assert metrics["branch_coverage_percent"] == 75.0
    assert metrics["class_count"] == 20
    assert metrics["method_count"] == 100


def test_dependency_check_parser_parses_findings() -> None:
    stdout = """
    {
      "dependencies": [
        {
          "fileName": "pom.xml",
          "vulnerabilities": [
            {
              "name": "CVE-2025-1234",
              "severity": "HIGH",
              "description": "critical dependency issue"
            }
          ]
        }
      ]
    }
    """
    findings = DependencyCheckParser().parse(stdout, "", Path.cwd())
    assert len(findings) == 1
    assert findings[0].category == Category.security
    assert findings[0].severity == Severity.high


def test_opengrep_java_parser_maps_spring_posture() -> None:
    stdout = """
    {
      "version": "2.1.0",
      "runs": [
        {
          "results": [
            {
              "ruleId": "SPRING.SEC.SQLInjection",
              "message": {"text": "Avoid SQL concat"},
              "locations": [
                {
                  "physicalLocation": {
                    "artifactLocation": {"uri": "src/main/java/com/acme/Repo.java"},
                    "region": {"startLine": 14, "startColumn": 9}
                  }
                }
              ]
            }
          ]
        }
      ]
    }
    """
    findings = OpenGrepJavaParser().parse(stdout, "", Path.cwd())
    assert len(findings) == 1
    finding = findings[0]
    assert finding.category == Category.security
    assert finding.severity == Severity.high
    assert "security_posture" in finding.tags

