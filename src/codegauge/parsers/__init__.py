"""Parser adapters for various scanners."""

from .bandit_parser import BanditParser
from .checkstyle_parser import CheckstyleParser
from .compose_scan_parser import ComposeScanParser
from .coverage_parser import CoverageParser
from .django_check_deploy_parser import DjangoCheckDeployParser
from .django_orm_health_parser import DjangoOrmHealthParser
from .django_settings_scan_parser import DjangoSettingsScanParser
from .django_template_scan_parser import DjangoTemplateScanParser
from .dependency_check_parser import DependencyCheckParser
from .dockerfile_scan_parser import DockerfileScanParser
from .eslint_parser import ESLintParser
from .errorprone_parser import ErrorProneParser
from .jacoco_parser import JaCoCoParser
from .js_coverage_parser import JSCoverageParser
from .npm_audit_parser import NPMAuditParser
from .opengrep_infra_parser import OpenGrepInfraParser
from .base import (
    FindingPathInvalidError,
    ScannerOutputInvalidError,
    ScannerParseError,
    ScannerParser,
    normalize_finding_path,
)
from .formats import parse_json_document, parse_sarif_runs, require_list, require_object, require_string
from .opengrep_parser import OpenGrepParser, OpenGrepRuleMapping, load_opengrep_rule_mapping
from .opengrep_java_parser import OpenGrepJavaParser, load_spring_rule_mapping
from .opengrep_js_parser import OpenGrepJSParser
from .pmd_parser import PMDParser
from .pyright_parser import PyrightParser
from .quadlet_scan_parser import QuadletScanParser
from .radon_parser import RadonParser
from .reverse_proxy_scan_parser import ReverseProxyScanParser
from .ruff_parser import RuffParser, RuffRuleMapping, load_ruff_rule_mapping
from .shellcheck_parser import ShellCheckParser
from .spotbugs_parser import SpotBugsParser
from .terraform_scan_parser import TerraformScanParser
from .typescript_diagnostics_parser import TypeScriptDiagnosticsParser
from .vulture_parser import VultureParser

__all__ = [
    "BanditParser",
    "CheckstyleParser",
    "ComposeScanParser",
    "CoverageParser",
    "DjangoCheckDeployParser",
    "DjangoOrmHealthParser",
    "DjangoSettingsScanParser",
    "DjangoTemplateScanParser",
    "DependencyCheckParser",
    "DockerfileScanParser",
    "ESLintParser",
    "ErrorProneParser",
    "FindingPathInvalidError",
    "JaCoCoParser",
    "JSCoverageParser",
    "NPMAuditParser",
    "OpenGrepInfraParser",
    "OpenGrepJavaParser",
    "OpenGrepJSParser",
    "OpenGrepParser",
    "OpenGrepRuleMapping",
    "PMDParser",
    "PyrightParser",
    "QuadletScanParser",
    "RadonParser",
    "ReverseProxyScanParser",
    "RuffParser",
    "RuffRuleMapping",
    "ShellCheckParser",
    "ScannerOutputInvalidError",
    "ScannerParseError",
    "ScannerParser",
    "normalize_finding_path",
    "load_opengrep_rule_mapping",
    "load_ruff_rule_mapping",
    "parse_json_document",
    "parse_sarif_runs",
    "require_list",
    "require_object",
    "require_string",
    "SpotBugsParser",
    "TerraformScanParser",
    "TypeScriptDiagnosticsParser",
    "VultureParser",
    "load_spring_rule_mapping",
]
