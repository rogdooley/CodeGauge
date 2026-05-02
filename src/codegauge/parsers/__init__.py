"""Parser adapters for various scanners."""

from .bandit_parser import BanditParser
from .checkstyle_parser import CheckstyleParser
from .composer_audit_parser import ComposerAuditParser
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
from .go_coverage_parser import GoCoverageParser
from .go_vet_parser import GoVetParser
from .git_history_secrets_parser import GitHistorySecretsParser
from .gitleaks_parser import GitleaksParser
from .govulncheck_parser import GovulncheckParser
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
from .opengrep_go_parser import OpenGrepGoParser
from .opengrep_php_parser import OpenGrepPHPParser
from .pmd_parser import PMDParser
from .phpcs_parser import PHPCSParser
from .phpstan_parser import PHPStanParser
from .pyright_parser import PyrightParser
from .quadlet_scan_parser import QuadletScanParser
from .radon_parser import RadonParser
from .reverse_proxy_scan_parser import ReverseProxyScanParser
from .ruff_parser import RuffParser, RuffRuleMapping, load_ruff_rule_mapping
from .secrets_heuristic_parser import SecretsHeuristicParser
from .shellcheck_parser import ShellCheckParser
from .spotbugs_parser import SpotBugsParser
from .staticcheck_parser import StaticcheckParser
from .terraform_scan_parser import TerraformScanParser
from .typescript_diagnostics_parser import TypeScriptDiagnosticsParser
from .trufflehog_parser import TruffleHogParser
from .vulture_parser import VultureParser

__all__ = [
    "BanditParser",
    "CheckstyleParser",
    "ComposerAuditParser",
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
    "GoCoverageParser",
    "GoVetParser",
    "GitHistorySecretsParser",
    "GitleaksParser",
    "GovulncheckParser",
    "FindingPathInvalidError",
    "JaCoCoParser",
    "JSCoverageParser",
    "NPMAuditParser",
    "OpenGrepInfraParser",
    "OpenGrepJavaParser",
    "OpenGrepJSParser",
    "OpenGrepGoParser",
    "OpenGrepPHPParser",
    "OpenGrepParser",
    "OpenGrepRuleMapping",
    "PMDParser",
    "PHPCSParser",
    "PHPStanParser",
    "PyrightParser",
    "QuadletScanParser",
    "RadonParser",
    "ReverseProxyScanParser",
    "RuffParser",
    "RuffRuleMapping",
    "SecretsHeuristicParser",
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
    "StaticcheckParser",
    "TerraformScanParser",
    "TypeScriptDiagnosticsParser",
    "TruffleHogParser",
    "VultureParser",
    "load_spring_rule_mapping",
]
