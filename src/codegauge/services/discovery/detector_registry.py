from __future__ import annotations

from ...profiles import ProfileRegistry
from .go_detector import GoDetector
from .infrastructure_detector import InfrastructureDetector
from .java_detector import JavaDetector
from .javascript_detector import JavaScriptDetector
from .php_detector import PHPDetector
from .python_detector import PythonDetector


class DiscoveryDetectorRegistry:
    def __init__(self, profile_registry: ProfileRegistry) -> None:
        self.python = PythonDetector(profile_registry)
        self.java = JavaDetector(profile_registry)
        self.javascript = JavaScriptDetector(profile_registry)
        self.php = PHPDetector(profile_registry)
        self.go = GoDetector(profile_registry)
        self.infrastructure = InfrastructureDetector(profile_registry)
