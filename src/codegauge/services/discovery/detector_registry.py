from __future__ import annotations

from ...profiles import ProfileRegistry
from .infrastructure_detector import InfrastructureDetector
from .java_detector import JavaDetector
from .javascript_detector import JavaScriptDetector
from .python_detector import PythonDetector


class DiscoveryDetectorRegistry:
    def __init__(self, profile_registry: ProfileRegistry) -> None:
        self.python = PythonDetector(profile_registry)
        self.java = JavaDetector(profile_registry)
        self.javascript = JavaScriptDetector(profile_registry)
        self.infrastructure = InfrastructureDetector(profile_registry)
