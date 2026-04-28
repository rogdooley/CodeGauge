"""Configuration layer for codegauge."""

from .config import ConfigLoadError, load_config
from .schema import CodeGaugeConfig, DEFAULT_SCANNER_NAMES, ScannerSettings, ThresholdConfig

__all__ = [
    "CodeGaugeConfig",
    "ConfigLoadError",
    "DEFAULT_SCANNER_NAMES",
    "ScannerSettings",
    "ThresholdConfig",
    "load_config",
]
