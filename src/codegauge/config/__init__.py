"""Configuration layer for codegauge."""

from .config import ConfigLoadError, load_config
from .schema import CodeGaugeConfig, DEFAULT_SCANNER_NAMES, ScannerSettings, ThresholdConfig, UIConfig

__all__ = [
    "CodeGaugeConfig",
    "ConfigLoadError",
    "DEFAULT_SCANNER_NAMES",
    "ScannerSettings",
    "ThresholdConfig",
    "UIConfig",
    "load_config",
]
