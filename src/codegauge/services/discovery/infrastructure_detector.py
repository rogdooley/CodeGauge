from __future__ import annotations

from pathlib import Path

from ...profiles import InfrastructureProfile, ProfileRegistry
from .base import DiscoveryHelper

_INFRA_DISCOVERY_PATTERNS: dict[str, tuple[str, ...]] = {
    "dockerfiles": ("Dockerfile", "Containerfile"),
    "compose": ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"),
    "quadlets": ("*.container", "*.kube", "*.volume", "*.network"),
    "traefik": ("*traefik*.yml", "*traefik*.yaml", "*traefik*.toml"),
    "apache": ("httpd.conf", "apache2.conf", "*.apache.conf"),
    "nginx": ("nginx.conf", "*.nginx.conf"),
    "terraform": ("*.tf", "*.tfvars"),
    "shell": ("*.sh",),
}


class InfrastructureDetector:
    def __init__(self, profile_registry: ProfileRegistry) -> None:
        self.profile_registry = profile_registry

    def detect(self, root: Path) -> dict[str, object] | None:
        matches: dict[str, list[str]] = {}
        for key, patterns in _INFRA_DISCOVERY_PATTERNS.items():
            found: list[Path] = []
            for pattern in patterns:
                found.extend(DiscoveryHelper.filtered_rglob(root, pattern))
            unique = sorted({path for path in found if path.is_file()})
            matches[key] = [path.relative_to(root).as_posix() for path in unique[:100]]

        total_detected = sum(len(items) for items in matches.values())
        if total_detected == 0:
            return None

        profile_spec = self.profile_registry.get("infrastructure")
        profile = InfrastructureProfile() if profile_spec is None else profile_spec
        frameworks: list[str] = []
        if matches["dockerfiles"]:
            frameworks.append("containers")
        if matches["compose"] or matches["quadlets"]:
            frameworks.append("orchestration")
        if matches["traefik"] or matches["apache"] or matches["nginx"]:
            frameworks.append("reverse_proxy")
        if matches["terraform"]:
            frameworks.append("terraform")
        if matches["shell"]:
            frameworks.append("shell")

        return {
            "detected": True,
            "frameworks": sorted(frameworks),
            "dockerfiles": matches["dockerfiles"],
            "compose_files": matches["compose"],
            "quadlets": matches["quadlets"],
            "traefik_configs": matches["traefik"],
            "apache_configs": matches["apache"],
            "nginx_configs": matches["nginx"],
            "terraform_files": matches["terraform"],
            "shell_scripts": matches["shell"],
            "profile": {
                "scanners": list(profile.scanners),
                "parsers": list(profile.parsers),
                "metric_providers": list(profile.metric_providers),
                "cards": list(profile.cards),
                "policy_extensions": list(profile.policy_extensions),
                "cache_behavior": profile.cache_behavior,
            },
        }
