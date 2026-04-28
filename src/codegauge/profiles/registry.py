from __future__ import annotations

from dataclasses import dataclass

from .django_profile import DjangoProfile
from .infrastructure_profile import InfrastructureProfile
from .java_profile import JavaProfile
from .javascript_profile import JavaScriptProfile, TypeScriptProfile
from .python_profile import PythonProfile


@dataclass(frozen=True)
class LanguageProfileSpec:
    name: str
    frameworks: tuple[str, ...]
    scanners: tuple[str, ...]
    parsers: tuple[str, ...]
    metric_providers: tuple[str, ...]
    cards: tuple[str, ...]
    policy_extensions: tuple[str, ...]
    cache_behavior: str


def _spec_from_profile(profile: object) -> LanguageProfileSpec:
    return LanguageProfileSpec(
        name=str(getattr(profile, "name")),
        frameworks=tuple(getattr(profile, "frameworks")),
        scanners=tuple(getattr(profile, "scanners")),
        parsers=tuple(getattr(profile, "parsers")),
        metric_providers=tuple(getattr(profile, "metric_providers")),
        cards=tuple(getattr(profile, "cards")),
        policy_extensions=tuple(getattr(profile, "policy_extensions")),
        cache_behavior=str(getattr(profile, "cache_behavior")),
    )


class ProfileRegistry:
    def __init__(self) -> None:
        self._profiles: dict[str, LanguageProfileSpec] = {}

    def register(self, profile: LanguageProfileSpec) -> None:
        self._profiles[profile.name] = profile

    def get(self, name: str) -> LanguageProfileSpec | None:
        return self._profiles.get(name)

    def all(self) -> list[LanguageProfileSpec]:
        return [self._profiles[name] for name in sorted(self._profiles.keys())]

    @classmethod
    def with_builtins(cls) -> ProfileRegistry:
        registry = cls()
        registry.register(_spec_from_profile(PythonProfile()))
        registry.register(_spec_from_profile(DjangoProfile()))
        registry.register(_spec_from_profile(JavaProfile()))
        registry.register(_spec_from_profile(JavaScriptProfile()))
        registry.register(_spec_from_profile(TypeScriptProfile()))
        registry.register(_spec_from_profile(InfrastructureProfile()))
        return registry
