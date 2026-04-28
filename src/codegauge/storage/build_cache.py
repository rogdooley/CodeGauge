from __future__ import annotations

import hashlib
import json
import shutil
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Iterable

CACHE_SCHEMA_VERSION = "2"
TOOL_VERSION = "1"

_DESCRIPTOR_SUFFIXES = (
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "settings.gradle",
    "settings.gradle.kts",
)
_WRAPPER_SUFFIXES = ("mvnw", "gradlew")
_LOCKFILE_SUFFIXES = ("gradle.lockfile",)


@dataclass(frozen=True)
class JavaModule:
    module_name: str
    module_path: Path
    module_id: str


@dataclass(frozen=True)
class JavaCacheManifest:
    module_name: str
    module_path: str
    cache_key: str
    created_at: str
    tool: str
    artifact_paths: list[str]
    input_hashes: dict[str, str]
    cache_schema_version: str
    tool_version: str
    last_status: str
    last_reasons: list[str]
    decision_history: list[dict[str, Any]]


class JavaBuildCacheService:
    _DESCRIPTOR_FILES = (
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
        "settings.gradle",
        "settings.gradle.kts",
        "mvnw",
        "gradlew",
        "gradle.lockfile",
    )

    def __init__(self, project_root: Path) -> None:
        self.project_root = project_root
        self.cache_root = project_root / ".scan-cache" / "java" / "modules"

    def discover_modules(self) -> list[JavaModule]:
        module_dirs: set[Path] = set()
        for marker in ("pom.xml", "build.gradle", "build.gradle.kts"):
            for path in self.project_root.rglob(marker):
                module_dirs.add(path.parent.resolve())
        if not module_dirs:
            module_dirs.add(self.project_root.resolve())
        modules: list[JavaModule] = []
        for directory in sorted(module_dirs):
            module_path = directory.resolve()
            relative = module_path.relative_to(self.project_root.resolve()) if module_path != self.project_root.resolve() else Path(".")
            module_name = self.project_root.name if str(relative) == "." else relative.as_posix().replace("/", "-")
            module_id = hashlib.sha1(relative.as_posix().encode("utf-8")).hexdigest()[:12]
            modules.append(JavaModule(module_name=module_name, module_path=module_path, module_id=module_id))
        return modules

    def compute_cache_key(self, module: JavaModule, tool: str) -> tuple[str, dict[str, str]]:
        hashes: dict[str, str] = {}
        for rel_path in self._module_input_files(module):
            file_hash = self._file_hash(rel_path)
            hashes[str(rel_path)] = file_hash
        joined = "|".join(f"{path}:{digest}" for path, digest in sorted(hashes.items()))
        cache_key = hashlib.sha256(f"{tool}|{module.module_id}|{joined}".encode("utf-8")).hexdigest()
        return cache_key, hashes

    def try_reuse(
        self,
        *,
        module: JavaModule,
        tool: str,
        cache_key: str,
        input_hashes: dict[str, str] | None = None,
    ) -> tuple[list[Path] | None, list[str], JavaCacheManifest | None]:
        manifest = self.load_manifest(module.module_id, tool)
        if manifest is None:
            return None, ["manifest_missing"], None
        reasons = self._miss_reasons(manifest=manifest, cache_key=cache_key, input_hashes=input_hashes or {})
        if reasons:
            return None, reasons, manifest
        artifact_paths = [self.project_root / item for item in manifest.artifact_paths]
        if not artifact_paths:
            return None, ["artifact_missing"], manifest
        if not all(path.exists() and path.is_file() for path in artifact_paths):
            return None, ["artifact_missing"], manifest
        return artifact_paths, [], manifest

    def save_manifest(
        self,
        *,
        module: JavaModule,
        tool: str,
        cache_key: str,
        artifact_paths: list[Path],
        input_hashes: dict[str, str],
        status: str = "miss",
        reasons: list[str] | None = None,
        previous_cache_key: str | None = None,
        previous_manifest: JavaCacheManifest | None = None,
    ) -> JavaCacheManifest:
        cache_artifact_paths = self._store_cached_artifacts(module.module_id, tool, artifact_paths)
        relative_paths = [path.resolve().relative_to(self.project_root.resolve()).as_posix() for path in cache_artifact_paths]
        now = datetime.now(UTC).isoformat().replace("+00:00", "Z")
        history = list(previous_manifest.decision_history) if previous_manifest else []
        history.append(
            {
                "timestamp": now,
                "status": status,
                "reasons": list(reasons or []),
                "previous_cache_key": previous_cache_key,
                "current_cache_key": cache_key,
            }
        )
        history = history[-10:]
        manifest = JavaCacheManifest(
            module_name=module.module_name,
            module_path=module.module_path.resolve().relative_to(self.project_root.resolve()).as_posix(),
            cache_key=cache_key,
            created_at=now,
            tool=tool,
            artifact_paths=relative_paths,
            input_hashes=input_hashes,
            cache_schema_version=CACHE_SCHEMA_VERSION,
            tool_version=TOOL_VERSION,
            last_status=status,
            last_reasons=list(reasons or []),
            decision_history=history,
        )
        manifest_path = self._manifest_path(module.module_id, tool)
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        self._atomic_write_json(manifest_path, manifest.__dict__)
        return manifest

    def load_manifest(self, module_id: str, tool: str) -> JavaCacheManifest | None:
        manifest_path = self._manifest_path(module_id, tool)
        if not manifest_path.exists():
            return None
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
        return JavaCacheManifest(
            module_name=str(payload.get("module_name", "")),
            module_path=str(payload.get("module_path", "")),
            cache_key=str(payload.get("cache_key", "")),
            created_at=str(payload.get("created_at", "")),
            tool=str(payload.get("tool", "")),
            artifact_paths=[str(item) for item in payload.get("artifact_paths", [])],
            input_hashes={str(k): str(v) for k, v in payload.get("input_hashes", {}).items()},
            cache_schema_version=str(payload.get("cache_schema_version", "1")),
            tool_version=str(payload.get("tool_version", "0")),
            last_status=str(payload.get("last_status", "unknown")),
            last_reasons=[str(item) for item in payload.get("last_reasons", [])],
            decision_history=list(payload.get("decision_history", [])),
        )

    def status(self) -> dict[str, Any]:
        modules = self.discover_modules()
        module_status: list[dict[str, Any]] = []
        total_hits = 0
        total_misses = 0
        for module in modules:
            module_dir = self.cache_root / module.module_id
            manifests: list[dict[str, Any]] = []
            if module_dir.exists():
                for manifest_path in sorted(module_dir.glob("*.manifest.json")):
                    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
                    if payload.get("last_status") == "hit":
                        total_hits += 1
                    elif payload.get("last_status") == "miss":
                        total_misses += 1
                    manifests.append(payload)
            module_status.append(
                {
                    "module_name": module.module_name,
                    "module_path": module.module_path.resolve().relative_to(self.project_root.resolve()).as_posix(),
                    "module_id": module.module_id,
                    "tools": manifests,
                }
            )
        hit_rate = round((total_hits / (total_hits + total_misses)) * 100.0, 2) if (total_hits + total_misses) > 0 else None
        return {
            "project": self.project_root.name,
            "cache_root": str(self.cache_root),
            "modules": module_status,
            "totals": {
                "hits": total_hits,
                "misses": total_misses,
                "hit_rate_percent": hit_rate,
            },
        }

    def clear(self, *, module_name: str | None = None, tool: str | None = None, dry_run: bool = False) -> dict[str, Any]:
        modules = self.discover_modules()
        selected = [module for module in modules if module_name is None or module.module_name == module_name]
        removed: list[str] = []
        removed_tools: list[str] = []
        for module in selected:
            module_dir = self.cache_root / module.module_id
            if module_dir.exists():
                if tool is None:
                    removed.append(module.module_name)
                    if not dry_run:
                        shutil.rmtree(module_dir)
                else:
                    manifest = self._manifest_path(module.module_id, tool)
                    if manifest.exists():
                        removed_tools.append(f"{module.module_name}:{tool}")
                        if not dry_run:
                            manifest.unlink()
                            artifact_dir = self._tool_artifact_dir(module.module_id, tool)
                            if artifact_dir.exists():
                                shutil.rmtree(artifact_dir)
        return {
            "project": self.project_root.name,
            "dry_run": dry_run,
            "requested_module": module_name,
            "requested_tool": tool,
            "removed_modules": removed,
            "removed_tool_entries": removed_tools,
            "removed_count": len(removed),
            "removed_tool_count": len(removed_tools),
        }

    def prune(
        self,
        *,
        days: int,
        max_history: int,
        module_name: str | None = None,
        tool: str | None = None,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        if days < 1:
            raise ValueError("days must be >= 1")
        if max_history < 1:
            raise ValueError("max_history must be >= 1")

        cutoff = datetime.now(UTC) - timedelta(days=days)
        known_modules = {module.module_id: module for module in self.discover_modules()}
        removed_entries = 0
        removed_artifacts = 0
        reclaimed_bytes = 0
        modules_pruned = 0
        history_entries_pruned = 0

        for module_dir in sorted(self.cache_root.glob("*")) if self.cache_root.exists() else []:
            if not module_dir.is_dir():
                continue
            module_id = module_dir.name
            module = known_modules.get(module_id)
            if module is None:
                modules_pruned += 1
                size = self._dir_size(module_dir)
                removed_artifacts += self._count_files(module_dir)
                reclaimed_bytes += size
                if not dry_run:
                    shutil.rmtree(module_dir)
                continue
            if module_name is not None and module.module_name != module_name:
                continue

            referenced_artifacts: set[Path] = set()
            for manifest_path in sorted(module_dir.glob("*.manifest.json")):
                scanner = manifest_path.name.removesuffix(".manifest.json")
                if tool is not None and scanner != tool:
                    continue
                payload = json.loads(manifest_path.read_text(encoding="utf-8"))
                created_at = self._parse_timestamp(str(payload.get("created_at", "")))
                if created_at is not None and created_at < cutoff:
                    removed_entries += 1
                    reclaimed_bytes += manifest_path.stat().st_size
                    if not dry_run:
                        manifest_path.unlink()
                    artifact_dir = self._tool_artifact_dir(module_id, scanner)
                    if artifact_dir.exists():
                        removed_artifacts += self._count_files(artifact_dir)
                        reclaimed_bytes += self._dir_size(artifact_dir)
                        if not dry_run:
                            shutil.rmtree(artifact_dir)
                    continue

                history = payload.get("decision_history", [])
                if isinstance(history, list):
                    trimmed: list[dict[str, Any]] = []
                    for item in history:
                        timestamp = self._parse_timestamp(str(item.get("timestamp", "")))
                        if timestamp is None or timestamp >= cutoff:
                            trimmed.append(item)
                    trimmed = trimmed[-max_history:]
                    history_entries_pruned += max(0, len(history) - len(trimmed))
                    payload["decision_history"] = trimmed
                    if not dry_run:
                        self._atomic_write_json(manifest_path, payload)
                for artifact in payload.get("artifact_paths", []):
                    if isinstance(artifact, str):
                        referenced_artifacts.add(self.project_root / artifact)

            artifacts_root = module_dir / "artifacts"
            if artifacts_root.exists():
                for artifact_file in artifacts_root.rglob("*"):
                    if not artifact_file.is_file():
                        continue
                    if tool is not None and artifact_file.parent.name != tool:
                        continue
                    if artifact_file not in referenced_artifacts:
                        removed_artifacts += 1
                        reclaimed_bytes += artifact_file.stat().st_size
                        if not dry_run:
                            artifact_file.unlink()
                for tool_dir in sorted(artifacts_root.iterdir()):
                    if tool_dir.is_dir() and not any(tool_dir.rglob("*")):
                        if not dry_run:
                            tool_dir.rmdir()
                if not dry_run and artifacts_root.exists() and not any(artifacts_root.rglob("*")):
                    artifacts_root.rmdir()
            if not dry_run and module_dir.exists() and not any(module_dir.iterdir()):
                module_dir.rmdir()

        return {
            "project": self.project_root.name,
            "days": days,
            "max_history": max_history,
            "module": module_name,
            "tool": tool,
            "dry_run": dry_run,
            "cache_entries_removed": removed_entries,
            "history_entries_pruned": history_entries_pruned,
            "artifacts_removed": removed_artifacts,
            "abandoned_module_caches_removed": modules_pruned,
            "space_reclaimed_bytes": reclaimed_bytes,
        }

    def known_tools(self) -> set[str]:
        tools: set[str] = set()
        if not self.cache_root.exists():
            return tools
        for path in self.cache_root.glob("**/*.manifest.json"):
            name = path.name.removesuffix(".manifest.json")
            tools.add(name)
        return tools

    def _module_input_files(self, module: JavaModule) -> Iterable[Path]:
        root = self.project_root.resolve()
        module_root = module.module_path.resolve()
        for name in self._DESCRIPTOR_FILES:
            project_level = root / name
            if project_level.exists():
                yield project_level
            module_level = module_root / name
            if module_level.exists() and module_level != project_level:
                yield module_level
        for pattern in ("src/**/*.java", "src/**/*.xml", "src/**/*.properties", "src/**/*.yml", "src/**/*.yaml"):
            for path in module_root.glob(pattern):
                if path.is_file():
                    yield path

    @staticmethod
    def _file_hash(path: Path) -> str:
        digest = hashlib.sha256()
        digest.update(path.read_bytes())
        return digest.hexdigest()

    def _manifest_path(self, module_id: str, tool: str) -> Path:
        return self.cache_root / module_id / f"{tool}.manifest.json"

    def _tool_artifact_dir(self, module_id: str, tool: str) -> Path:
        return self.cache_root / module_id / "artifacts" / tool

    def _store_cached_artifacts(self, module_id: str, tool: str, artifact_paths: list[Path]) -> list[Path]:
        target_root = self._tool_artifact_dir(module_id, tool)
        target_root.mkdir(parents=True, exist_ok=True)
        cached_paths: list[Path] = []
        for artifact in artifact_paths:
            digest = hashlib.sha1(artifact.resolve().as_posix().encode("utf-8")).hexdigest()[:8]
            target = target_root / f"{artifact.name}.{digest}"
            shutil.copy2(artifact, target)
            cached_paths.append(target)
        return cached_paths

    @staticmethod
    def _parse_timestamp(value: str) -> datetime | None:
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)
        except ValueError:
            return None

    @staticmethod
    def _dir_size(path: Path) -> int:
        total = 0
        for file in path.rglob("*"):
            if file.is_file():
                total += file.stat().st_size
        return total

    @staticmethod
    def _count_files(path: Path) -> int:
        return sum(1 for file in path.rglob("*") if file.is_file())

    @staticmethod
    def _classify_input(path: str) -> str:
        lowered = path.lower()
        if lowered.endswith(_DESCRIPTOR_SUFFIXES):
            return "descriptor"
        if lowered.endswith(_WRAPPER_SUFFIXES):
            return "wrapper"
        if lowered.endswith(_LOCKFILE_SUFFIXES):
            return "lockfile"
        return "source"

    def _miss_reasons(
        self,
        *,
        manifest: JavaCacheManifest,
        cache_key: str,
        input_hashes: dict[str, str],
    ) -> list[str]:
        reasons: list[str] = []
        if manifest.cache_schema_version != CACHE_SCHEMA_VERSION:
            reasons.append("cache_schema_changed")
        if manifest.tool_version != TOOL_VERSION:
            reasons.append("tool_version_changed")
        if manifest.cache_key != cache_key:
            previous = manifest.input_hashes
            changed_classes: set[str] = set()
            for path, digest in input_hashes.items():
                if previous.get(path) != digest:
                    changed_classes.add(self._classify_input(path))
            for path in previous:
                if path not in input_hashes:
                    changed_classes.add(self._classify_input(path))
            if "source" in changed_classes:
                reasons.append("source_hash_changed")
            if "descriptor" in changed_classes:
                reasons.append("descriptor_hash_changed")
            if "wrapper" in changed_classes:
                reasons.append("wrapper_hash_changed")
            if "lockfile" in changed_classes:
                reasons.append("lockfile_hash_changed")
            if not changed_classes:
                reasons.append("source_hash_changed")
        return sorted(set(reasons))

    @staticmethod
    def _atomic_write_json(path: Path, payload: Any) -> None:
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        tmp.replace(path)
