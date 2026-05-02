from pathlib import Path

from codegauge.services.project_discovery import ProjectDiscoveryService
from codegauge.domain.models import Language


def test_python_project_detected(tmp_path: Path) -> None:
    proj = tmp_path / "myproj"
    proj.mkdir()
    (proj / "pyproject.toml").write_text("")
    svc = ProjectDiscoveryService()
    project = svc.discover(proj)
    assert Language.python in project.language_hints


def test_java_project_detected_with_framework_metadata(tmp_path: Path) -> None:
    proj = tmp_path / "javaproj"
    proj.mkdir()
    (proj / "pom.xml").write_text("<project><dependencies><dependency>org.springframework.boot</dependency></dependencies></project>")
    src = proj / "src" / "main" / "java" / "App.java"
    src.parent.mkdir(parents=True, exist_ok=True)
    src.write_text("@RestController\nclass App {}")

    svc = ProjectDiscoveryService()
    project = svc.discover(proj)
    assert Language.java in project.language_hints
    java_meta = project.metadata.get("java")
    assert isinstance(java_meta, dict)
    assert java_meta["module_count"] >= 1
    assert "spring_boot" in java_meta["frameworks"]
    assert "spring" in java_meta["frameworks"]


def test_django_project_detected_with_framework_metadata(tmp_path: Path) -> None:
    proj = tmp_path / "django-proj"
    proj.mkdir()
    (proj / "manage.py").write_text("import django\n")
    settings = proj / "app" / "settings.py"
    settings.parent.mkdir(parents=True, exist_ok=True)
    settings.write_text("DEBUG = True\nALLOWED_HOSTS = []\n")
    views = proj / "app" / "views.py"
    views.write_text("from rest_framework.views import APIView\n")
    asgi = proj / "app" / "asgi.py"
    asgi.write_text("from channels.routing import ProtocolTypeRouter\n")

    project = ProjectDiscoveryService().discover(proj)
    assert Language.python in project.language_hints
    django_meta = project.metadata.get("django")
    assert isinstance(django_meta, dict)
    assert django_meta["detected"] is True
    assert django_meta["drf"] is True
    assert django_meta["channels"] is True
    assert "django_check_deploy" in django_meta["profile"]["scanners"]
    assert "framework_cards" in django_meta["profile"]["cards"]
    assert django_meta["profile"]["cache_behavior"] == "stateless"


def test_fastapi_style_settings_file_does_not_trigger_django_detection(tmp_path: Path) -> None:
    proj = tmp_path / "fastapi-proj"
    proj.mkdir()
    (proj / "pyproject.toml").write_text(
        "[project]\nname='fastapi-proj'\nversion='0.1.0'\ndependencies=['fastapi','uvicorn']\n"
    )
    settings = proj / "src" / "config" / "settings.py"
    settings.parent.mkdir(parents=True, exist_ok=True)
    settings.write_text("DEBUG = True\nAPP_ENV = 'dev'\n")
    app_py = proj / "src" / "main.py"
    app_py.write_text("from fastapi import FastAPI\napp = FastAPI()\n")

    project = ProjectDiscoveryService().discover(proj)
    assert Language.python in project.language_hints
    assert project.metadata.get("django") is None
    runtime = project.metadata.get("python_runtime")
    assert isinstance(runtime, dict)
    assert runtime["language"] == "python"
    assert runtime["framework"] == "fastapi"
    assert runtime["framework_confidence"] >= 0.7


def test_venv_files_are_ignored_for_framework_and_infra_detection(tmp_path: Path) -> None:
    proj = tmp_path / "proj-with-venv"
    proj.mkdir()
    (proj / "pyproject.toml").write_text("[project]\nname='x'\nversion='0.1.0'\n")
    app_py = proj / "app.py"
    app_py.write_text("from fastapi import FastAPI\napp = FastAPI()\n")

    venv_settings = proj / ".venv" / "lib" / "python3.14" / "site-packages" / "fakepkg" / "settings.py"
    venv_settings.parent.mkdir(parents=True, exist_ok=True)
    venv_settings.write_text("from django.conf import settings\n")
    venv_shell = proj / ".venv" / "lib" / "python3.14" / "site-packages" / "fakepkg" / "vendor_install.sh"
    venv_shell.write_text("#!/bin/sh\necho vendor\n")

    project = ProjectDiscoveryService().discover(proj)
    runtime = project.metadata.get("python_runtime")
    assert isinstance(runtime, dict)
    assert runtime["framework"] == "fastapi"
    assert project.metadata.get("django") is None
    assert project.metadata.get("infrastructure") is None


def test_generic_python_framework_detected_with_low_confidence(tmp_path: Path) -> None:
    proj = tmp_path / "generic-python"
    proj.mkdir()
    (proj / "pyproject.toml").write_text("[project]\nname='generic'\nversion='0.1.0'\n")
    (proj / "script.py").write_text("print('hello')\n")

    project = ProjectDiscoveryService().discover(proj)
    runtime = project.metadata.get("python_runtime")
    assert isinstance(runtime, dict)
    assert runtime["language"] == "python"
    assert runtime["framework"] == "generic"
    assert runtime["framework_confidence"] == 0.4


def test_typescript_project_detected_with_framework_metadata(tmp_path: Path) -> None:
    proj = tmp_path / "ts-proj"
    proj.mkdir()
    (proj / "package.json").write_text(
        '{"name":"x","dependencies":{"react":"18.0.0"},"devDependencies":{"typescript":"5.0.0"}}'
    )
    (proj / "tsconfig.json").write_text('{"compilerOptions":{"strict":true}}')
    src = proj / "src" / "app.tsx"
    src.parent.mkdir(parents=True, exist_ok=True)
    src.write_text("export const App = () => null;\n")

    project = ProjectDiscoveryService().discover(proj)
    assert Language.typescript in project.language_hints
    assert Language.javascript in project.language_hints
    ts_meta = project.metadata.get("typescript")
    assert isinstance(ts_meta, dict)
    assert "react" in ts_meta["frameworks"]
    assert "typescript_diagnostics" in ts_meta["profile"]["scanners"]
    assert ts_meta["profile"]["cache_behavior"] == "partial"


def test_infrastructure_project_detected_with_metadata(tmp_path: Path) -> None:
    proj = tmp_path / "infra-proj"
    proj.mkdir()
    (proj / "Dockerfile").write_text("FROM alpine\n")
    (proj / "docker-compose.yml").write_text("services:\n  web:\n    image: nginx\n")
    (proj / "web.container").write_text("[Container]\nImage=nginx\n")
    (proj / "nginx.conf").write_text("events {}\nhttp {}\n")
    (proj / "main.tf").write_text('resource "x" "y" {}\n')
    scripts = proj / "scripts" / "deploy.sh"
    scripts.parent.mkdir(parents=True, exist_ok=True)
    scripts.write_text("#!/bin/sh\necho ok\n")

    project = ProjectDiscoveryService().discover(proj)
    assert Language.general in project.language_hints
    infra_meta = project.metadata.get("infrastructure")
    assert isinstance(infra_meta, dict)
    assert infra_meta["detected"] is True
    assert "containers" in infra_meta["frameworks"]
    assert "reverse_proxy" in infra_meta["frameworks"]
    assert "terraform" in infra_meta["frameworks"]
    assert "shell" in infra_meta["frameworks"]
    assert "dockerfile_scan" in infra_meta["profile"]["scanners"]


def test_php_project_detected_with_framework_metadata(tmp_path: Path) -> None:
    proj = tmp_path / "php-proj"
    proj.mkdir()
    (proj / "composer.json").write_text('{"require": {"laravel/framework": "^10"}}')
    (proj / "index.php").write_text("<?php echo 'ok';")

    project = ProjectDiscoveryService().discover(proj)
    assert Language.php in project.language_hints
    php_meta = project.metadata.get("php")
    assert isinstance(php_meta, dict)
    assert php_meta["framework"] == "laravel"
    assert "phpstan" in php_meta["profile"]["scanners"]


def test_go_project_detected_with_framework_metadata(tmp_path: Path) -> None:
    proj = tmp_path / "go-proj"
    proj.mkdir()
    (proj / "go.mod").write_text(
        "module example.com/demo\n\nrequire github.com/gin-gonic/gin v1.10.0\n",
        encoding="utf-8",
    )
    (proj / "main.go").write_text("package main\nfunc main() {}\n", encoding="utf-8")

    project = ProjectDiscoveryService().discover(proj)
    assert Language.go in project.language_hints
    go_meta = project.metadata.get("go")
    assert isinstance(go_meta, dict)
    assert go_meta["framework"] == "gin"
    assert "go_vet" in go_meta["profile"]["scanners"]
