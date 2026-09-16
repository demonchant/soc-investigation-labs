import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]


def executable_scripts():
    scripts = []
    for path in ROOT.rglob("*.py"):
        if any(part in {".git", ".venv", "tests"} for part in path.parts):
            continue
        text = path.read_text(encoding="utf-8")
        if "__main__" not in text or path.name == "generate_sample_data.py":
            continue
        if path.as_posix().endswith("mini_siem_platform/api/server.py"):
            continue
        scripts.append(path.relative_to(ROOT))
    return sorted(scripts)


@pytest.fixture(scope="session")
def isolated_repository(tmp_path_factory):
    destination = tmp_path_factory.mktemp("repository") / "source"
    shutil.copytree(
        ROOT,
        destination,
        ignore=shutil.ignore_patterns(".git", ".venv", "__pycache__", ".pytest_cache"),
    )
    return destination


def test_all_json_fixtures_are_valid():
    for path in ROOT.rglob("*.json"):
        json.loads(path.read_text(encoding="utf-8"))


@pytest.mark.parametrize("relative_path", executable_scripts(), ids=lambda path: str(path))
def test_entry_point_runs_with_bundled_data(isolated_repository, relative_path):
    script = isolated_repository / relative_path
    environment = os.environ.copy()
    environment["PYTHONUTF8"] = "1"
    result = subprocess.run(
        [sys.executable, script.name],
        cwd=script.parent,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=20,
        env=environment,
    )
    assert result.returncode == 0, result.stderr


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_detection_conditions_do_not_execute_python():
    module = load_module(
        "detection_pipeline",
        ROOT / "detection_as_code" / "scanner" / "detection_pipeline.py",
    )
    with pytest.raises(ValueError):
        module.evaluate_boolean_condition("__import__('os').getcwd()", {"selection": True})
    assert module.evaluate_boolean_condition(
        "selection and not filter_known",
        {"selection": True, "filter_known": False},
    )


def test_mini_siem_api_has_safe_defaults(monkeypatch, tmp_path):
    project = ROOT / "mini_siem_platform"
    monkeypatch.syspath_prepend(str(project))
    monkeypatch.chdir(tmp_path)
    server = load_module("mini_siem_server", project / "api" / "server.py")
    client = server.app.test_client()
    response = client.get("/logs?limit=invalid")
    assert response.status_code == 400
    assert response.headers["Cache-Control"] == "no-store"
