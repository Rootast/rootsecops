from __future__ import annotations

import json
import logging
import shutil
import subprocess
import time
import urllib.error
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from django.utils import timezone
from django.conf import settings

from scanner_engine.models import ScannerConfig, ToolState

from .tool_locks import tool_lock

logger = logging.getLogger("scanner_engine.tool_updates")


@dataclass(frozen=True)
class ToolUpdateSpec:
    github_repo: str = ""
    version_commands: tuple[tuple[str, ...], ...] = (("version",), ("--version",))
    db_version_commands: tuple[tuple[str, ...], ...] = ()
    db_update_command: tuple[str, ...] = ()


TOOL_UPDATE_SPECS: dict[str, ToolUpdateSpec] = {
    "grant": ToolUpdateSpec(github_repo="anchore/grant", version_commands=(("version",), ("--version",))),
    "grype": ToolUpdateSpec(
        github_repo="anchore/grype",
        version_commands=(("version",), ("--version",)),
        db_version_commands=(("db", "status", "-o", "json"), ("db", "status"),),
        db_update_command=("db", "update"),
    ),
    "trivy": ToolUpdateSpec(
        github_repo="aquasecurity/trivy",
        version_commands=(("version", "--format", "json"), ("version",), ("--version",)),
        db_version_commands=(("version",),),
        db_update_command=("image", "--download-db-only"),
    ),
    "osv-scanner": ToolUpdateSpec(github_repo="google/osv-scanner", version_commands=(("--version",), ("version",))),
    "clamav": ToolUpdateSpec(version_commands=(("--version",),), db_version_commands=(("--version",),), db_update_command=()),
    "yara": ToolUpdateSpec(version_commands=(("--version",),), db_version_commands=(), db_update_command=()),
    "exiftool": ToolUpdateSpec(version_commands=(("-ver",),)),
    "pdfinfo": ToolUpdateSpec(version_commands=(("-v",), ("--version",))),
    "gitleaks": ToolUpdateSpec(github_repo="gitleaks/gitleaks", version_commands=(("version",), ("--version",))),
    "trufflehog": ToolUpdateSpec(github_repo="trufflesecurity/trufflehog", version_commands=(("--version",),)),
}


def ensure_tool_state(config: ScannerConfig) -> ToolState:
    state, _ = ToolState.objects.get_or_create(tool=config)
    return state


def append_tool_log(state: ToolState, message: str, level: str = "info") -> None:
    entry = {
        "timestamp": timezone.now().isoformat(),
        "level": level,
        "message": _safe_message(message),
    }
    logs = [*(state.logs or []), entry][-80:]
    state.logs = logs


def check_tool_version(config: ScannerConfig) -> ToolState:
    state = ensure_tool_state(config)
    state.action_state = ToolState.ActionState.CHECKING
    state.last_error = ""
    append_tool_log(state, "Starting version check.")
    state.save()

    started = time.monotonic()
    try:
        if not _binary_available(config.executable_path):
            state.health_state = ToolState.Health.UNKNOWN
            state.action_state = ToolState.ActionState.IDLE
            state.current_version = ""
            state.latest_version = ""
            state.last_error = f"Executable not found: {config.executable_path}"
            state.last_checked_at = timezone.now()
            append_tool_log(state, f"{state.last_error}. Install it or disable this scanner.", "warning")
            state.save()
            return state
        current = installed_version(config)
        latest = latest_release_version(config.tool_name)
        state.current_version = current
        state.latest_version = latest
        state.health_state = ToolState.Health.HEALTHY
        state.action_state = ToolState.ActionState.SUCCESS
        state.last_checked_at = timezone.now()
        append_tool_log(state, f"Version check complete in {int((time.monotonic() - started) * 1000)}ms.")
    except Exception as exc:
        state.health_state = ToolState.Health.UNHEALTHY
        state.action_state = ToolState.ActionState.FAILED
        state.last_error = _safe_message(str(exc))
        state.last_checked_at = timezone.now()
        append_tool_log(state, state.last_error, "error")
    state.save()
    return state


def check_tool_database(config: ScannerConfig) -> ToolState:
    state = ensure_tool_state(config)
    state.action_state = ToolState.ActionState.CHECKING
    state.last_error = ""
    append_tool_log(state, "Starting database/signature check.")
    state.save()

    try:
        database_version = tool_database_version(config)
        state.database_version = database_version
        state.database_status = "available" if database_version else "not_applicable"
        state.health_state = ToolState.Health.HEALTHY
        state.action_state = ToolState.ActionState.SUCCESS
        state.last_db_checked_at = timezone.now()
        append_tool_log(state, "Database/signature check complete.")
    except Exception as exc:
        state.database_status = "failed"
        state.health_state = ToolState.Health.UNHEALTHY
        state.action_state = ToolState.ActionState.FAILED
        state.last_error = _safe_message(str(exc))
        state.last_db_checked_at = timezone.now()
        append_tool_log(state, state.last_error, "error")
    state.save()
    return state


def update_tool_binary(config: ScannerConfig) -> ToolState:
    state = ensure_tool_state(config)
    state.action_state = ToolState.ActionState.UPDATING
    state.last_error = ""
    append_tool_log(state, "Starting binary/tool update.")
    state.save()

    try:
        command = config.binary_update_command or []
        if not command:
            state.action_state = ToolState.ActionState.IDLE
            state.last_error = ""
            append_tool_log(
                state,
                f"Binary update is not configured. Set {config.tool_name.upper().replace('-', '_')}_UPDATE_COMMAND or configure binary_update_command in admin.",
                "warning",
            )
            state.save()
            return state
        _run_update_command(config.tool_name, command)
        state.current_version = installed_version(config)
        state.action_state = ToolState.ActionState.SUCCESS
        state.health_state = ToolState.Health.HEALTHY
        state.last_updated_at = timezone.now()
        append_tool_log(state, "Binary/tool update completed.")
    except Exception as exc:
        state.action_state = ToolState.ActionState.FAILED
        state.health_state = ToolState.Health.UNHEALTHY
        state.last_error = _safe_message(str(exc))
        append_tool_log(state, state.last_error, "error")
    state.save()
    return state


def update_tool_database(config: ScannerConfig) -> ToolState:
    state = ensure_tool_state(config)
    state.action_state = ToolState.ActionState.UPDATING
    state.last_error = ""
    append_tool_log(state, "Starting database/signature update.")
    state.save()

    try:
        if config.tool_name == "yara":
            updated = update_yara_rules()
            append_tool_log(state, f"YARA rule update fetched {updated} rule files.")
        else:
            command = config.database_update_command or _default_db_update_command(config)
            if not command:
                raise ToolActionError("This tool does not expose a database/signature update command.")
            _run_update_command(config.tool_name, command)
        state.database_version = tool_database_version(config)
        state.database_status = "updated"
        state.action_state = ToolState.ActionState.SUCCESS
        state.health_state = ToolState.Health.HEALTHY
        state.last_db_updated_at = timezone.now()
        append_tool_log(state, "Database/signature update completed.")
    except Exception as exc:
        state.action_state = ToolState.ActionState.FAILED
        state.health_state = ToolState.Health.UNHEALTHY
        state.last_error = _safe_message(str(exc))
        append_tool_log(state, state.last_error, "error")
    state.save()
    return state


def crawl_enabled_tools() -> list[ToolState]:
    states = []
    for config in ScannerConfig.objects.select_related("state").all():
        ensure_tool_state(config)
        if config.version_crawler_enabled:
            states.append(check_tool_version(config))
        if config.db_check_enabled:
            states.append(check_tool_database(config))
    return states


def installed_version(config: ScannerConfig) -> str:
    spec = TOOL_UPDATE_SPECS.get(config.tool_name, ToolUpdateSpec())
    for args in spec.version_commands:
        output = _run_command([config.executable_path, *args], timeout=20, allowed_returncodes=(0,))
        parsed = _extract_version(output)
        if parsed:
            return parsed
    return ""


def latest_release_version(tool_name: str) -> str:
    spec = TOOL_UPDATE_SPECS.get(tool_name)
    if not spec or not spec.github_repo:
        return ""
    url = f"https://api.github.com/repos/{spec.github_repo}/releases/latest"
    request = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json", "User-Agent": "rootsecops-tool-crawler"})
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except urllib.error.URLError as exc:
        raise ToolActionError(f"Could not check latest release for {tool_name}: {exc}") from exc
    return str(payload.get("tag_name") or payload.get("name") or "")


def tool_database_version(config: ScannerConfig) -> str:
    if config.tool_name == "yara":
        return yara_database_status()
    spec = TOOL_UPDATE_SPECS.get(config.tool_name, ToolUpdateSpec())
    if not spec.db_version_commands:
        return ""
    errors = []
    for args in spec.db_version_commands:
        try:
            output = _run_command([config.executable_path, *args], timeout=60, allowed_returncodes=(0,))
            return _summarize_database_output(output)
        except Exception as exc:
            errors.append(str(exc))
    raise ToolActionError("; ".join(errors) or "Database status command failed.")


def update_yara_rules() -> int:
    target_root = settings.YARA_RULES_DIR
    target_root.mkdir(parents=True, exist_ok=True)
    total = 0
    for repo in settings.YARA_RULE_REPOS:
        total += _download_yara_repo(repo, target_root)
    return total


def yara_database_status() -> str:
    rule_dir = settings.YARA_RULES_DIR
    if not rule_dir.exists():
        return "rules=0"
    count = sum(1 for suffix in ("*.yar", "*.yara", "*.rules") for _path in rule_dir.rglob(suffix))
    return f"rules={count}"


def _download_yara_repo(repo_url: str, target_root: Path) -> int:
    repo_name = repo_url.rstrip("/").split("/")[-1].replace(".git", "")
    destination = target_root / repo_name
    if shutil.which("git"):
        if destination.exists():
            _run_command(["git", "-C", str(destination), "pull", "--ff-only"], timeout=300, allowed_returncodes=(0,))
        else:
            _run_command(["git", "clone", "--depth", "1", repo_url, str(destination)], timeout=600, allowed_returncodes=(0,))
    else:
        zip_url = repo_url.rstrip("/").replace("github.com", "github.com") + "/archive/refs/heads/master.zip"
        archive_path = target_root / f"{repo_name}.zip"
        with urllib.request.urlopen(zip_url, timeout=60) as response:
            archive_path.write_bytes(response.read())
        with zipfile.ZipFile(archive_path) as archive:
            archive.extractall(target_root)
    return sum(1 for suffix in ("*.yar", "*.yara", "*.rules") for _path in destination.rglob(suffix)) if destination.exists() else 0


def _default_db_update_command(config: ScannerConfig) -> list[str]:
    spec = TOOL_UPDATE_SPECS.get(config.tool_name, ToolUpdateSpec())
    if not spec.db_update_command:
        return []
    return [config.executable_path, *spec.db_update_command]


def _run_update_command(tool_name: str, command: list[str]) -> str:
    with tool_lock(tool_name, exclusive=True, blocking=False):
        return _run_command(command, timeout=1800, allowed_returncodes=(0,))


def _run_command(command: list[str], timeout: int, allowed_returncodes: tuple[int, ...]) -> str:
    if not command:
        raise ToolActionError("Empty command.")
    completed = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
    output = "\n".join(item for item in [completed.stdout, completed.stderr] if item).strip()
    if completed.returncode not in allowed_returncodes:
        raise ToolActionError(f"Command failed with exit {completed.returncode}: {_safe_message(output)}")
    return output


def _binary_available(executable: str) -> bool:
    if "/" in executable:
        return bool(shutil.which(executable) or Path(executable).exists())
    return shutil.which(executable) is not None


def _extract_version(output: str) -> str:
    text = output.strip()
    if not text:
        return ""
    try:
        payload = json.loads(text)
        if isinstance(payload, dict):
            for key in ("Version", "version", "GitVersion"):
                if payload.get(key):
                    return str(payload[key])
    except json.JSONDecodeError:
        pass
    for line in text.splitlines():
        lowered = line.lower()
        if "version" in lowered:
            if ":" in line:
                return line.split(":", 1)[1].strip().split()[0]
            parts = line.split()
            for part in parts:
                if any(ch.isdigit() for ch in part):
                    return part.strip()
    first = text.splitlines()[0].strip()
    return first[:128]


def _summarize_database_output(output: str) -> str:
    text = output.strip()
    if not text:
        return ""
    try:
        payload = json.loads(text)
        values = []
        for key in ("built", "schemaVersion", "checksum", "updated", "nextUpdate"):
            if payload.get(key):
                values.append(f"{key}={payload[key]}")
        return ", ".join(values) or json.dumps(payload)[:240]
    except json.JSONDecodeError:
        return text.splitlines()[0][:240]


def _safe_message(value: str) -> str:
    if not value:
        return ""
    sanitized = value.replace("\r", " ").strip()
    return sanitized[:1200]


class ToolActionError(Exception):
    pass
