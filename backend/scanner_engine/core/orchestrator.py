from __future__ import annotations

import json
import logging
import mimetypes
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from django.conf import settings

from scanner_engine.models import ScanTask, ScannerConfig

from .normalizers import normalize_results
from .preprocessing import clone_repo_with_token, export_image_fs, syft_cyclonedx_sbom, syft_sbom
from .registry import SCANNER_REGISTRY
from .scanners.base import ScannerContext
from scanner_engine.logging import log_tool_execution

logger = logging.getLogger("scanner_engine.scan")


def run_scan(scan_task: ScanTask) -> dict[str, Any]:
    logs: list[str] = []

    def log(message: str, progress: int | None = None) -> None:
        logs.append(message)
        level = logging.ERROR if "[ERROR]" in message else logging.WARNING if "[WARN]" in message else logging.INFO
        logger.log(
            level,
            message,
            extra={
                "task_id": str(scan_task.id),
                "scan_id": str(scan_task.id),
                "target": scan_task.target,
                "progress": progress,
            },
        )
        if progress is not None:
            scan_task.progress = progress
            scan_task.logs = logs
            scan_task.save(update_fields=["progress", "logs", "updated_at"])

    log(f"[INFO] Starting scan for {scan_task.target}", 10)

    if getattr(settings, "SCANNER_MOCK_MODE", False):
        raw_results = {
            "_errors": [
                {
                    "tool": "mock",
                    "stage": "configuration",
                    "message": "SCANNER_MOCK_MODE is enabled. Disable it for real scanner execution.",
                    "install_hint": "Set SCANNER_MOCK_MODE=false and restart Django.",
                }
            ],
            "_tool_status": [],
        }
        log("[WARN] Mock scanner mode is enabled; no real scanners were executed.", 80)
    else:
        raw_results = _run_real_scan(scan_task, log)

    normalized, summary = normalize_results(scan_task, raw_results)
    log("[INFO] Aggregated and normalized scanner output.", 95)
    log("[INFO] Scan completed successfully.", 100)
    return {
        "raw_results": raw_results,
        "normalized_results": normalized,
        "summary": summary,
        "logs": logs,
    }


def _run_real_scan(scan_task: ScanTask, log) -> dict[str, Any]:
    workdir = Path(tempfile.mkdtemp(prefix=f"scan_{scan_task.id}_", dir=str(settings.SCANNER_WORK_DIR.parent)))
    workdir.mkdir(parents=True, exist_ok=True)
    target_for_filesystem_tools = scan_task.target
    sbom_path: str | None = None
    cyclonedx_sbom_path: str | None = None
    raw_results: dict[str, Any] = {"_errors": [], "_tool_status": []}
    file_profile: dict[str, Any] = {}
    audit = {
        "triggered_by_user": scan_task.owner.username if scan_task.owner else "system",
        "client_ip": (scan_task.options or {}).get("client_ip", ""),
    }

    def persist_raw_results() -> None:
        scan_task.raw_results = raw_results
        scan_task.save(update_fields=["raw_results", "logs", "updated_at"])

    def record_status(tool: str, status: str, stage: str, message: str = "", progress: int | None = None) -> None:
        raw_results["_tool_status"].append(
            {
                "tool": tool,
                "status": status,
                "stage": stage,
                "message": message,
                "progress": scan_task.progress if progress is None else progress,
                "timestamp": timezone_now_iso(),
            }
        )
        persist_raw_results()

    def record_error(tool: str, stage: str, message: str, install_hint: str = "", status: str = "error") -> None:
        friendly = _friendly_tool_error(tool, message)
        raw_results["_errors"].append(
            {
                "tool": tool,
                "stage": stage,
                "message": friendly,
                "raw_message": message[:2000],
                "install_hint": install_hint,
            }
        )
        record_status(tool, status, stage, friendly)
        log(f"[ERROR] {tool}: {friendly}" + (f" | {install_hint}" if install_hint else ""))

    def record_skip(tool: str, stage: str, message: str, status: str = "skipped") -> None:
        record_status(tool, status, stage, message)
        log(f"[INFO] {tool}: {message}")

    def executable_available(executable_path: str) -> bool:
        executable = Path(executable_path)
        if executable.is_absolute() or "/" in executable_path:
            return executable.exists() and executable.is_file()
        return shutil.which(executable_path) is not None

    if scan_task.input_type == ScanTask.InputType.IMAGE:
        if (scan_task.options or {}).get("generate_sbom", True):
            if executable_available("syft"):
                sbom_path = str(workdir / "sbom.json")
                cyclonedx_sbom_path = str(workdir / "sbom.cdx.json")
                log("[INFO] Generating Syft JSON SBOM.", 20)
                try:
                    syft_sbom(scan_task.target, sbom_path)
                    log("[INFO] Generating CycloneDX SBOM for OSV-Scanner.", 23)
                    syft_cyclonedx_sbom(scan_task.target, cyclonedx_sbom_path)
                    with open(sbom_path, "r", encoding="utf-8") as handle:
                        raw_results["syft"] = {"tool": "syft", "result": json.load(handle)}
                    raw_results["syft"]["cyclonedx_path"] = cyclonedx_sbom_path
                    record_status("syft", "success", "sbom", "SBOM generated", 23)
                except (subprocess.CalledProcessError, OSError, json.JSONDecodeError) as exc:
                    record_error("syft", "sbom", str(exc), "Install Syft: brew install syft")
            else:
                record_error("syft", "sbom", "Syft executable was not found.", "Install Syft: brew install syft", "missing_binary")

        if (scan_task.options or {}).get("deep_scan", True):
            if executable_available("docker"):
                log("[INFO] Exporting image filesystem for filesystem scanners.", 35)
                try:
                    target_for_filesystem_tools = export_image_fs(scan_task.target, workdir)
                    record_status("docker", "success", "filesystem_export", "Image filesystem exported", 35)
                except (subprocess.CalledProcessError, OSError) as exc:
                    record_error("docker", "filesystem_export", str(exc), "Install/start Docker Desktop, then retry.")
            else:
                record_error("docker", "filesystem_export", "Docker executable was not found.", "Install/start Docker Desktop, then retry.", "missing_binary")
    elif scan_task.input_type == ScanTask.InputType.GIT:
        target_for_filesystem_tools = str(workdir / "repo")
        token = (scan_task.options or {}).get("github_token", "")
        log("[INFO] Cloning git repository.", 25)
        clone_repo_with_token(scan_task.target, token, target_for_filesystem_tools)
    elif scan_task.input_type == ScanTask.InputType.DOCKERFILE:
        dockerfile_path = Path(scan_task.target)
        if not dockerfile_path.exists():
            dockerfile_path = workdir / "Dockerfile"
            dockerfile_path.write_text(scan_task.target, encoding="utf-8")
            log("[INFO] Wrote inline Dockerfile to scan workspace.", 25)
        target_for_filesystem_tools = str(dockerfile_path)
    elif scan_task.input_type == ScanTask.InputType.FILE:
        target_for_filesystem_tools = scan_task.target
        file_profile = _file_profile(scan_task.target)
        raw_results["_file_profile"] = file_profile

    enabled_tools = list(ScannerConfig.objects.filter(enabled=True).select_related("state"))
    runnable_configs = [
        config
        for config in enabled_tools
        if (definition := SCANNER_REGISTRY.get(config.tool_name))
        and definition.scanner_class
        and getattr(getattr(config, "state", None), "active", True)
        and scan_task.input_type in (config.supported_input_types or definition.supported_input_types)
    ]
    total_tools = max(len(runnable_configs), 1)
    for index, config in enumerate(runnable_configs, start=1):
        definition = SCANNER_REGISTRY.get(config.tool_name)
        progress = min(90, 40 + int((index - 1) / total_tools * 45))

        executable_path = config.executable_path or definition.executable_path
        if not _runtime_enabled(config.tool_name):
            record_skip(
                config.tool_name,
                "configuration",
                f"{config.tool_name} is disabled by environment configuration.",
                "skipped",
            )
            continue
        if not executable_available(executable_path):
            log_tool_execution(
                job_id=str(scan_task.id),
                target_file=_target_file_metadata(scan_task.target),
                scanner_name=config.tool_name,
                command_executed=[executable_path],
                timeout_seconds=0,
                status="missing_binary",
                exit_code=None,
                duration_ms=0,
                stderr=f"Executable not found: {executable_path}",
                audit=audit,
            )
            record_skip(
                config.tool_name,
                "scanner_start",
                f"Executable not found: {executable_path}",
                "missing_binary",
            )
            continue
        if scan_task.input_type == ScanTask.InputType.FILE and not _scanner_matches_file(config.tool_name, file_profile):
            record_skip(
                config.tool_name,
                "routing",
                f"Skipped for detected file type {file_profile.get('mime_type') or 'unknown'}.",
            )
            continue
        target = target_for_filesystem_tools
        if config.category == ScannerConfig.Category.VULNERABILITY and scan_task.input_type == ScanTask.InputType.IMAGE:
            target = scan_task.target
        context = ScannerContext(
            tool_name=config.tool_name,
            executable_path=executable_path,
            local_db_path=config.local_db_path or None,
            is_offline_mode=config.is_offline_mode,
            extra_args=config.extra_args or [],
            env=config.env or {},
            job_id=str(scan_task.id),
            target_file=_target_file_metadata(target),
            audit=audit,
        )
        scanner = definition.scanner_class(context)
        if config.category != ScannerConfig.Category.VULNERABILITY and target_for_filesystem_tools == scan_task.target and scan_task.input_type == ScanTask.InputType.IMAGE:
            record_error(
                config.tool_name,
                "scanner_start",
                "Filesystem export is unavailable, so this filesystem scanner was skipped.",
                "Install/start Docker Desktop for filesystem-based scans.",
                "skipped",
            )
            continue
        log(f"[INFO] Running {config.tool_name} against {target}.", progress)
        record_status(config.tool_name, "running", "scan", f"Running {config.tool_name}", progress)
        try:
            raw_results[config.tool_name] = scanner.scan(
                target,
                sbom_path=sbom_path,
                cyclonedx_sbom_path=cyclonedx_sbom_path,
            )
            success_message = _scanner_success_message(config.tool_name, raw_results[config.tool_name])
            record_status(config.tool_name, "success", "scan", success_message, min(92, progress + 3))
            log(f"[INFO] {success_message}.", min(92, progress + 3))
        except Exception as exc:
            record_error(config.tool_name, "scan", str(exc), _install_hint(config.tool_name))

    return raw_results


def _scanner_success_message(tool_name: str, result: dict[str, Any]) -> str:
    findings = result.get("result") if isinstance(result, dict) else None
    if tool_name in {"gitleaks", "trufflehog"} and isinstance(findings, list):
        return f"{tool_name} completed with {len(findings)} finding(s)"
    return f"{tool_name} completed"


def _target_file_metadata(target: str) -> dict[str, Any]:
    path = Path(str(target))
    name = path.name if path.name else str(target)
    size = path.stat().st_size if path.exists() and path.is_file() else 0
    profile = _file_profile(str(path)) if path.exists() and path.is_file() else {}
    mime_type = profile.get("mime_type") or mimetypes.guess_type(str(path))[0] or "application/octet-stream"
    return {
        "name": name,
        "stored_path": str(target),
        "size_bytes": size,
        "mime_type": mime_type,
    }


def _file_profile(target: str) -> dict[str, Any]:
    path = Path(str(target))
    guessed_mime = mimetypes.guess_type(str(path))[0] or "application/octet-stream"
    header = b""
    suspicious_pdf_tags: list[str] = []
    magic_mime = ""
    try:
        if path.exists() and path.is_file():
            with path.open("rb") as handle:
                header = handle.read(8192)
    except OSError:
        header = b""
    if header.startswith(b"%PDF-"):
        magic_mime = "application/pdf"
        for tag in (b"/JavaScript", b"/JS", b"/Launch", b"/OpenAction", b"/AA"):
            if tag in header:
                suspicious_pdf_tags.append(tag.decode("ascii", errors="ignore"))
    elif header.startswith(b"PK\x03\x04"):
        magic_mime = "application/zip"
    elif header.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        magic_mime = "application/x-ole-storage"
    elif header.startswith(b"\x89PNG\r\n\x1a\n"):
        magic_mime = "image/png"
    elif header.startswith(b"\xff\xd8\xff"):
        magic_mime = "image/jpeg"
    else:
        magic_mime = guessed_mime
    extension_mismatch = _extension_mismatch(path.suffix.lower(), magic_mime)
    return {
        "name": path.name,
        "stored_path": str(path),
        "mime_type": magic_mime or guessed_mime,
        "guessed_mime_type": guessed_mime,
        "extension": path.suffix.lower(),
        "extension_mismatch": extension_mismatch,
        "suspicious_pdf_tags": suspicious_pdf_tags,
    }


def _extension_mismatch(extension: str, mime_type: str) -> bool:
    if not extension or not mime_type:
        return False
    expected = {
        ".pdf": "application/pdf",
        ".png": "image/png",
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".zip": "application/zip",
        ".docx": "application/zip",
        ".xlsx": "application/zip",
        ".pptx": "application/zip",
    }
    expected_mime = expected.get(extension)
    return bool(expected_mime and expected_mime != mime_type)


def _scanner_matches_file(tool_name: str, file_profile: dict[str, Any]) -> bool:
    mime_type = file_profile.get("mime_type", "")
    if tool_name == "pdfinfo":
        return mime_type == "application/pdf"
    return True


def _install_hint(tool_name: str) -> str:
    hints = {
        "trivy": "Install Trivy: brew install aquasecurity/trivy/trivy",
        "grant": "Install Grant: brew install anchore/grant/grant",
        "grype": "Install Grype: brew install anchore/grype/grype",
        "osv-scanner": "Install OSV-Scanner: brew install osv-scanner",
        "clair": "Install/configure Clair or disable the clair tool.",
        "anchore": "Install/configure Anchore CLI or disable the anchore tool.",
        "gitleaks": "Install Gitleaks: brew install gitleaks",
        "trufflehog": "Install TruffleHog: brew install trufflesecurity/trufflehog/trufflehog",
        "checkov": "Install Checkov: pipx install checkov",
        "kics": "Install KICS: brew install checkmarx/tap/kics",
        "hadolint": "Install Hadolint: brew install hadolint",
        "clamav": "Install ClamAV: brew install clamav",
        "yara": "Install YARA: brew install yara",
        "exiftool": "Install ExifTool: brew install exiftool",
        "pdfinfo": "Install Poppler pdfinfo: brew install poppler",
    }
    return hints.get(tool_name, f"Install {tool_name} or disable it in scanner config.")


def _friendly_tool_error(tool_name: str, message: str) -> str:
    lowered = message.lower()
    if "no such host" in lowered or "lookup " in lowered or "dial tcp" in lowered:
        return f"{tool_name} could not reach its update/vulnerability database endpoint. Check DNS/network access or run/update the tool database offline."
    if "java db update failed" in lowered:
        return "Trivy tried to update the Java vulnerability DB and failed. Run Trivy DB updates manually or keep --skip-java-db-update enabled for offline scans."
    if "executable not found" in lowered or "no such file or directory" in lowered:
        return f"{tool_name} binary is not available on this host. Install it or disable this scanner."
    if "neither cpe nor purl found" in lowered:
        return "OSV-Scanner received SBOM entries without package identifiers. Vulnerability matching may be incomplete; regenerate a package-focused CycloneDX SBOM."
    return message[:1200]


def _runtime_enabled(tool_name: str) -> bool:
    flags = {
        "clamav": getattr(settings, "CLAMAV_ENABLED", True),
        "yara": getattr(settings, "YARA_ENABLED", True),
        "exiftool": getattr(settings, "EXIFTOOL_ENABLED", True),
        "pdfinfo": getattr(settings, "PDFINFO_ENABLED", True),
    }
    return flags.get(tool_name, True)


def _enabled_env_name(tool_name: str) -> str:
    return {
        "clamav": "CLAMAV_ENABLED",
        "yara": "YARA_ENABLED",
        "exiftool": "EXIFTOOL_ENABLED",
        "pdfinfo": "PDFINFO_ENABLED",
    }.get(tool_name, f"{tool_name.upper()}_ENABLED")


def timezone_now_iso() -> str:
    from django.utils import timezone

    return timezone.now().isoformat()
