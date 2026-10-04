from dataclasses import dataclass
from pathlib import Path
import shutil
from typing import Type

from django.conf import settings

from scanner_engine.models import ScanTask, ScannerConfig, ToolState

from .scanners.base import BaseScanner
from .scanners.command_scanners import (
    AnchoreScanner,
    CheckovScanner,
    ClairScanner,
    ClamAVScanner,
    ExifToolScanner,
    GitleaksScanner,
    GrantScanner,
    GrypeScanner,
    HadolintScanner,
    KICSScanner,
    OSVScanner,
    PdfInfoScanner,
    TrivyScanner,
    TrufflehogScanner,
    YaraScanner,
)


@dataclass(frozen=True)
class ScannerDefinition:
    tool_name: str
    display_name: str
    category: str
    scanner_class: Type[BaseScanner] | None
    supported_input_types: list[str]
    executable_path: str


SCANNER_REGISTRY: dict[str, ScannerDefinition] = {
    "syft": ScannerDefinition("syft", "Syft", ScannerConfig.Category.SBOM, None, [ScanTask.InputType.IMAGE], "syft"),
    "trivy": ScannerDefinition("trivy", "Trivy", ScannerConfig.Category.VULNERABILITY, TrivyScanner, [ScanTask.InputType.IMAGE], "trivy"),
    "grype": ScannerDefinition("grype", "Grype", ScannerConfig.Category.VULNERABILITY, GrypeScanner, [ScanTask.InputType.IMAGE], "grype"),
    "grant": ScannerDefinition("grant", "Grant", ScannerConfig.Category.SBOM, GrantScanner, [ScanTask.InputType.IMAGE], "grant"),
    "osv-scanner": ScannerDefinition("osv-scanner", "OSV Scanner", ScannerConfig.Category.VULNERABILITY, OSVScanner, [ScanTask.InputType.IMAGE], "osv-scanner"),
    "clair": ScannerDefinition("clair", "Clair", ScannerConfig.Category.VULNERABILITY, ClairScanner, [ScanTask.InputType.IMAGE], "clairctl"),
    "anchore": ScannerDefinition("anchore", "Anchore", ScannerConfig.Category.VULNERABILITY, AnchoreScanner, [ScanTask.InputType.IMAGE], "anchorectl"),
    "gitleaks": ScannerDefinition("gitleaks", "Gitleaks", ScannerConfig.Category.SECRET, GitleaksScanner, [ScanTask.InputType.GIT, ScanTask.InputType.IMAGE, ScanTask.InputType.FILE, ScanTask.InputType.DOCKERFILE], "gitleaks"),
    "trufflehog": ScannerDefinition("trufflehog", "TruffleHog", ScannerConfig.Category.SECRET, TrufflehogScanner, [ScanTask.InputType.GIT, ScanTask.InputType.IMAGE, ScanTask.InputType.FILE, ScanTask.InputType.DOCKERFILE], "trufflehog"),
    "checkov": ScannerDefinition("checkov", "Checkov", ScannerConfig.Category.MISCONFIGURATION, CheckovScanner, [ScanTask.InputType.DOCKERFILE, ScanTask.InputType.GIT], "checkov"),
    "kics": ScannerDefinition("kics", "KICS", ScannerConfig.Category.MISCONFIGURATION, KICSScanner, [ScanTask.InputType.DOCKERFILE, ScanTask.InputType.GIT], "kics"),
    "hadolint": ScannerDefinition("hadolint", "Hadolint", ScannerConfig.Category.MISCONFIGURATION, HadolintScanner, [ScanTask.InputType.DOCKERFILE], "hadolint"),
    "exiftool": ScannerDefinition("exiftool", "ExifTool", ScannerConfig.Category.METADATA, ExifToolScanner, [ScanTask.InputType.FILE], settings.EXIFTOOL_BIN),
    "pdfinfo": ScannerDefinition("pdfinfo", "PDFInfo", ScannerConfig.Category.METADATA, PdfInfoScanner, [ScanTask.InputType.FILE], settings.PDFINFO_BIN),
    "clamav": ScannerDefinition("clamav", "ClamAV", ScannerConfig.Category.MALWARE, ClamAVScanner, [ScanTask.InputType.IMAGE, ScanTask.InputType.FILE], settings.CLAMSCAN_BIN),
    "yara": ScannerDefinition("yara", "YARA", ScannerConfig.Category.MALWARE, YaraScanner, [ScanTask.InputType.IMAGE, ScanTask.InputType.GIT, ScanTask.InputType.FILE], settings.YARA_BIN),
}


def seed_scanner_configs() -> None:
    for definition in SCANNER_REGISTRY.values():
        defaults = {
            "display_name": definition.display_name,
            "category": definition.category,
            "executable_path": _resolve_executable(definition.executable_path),
            "supported_input_types": definition.supported_input_types,
            "enabled": _default_enabled(definition.tool_name),
            "version_crawler_enabled": definition.tool_name in {"grant", "osv-scanner", "grype", "trivy"},
            "db_check_enabled": definition.tool_name in {"clamav", "grype", "trivy", "yara"},
        }
        if definition.tool_name == "trivy":
            defaults["is_offline_mode"] = True
        binary_update_command = _binary_update_command(definition.tool_name)
        if binary_update_command:
            defaults["binary_update_command"] = binary_update_command
        database_update_command = _database_update_command(definition.tool_name, definition.executable_path)
        if database_update_command:
            defaults["database_update_command"] = database_update_command
        if definition.tool_name == "kics":
            query_path = _discover_kics_queries(definition.executable_path)
            if query_path:
                defaults["local_db_path"] = query_path
        if definition.tool_name == "yara":
            defaults["local_db_path"] = str(settings.YARA_RULES_DIR)
        config, _ = ScannerConfig.objects.update_or_create(
            tool_name=definition.tool_name,
            defaults=defaults,
        )
        ToolState.objects.get_or_create(tool=config)


def _discover_kics_queries(executable_path: str) -> str:
    executable = shutil.which(executable_path) or executable_path
    path = Path(executable).resolve()
    for candidate in (
        path.parent.parent / "assets" / "queries",
        path.parent / "assets" / "queries",
        Path.cwd() / "assets" / "queries",
    ):
        if candidate.is_dir():
            return str(candidate)
    return ""


def _resolve_executable(executable_path: str) -> str:
    discovered = shutil.which(executable_path)
    return discovered or executable_path


def _default_enabled(tool_name: str) -> bool:
    env_flags = {
        "clamav": settings.CLAMAV_ENABLED,
        "yara": settings.YARA_ENABLED,
        "exiftool": settings.EXIFTOOL_ENABLED,
        "pdfinfo": settings.PDFINFO_ENABLED,
    }
    return env_flags.get(tool_name, True)


def _binary_update_command(tool_name: str) -> list[str]:
    import os
    import shlex

    env_name = f"{tool_name.upper().replace('-', '_')}_UPDATE_COMMAND"
    raw = os.getenv(env_name, "")
    return shlex.split(raw) if raw else []


def _database_update_command(tool_name: str, executable_path: str) -> list[str]:
    if tool_name == "clamav":
        return [settings.FRESHCLAM_BIN]
    if tool_name == "grype":
        return [executable_path, "db", "update"]
    if tool_name == "trivy":
        return [executable_path, "image", "--download-db-only"]
    return []
