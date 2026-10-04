from __future__ import annotations

import json
import logging
import subprocess
from datetime import UTC, datetime
from typing import Any

RESERVED_LOG_RECORD_KEYS = {
    "args",
    "asctime",
    "created",
    "exc_info",
    "exc_text",
    "filename",
    "funcName",
    "levelname",
    "levelno",
    "lineno",
    "module",
    "msecs",
    "message",
    "msg",
    "name",
    "pathname",
    "process",
    "processName",
    "relativeCreated",
    "stack_info",
    "thread",
    "threadName",
}


class StructuredJsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        event_time = datetime.fromtimestamp(record.created, UTC)
        payload = {
            "timestamp": event_time.isoformat(),
            "asctime": event_time.strftime("%Y-%m-%d %H:%M:%S,%f")[:-3],
            "log_level": record.levelname,
            "levelname": record.levelname,
            "module": self._module_name(record),
            "logger": record.name,
            "name": record.name,
            "message": record.getMessage(),
            "task_id": self._task_id(record),
            "scanner_name": self._scanner_name(record),
            "metadata": self._metadata(record),
        }
        if record.exc_info:
            payload["metadata"]["exception"] = self.formatException(record.exc_info)
        if record.stack_info:
            payload["metadata"]["stack_info"] = self.formatStack(record.stack_info)
        return json.dumps(payload, ensure_ascii=False, default=str)

    def _module_name(self, record: logging.LogRecord) -> str:
        explicit = getattr(record, "module_name", "")
        if explicit:
            return str(explicit)
        if record.name == "scanner_engine.scan":
            return "orchestrator"
        if record.name == "scanner_engine.tool_execution":
            return "scanner_execution"
        if record.name == "scanner_engine.tool_updates":
            return "tool_updates"
        if record.name.startswith("celery"):
            return "celery_task"
        if record.name.startswith("django"):
            return "api"
        return record.module

    def _task_id(self, record: logging.LogRecord) -> str:
        for key in ("task_id", "scan_id", "job_id"):
            value = getattr(record, key, "")
            if value:
                return str(value)
        return ""

    def _scanner_name(self, record: logging.LogRecord) -> str:
        scanner_name = getattr(record, "scanner_name", "")
        if scanner_name:
            return str(scanner_name)
        scanner = getattr(record, "scanner", None)
        if isinstance(scanner, dict):
            return str(scanner.get("name") or "")
        return ""

    def _metadata(self, record: logging.LogRecord) -> dict[str, Any]:
        metadata: dict[str, Any] = {
            "source_file": record.pathname,
            "line_number": record.lineno,
            "function": record.funcName,
        }
        record_dict = record.__dict__
        for key, value in record_dict.items():
            if key in RESERVED_LOG_RECORD_KEYS or key in {"module_name", "task_id", "scan_id", "job_id", "scanner_name"}:
                continue
            metadata[key] = value
        if "job_id" in record_dict and "job_id" not in metadata:
            metadata["job_id"] = record_dict["job_id"]
        if "scan_id" in record_dict and "scan_id" not in metadata:
            metadata["scan_id"] = record_dict["scan_id"]
        return metadata


def log_tool_execution(
    *,
    job_id: str,
    target_file: dict[str, Any],
    scanner_name: str,
    command_executed: list[str],
    timeout_seconds: int,
    status: str,
    exit_code: int | None,
    duration_ms: int,
    stdout: str = "",
    stderr: str = "",
    audit: dict[str, Any] | None = None,
) -> None:
    document = {
        "@timestamp": datetime.now(UTC).isoformat(),
        "job_id": job_id,
        "target_file": target_file,
        "scanner": {
            "name": scanner_name,
            "command_executed": command_executed,
            "version": tool_version(command_executed[0]) if command_executed else "",
            "timeout_seconds": timeout_seconds,
        },
        "execution": {
            "status": status,
            "exit_code": exit_code,
            "duration_ms": duration_ms,
            "stdout": _limit_output(stdout),
            "stderr": _limit_output(stderr),
            "severity_counts": extract_severity_counts(stdout),
        },
        "audit": audit or {"triggered_by_user": "system", "client_ip": ""},
    }

    logging.getLogger("scanner_engine.tool_execution").info("security tool execution", extra=document)


def tool_version(executable: str) -> str:
    if not executable:
        return ""
    executable_name = executable.rsplit("/", 1)[-1]
    command_args = {
        "trufflehog": ([executable, "--version"],),
        "exiftool": ([executable, "-ver"],),
        "pdfinfo": ([executable, "-v"], [executable, "--version"]),
    }.get(executable_name, ([executable, "version"], [executable, "--version"], [executable, "-v"]))
    for args in command_args:
        try:
            completed = subprocess.run(args, capture_output=True, text=True, timeout=5, check=False)
        except (OSError, subprocess.TimeoutExpired):
            continue
        if completed.returncode != 0:
            continue
        output = (completed.stdout or completed.stderr or "").strip()
        if output:
            return output.splitlines()[0][:300]
    return ""


def extract_severity_counts(output: str) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    if not output:
        return counts
    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        lowered = output.lower()
        for key in counts:
            counts[key] = lowered.count(key)
        return counts

    severity_counters = data.get("severity_counters") if isinstance(data, dict) else None
    if isinstance(severity_counters, dict):
        for key in counts:
            counts[key] = int(severity_counters.get(key.upper(), severity_counters.get(key, 0)) or 0)
        return counts

    def visit(node: Any) -> None:
        if isinstance(node, dict):
            severity = str(node.get("Severity") or node.get("severity") or "").lower()
            if severity in counts:
                counts[severity] += 1
            for value in node.values():
                visit(value)
        elif isinstance(node, list):
            for item in node:
                visit(item)

    visit(data)
    return counts


def _limit_output(value: str, limit: int = 20000) -> str:
    return (value or "")[:limit]
