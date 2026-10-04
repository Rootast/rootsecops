from __future__ import annotations

import os
import subprocess
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

from scanner_engine.logging import log_tool_execution
from scanner_engine.core.tool_locks import tool_lock


class ScannerExecutionError(Exception):
    pass


@dataclass
class ScannerContext:
    tool_name: str
    executable_path: str
    local_db_path: str | None = None
    is_offline_mode: bool = True
    extra_args: list[str] | None = None
    env: dict[str, str] | None = None
    job_id: str = ""
    target_file: dict[str, Any] | None = None
    audit: dict[str, Any] | None = None


class BaseScanner(ABC):
    def __init__(self, context: ScannerContext):
        self.ctx = context
        self.extra_args = context.extra_args or []
        self.env = context.env or {}

    @abstractmethod
    def scan(self, target: str, **kwargs) -> dict[str, Any]:
        raise NotImplementedError

    def update_database(self) -> dict[str, Any]:
        return {"tool": self.ctx.tool_name, "action": "noop"}

    def run_cmd(
        self,
        cmd: list[str],
        timeout: int = 3600,
        allowed_returncodes: tuple[int, ...] = (0,),
    ) -> subprocess.CompletedProcess:
        env = os.environ.copy()
        env.update(self.env)
        started = time.monotonic()
        try:
            with tool_lock(self.ctx.tool_name, exclusive=False, blocking=True):
                completed = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    check=False,
                    env=env,
                )
        except subprocess.TimeoutExpired as exc:
            duration_ms = int((time.monotonic() - started) * 1000)
            log_tool_execution(
                job_id=self.ctx.job_id,
                target_file=self.ctx.target_file or {},
                scanner_name=self.ctx.tool_name,
                command_executed=cmd,
                timeout_seconds=timeout,
                status="timeout",
                exit_code=None,
                duration_ms=duration_ms,
                stdout=(exc.stdout or "") if isinstance(exc.stdout, str) else "",
                stderr=(exc.stderr or "") if isinstance(exc.stderr, str) else "",
                audit=self.ctx.audit,
            )
            raise ScannerExecutionError(f"[{self.ctx.tool_name}] command timed out after {timeout}s") from exc
        except OSError as exc:
            duration_ms = int((time.monotonic() - started) * 1000)
            log_tool_execution(
                job_id=self.ctx.job_id,
                target_file=self.ctx.target_file or {},
                scanner_name=self.ctx.tool_name,
                command_executed=cmd,
                timeout_seconds=timeout,
                status="missing_binary",
                exit_code=None,
                duration_ms=duration_ms,
                stderr=str(exc),
                audit=self.ctx.audit,
            )
            raise ScannerExecutionError(f"[{self.ctx.tool_name}] {exc}") from exc
        duration_ms = int((time.monotonic() - started) * 1000)
        status = "success" if completed.returncode in allowed_returncodes else "failed"
        log_tool_execution(
            job_id=self.ctx.job_id,
            target_file=self.ctx.target_file or {},
            scanner_name=self.ctx.tool_name,
            command_executed=cmd,
            timeout_seconds=timeout,
            status=status,
            exit_code=completed.returncode,
            duration_ms=duration_ms,
            stdout=completed.stdout,
            stderr=completed.stderr,
            audit=self.ctx.audit,
        )
        if completed.returncode not in allowed_returncodes:
            output = (completed.stderr or completed.stdout or "").strip()
            if not output:
                output = "No stdout/stderr was returned by the tool."
            command = " ".join(cmd)
            raise ScannerExecutionError(
                f"[{self.ctx.tool_name}] exit={completed.returncode}; command={command}; output={output[:2000]}"
            )
        return completed
