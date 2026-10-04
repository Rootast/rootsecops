# scanner_engine/core/scanners/clair_scanner.py
import json
from .base import BaseScanner, ScannerExecutionError


class ClairScanner(BaseScanner):
    """
    Assumes Clair CLI wrapper available. Adjust to your deployment (e.g. clairectl).
    """
    def update_database(self):
        # Clair updates typically via API/task; placeholder:
        return {"tool": "clair", "action": "managed_externally"}

    def scan(self, target: str, **kwargs):
        cmd = [
            self.ctx.executable_path,
            "report",
            "--image", target,
            "--output", "json",
        ]
        if self.ctx.is_offline_mode and self.ctx.local_db_path:
            cmd += ["--local-index", self.ctx.local_db_path]
        cmd += self.extra_args
        cp = self.run_cmd(cmd, timeout=3600)
        try:
            data = json.loads(cp.stdout or "{}")
        except json.JSONDecodeError as exc:
            raise ScannerExecutionError("Clair returned invalid JSON") from exc
        return {"tool": "clair", "result": data}
