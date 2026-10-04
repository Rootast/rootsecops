import json
from .base import BaseScanner, ScannerExecutionError


class TrivyScanner(BaseScanner):
    def update_database(self):
        cmd = [self.ctx.executable_path, "image", "--download-db-only"]
        if self.ctx.local_db_path:
            cmd += ["--db-dir", self.ctx.local_db_path]
        cp = self.run_cmd(cmd, timeout=1800)
        return {"tool": "trivy", "action": "db_update", "stdout": cp.stdout}

    def scan(self, target: str, **kwargs):
        cmd = [
            self.ctx.executable_path,
            "image",
            "--format",
            "json",
            "--quiet",
            "--scanners",
            "vuln",
            "--skip-db-update",
            "--skip-java-db-update",
            "--offline-scan",
        ]
        if self.ctx.local_db_path:
            cmd += ["--db-dir", self.ctx.local_db_path]
        cmd += self.extra_args + [target]
        cp = self.run_cmd(cmd)
        try:
            data = json.loads(cp.stdout or "{}")
        except json.JSONDecodeError as exc:
            raise ScannerExecutionError("Trivy returned invalid JSON") from exc
        return {"tool": "trivy", "result": data}
