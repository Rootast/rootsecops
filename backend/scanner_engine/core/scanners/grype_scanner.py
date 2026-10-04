import json
from .base import BaseScanner, ScannerExecutionError


class GrypeScanner(BaseScanner):
    def update_database(self):
        cmd = [self.ctx.executable_path, "db", "update"]
        if self.ctx.local_db_path:
            cmd += ["--db-dir", self.ctx.local_db_path]
        cp = self.run_cmd(cmd, timeout=1800)
        return {"tool": "grype", "action": "db_update", "stdout": cp.stdout}

    def scan(self, target: str, **kwargs):
        cmd = [self.ctx.executable_path, target, "-o", "json"]
        if self.ctx.local_db_path:
            cmd += ["--db-dir", self.ctx.local_db_path]
        if self.ctx.is_offline_mode:
            cmd += ["--auto-update", "false"]
        cmd += self.extra_args
        cp = self.run_cmd(cmd)
        try:
            data = json.loads(cp.stdout or "{}")
        except json.JSONDecodeError as exc:
            raise ScannerExecutionError("Grype returned invalid JSON") from exc
        return {"tool": "grype", "result": data}
