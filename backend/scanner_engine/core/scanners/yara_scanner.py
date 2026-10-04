from pathlib import Path
from scanner_engine.models import YaraRule
from .base import BaseScanner, ScannerExecutionError


class YaraScanner(BaseScanner):
    def update_database(self):
        # YARA uses rules, no vulnerability DB.
        active = YaraRule.objects.filter(is_active=True).count()
        return {"tool": "yara", "action": "rules_refresh", "active_rules": active}

    def scan(self, target: str, **kwargs):
        rules = list(YaraRule.objects.filter(is_active=True).values_list("file_path", flat=True))
        if not rules:
            return {"tool": "yara", "result": {"matches": [], "message": "No active YARA rules"}}

        # Validate rules exist
        missing = [r for r in rules if not Path(r).exists()]
        if missing:
            raise ScannerExecutionError(f"Missing YARA rules: {missing}")

        cmd = [self.ctx.executable_path, "-r", "-s"] + rules + [target] + self.extra_args
        cp = self.run_cmd(cmd)
        lines = [ln for ln in cp.stdout.splitlines() if ln.strip()]
        return {"tool": "yara", "result": {"matches": lines, "count": len(lines)}}
