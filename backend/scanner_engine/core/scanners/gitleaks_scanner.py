import json
from .base import BaseScanner


class GitleaksScanner(BaseScanner):
    def update_database(self):
        return {"tool": "gitleaks", "action": "noop"}

    def scan(self, target: str, **kwargs):
        report_path = "/tmp/gitleaks_report.json"

        cmd = [
            self.ctx.executable_path,
            "detect",
            "--source",
            target,
            "--report-format",
            "json",
            "--report-path",
            report_path,
            "--no-banner",
            "--exit-code",
            "0",
        ]

        cmd += self.extra_args

        cp = self.run_cmd(cmd, timeout=3600)

        # 🔥 IMPORTANT: read file, NOT stdout
        try:
            with open(report_path, "r") as f:
                raw = json.load(f)
        except Exception:
            raw = []

        findings = []

        for f in raw:
            findings.append({
                "File": f.get("File") or f.get("file", ""),
                "StartLine": f.get("StartLine") or f.get("startLine", 0),
                "RuleID": f.get("RuleID") or f.get("rule", "Secret"),
                "Secret": f.get("Secret") or f.get("secret", ""),
            })

        return {
            "gitleaks": {
                "result": findings
            }
        }