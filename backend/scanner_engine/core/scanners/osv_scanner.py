# scanner_engine/core/scanners/osv_scanner.py
import json
from pathlib import Path
from .base import BaseScanner, ScannerExecutionError


class OSVScanner(BaseScanner):
    """
    OSV-Scanner requires an SBOM file (CycloneDX or Syft JSON).
    We'll expect caller to pass sbom_path.
    """
    def update_database(self):
        # OSV-Scanner uses remote API; no local DB to sync.
        return {"tool": "osv-scanner", "action": "noop"}

    def scan(self, target: str, sbom_path: str | None = None, **kwargs):
        if not sbom_path or not Path(sbom_path).exists():
            raise ScannerExecutionError("SBOM path is required for OSV-Scanner.")

        cmd = [
            self.ctx.executable_path,
            "--sbom", sbom_path,
            "--format", "json",
        ]
        cmd += self.extra_args
        cp = self.run_cmd(cmd, timeout=1800)
        try:
            data = json.loads(cp.stdout or "{}")
        except json.JSONDecodeError as exc:
            raise ScannerExecutionError("OSV-Scanner returned invalid JSON") from exc

        return {"tool": "osv-scanner", "result": data, "sbom": sbom_path}
