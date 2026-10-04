import json
import os
import shutil
import tempfile
from pathlib import Path

from scanner_engine.models import YaraRule

from .base import BaseScanner, ScannerExecutionError


def parse_json(stdout: str, tool_name: str):
    try:
        return json.loads(stdout or "{}")
    except json.JSONDecodeError as exc:
        raise ScannerExecutionError(f"{tool_name} returned invalid JSON") from exc


def parse_json_lines(stdout: str):
    findings = []
    for line in stdout.splitlines():
        if not line.strip():
            continue
        try:
            findings.append(json.loads(line))
        except json.JSONDecodeError:
            findings.append({"raw": line})
    return findings


class TrivyScanner(BaseScanner):
    def update_database(self):
        cmd = [self.ctx.executable_path, "image", "--download-db-only"]
        if self.ctx.local_db_path:
            cmd += ["--cache-dir", self.ctx.local_db_path]
        return {"tool": "trivy", "stdout": self.run_cmd(cmd, timeout=1800).stdout}

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
            cmd += ["--cache-dir", self.ctx.local_db_path]
        cmd += self.extra_args + [target]
        return {"tool": "trivy", "result": parse_json(self.run_cmd(cmd).stdout, "Trivy")}


class GrypeScanner(BaseScanner):
    def scan(self, target: str, **kwargs):
        cmd = [self.ctx.executable_path, target, "-o", "json"]
        if self.ctx.local_db_path:
            self.env["GRYPE_DB_CACHE_DIR"] = self.ctx.local_db_path
        if self.ctx.is_offline_mode:
            self.env.setdefault("GRYPE_DB_AUTO_UPDATE", "false")
        cmd += self.extra_args
        return {"tool": "grype", "result": parse_json(self.run_cmd(cmd).stdout, "Grype")}


class GrantScanner(BaseScanner):
    def scan(self, target: str, **kwargs):
        cmd = [self.ctx.executable_path, "list", target, "-o", "json"] + self.extra_args
        completed = self.run_cmd(cmd, timeout=1800, allowed_returncodes=(0,))
        return {
            "tool": "grant",
            "result": parse_json(completed.stdout or "{}", "Grant"),
            "stderr": completed.stderr,
            "returncode": completed.returncode,
        }


class ExifToolScanner(BaseScanner):
    def scan(self, target: str, **kwargs):
        cmd = [self.ctx.executable_path, "-json", target] + self.extra_args
        completed = self.run_cmd(cmd, timeout=300, allowed_returncodes=(0,))
        return {
            "tool": "exiftool",
            "result": parse_json(completed.stdout or "[]", "ExifTool"),
            "stderr": completed.stderr,
            "returncode": completed.returncode,
        }


class PdfInfoScanner(BaseScanner):
    def scan(self, target: str, **kwargs):
        cmd = [self.ctx.executable_path, "-meta", "-js", "-struct", target] + self.extra_args
        completed = self.run_cmd(cmd, timeout=300, allowed_returncodes=(0,))
        metadata = {}
        for line in completed.stdout.splitlines():
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            metadata[key.strip()] = value.strip()
        return {
            "tool": "pdfinfo",
            "result": {
                "metadata": metadata,
                "stdout": completed.stdout,
                "stderr": completed.stderr,
                "returncode": completed.returncode,
            },
        }


class OSVScanner(BaseScanner):
    def scan(self, target: str, cyclonedx_sbom_path: str | None = None, **kwargs):
        if not cyclonedx_sbom_path or not Path(cyclonedx_sbom_path).exists():
            raise ScannerExecutionError("CycloneDX SBOM path is required for OSV-Scanner.")
        cmd = [self.ctx.executable_path, "scan", "source", "-L", cyclonedx_sbom_path, "--format", "json"] + self.extra_args
        completed = self.run_cmd(cmd, timeout=1800, allowed_returncodes=(0, 1))
        result = parse_json(completed.stdout, "OSV-Scanner")
        return {
            "tool": "osv-scanner",
            "result": result,
            "sbom": cyclonedx_sbom_path,
            "stderr": completed.stderr,
            "returncode": completed.returncode,
        }


class ClairScanner(BaseScanner):
    def scan(self, target: str, **kwargs):
        cmd = [self.ctx.executable_path, "report", "--image", target, "--output", "json"] + self.extra_args
        return {"tool": "clair", "result": parse_json(self.run_cmd(cmd).stdout, "Clair")}


class AnchoreScanner(BaseScanner):
    def scan(self, target: str, **kwargs):
        cmd = [self.ctx.executable_path, "image", "vuln", target, "--output", "json"] + self.extra_args
        return {"tool": "anchore", "result": parse_json(self.run_cmd(cmd).stdout, "Anchore")}


class GitleaksScanner(BaseScanner):
    def scan(self, target: str, **kwargs):
        target_path = Path(target)
        report_path = None
        if target_path.is_file():
            report_path = Path(tempfile.mkdtemp(prefix="gitleaks-file-")) / "report.json"
            cmd = [
                self.ctx.executable_path,
                "detect",
                "--no-git",
                "--source",
                target,
                "--report-format",
                "json",
                "--report-path",
                str(report_path),
                "--no-banner",
                "--redact",
            ] + self.extra_args
        else:
            cmd = [
                self.ctx.executable_path,
                "detect",
                "--source",
                target,
                "--report-format",
                "json",
                "--no-banner",
                "--redact",
            ] + self.extra_args
        completed = self.run_cmd(cmd, timeout=1800, allowed_returncodes=(0, 1))
        stdout = completed.stdout
        if report_path and report_path.exists():
            stdout = report_path.read_text(encoding="utf-8")
        return {
            "tool": "gitleaks",
            "result": parse_json(stdout or "[]", "Gitleaks"),
            "stderr": completed.stderr,
            "returncode": completed.returncode,
        }


class TrufflehogScanner(BaseScanner):
    def scan(self, target: str, **kwargs):
        cmd = [
            self.ctx.executable_path,
            "filesystem",
            target,
            "--json",
            "--no-update",
            "--no-verification",
            "--results=verified,unknown,unverified",
        ] + self.extra_args
        completed = self.run_cmd(cmd, timeout=3600, allowed_returncodes=(0, 1, 183))
        findings = [item for item in parse_json_lines(completed.stdout) if _is_trufflehog_finding(item)]
        return {
            "tool": "trufflehog",
            "result": findings,
            "stderr": completed.stderr,
            "returncode": completed.returncode,
        }


def _is_trufflehog_finding(item) -> bool:
    if not isinstance(item, dict):
        return False
    return any(key in item for key in ("Raw", "DetectorName", "DetectorType", "SourceMetadata", "Verified"))


class CheckovScanner(BaseScanner):
    def scan(self, target: str, **kwargs):
        target_path = Path(target)
        target_flag = "-f" if target_path.is_file() else "-d"
        cmd = [self.ctx.executable_path, target_flag, target, "-o", "json", "--quiet"] + self.extra_args
        completed = self.run_cmd(cmd, timeout=1800, allowed_returncodes=(0, 1))
        return {"tool": "checkov", "result": parse_json(completed.stdout or "{}", "Checkov")}


class KICSScanner(BaseScanner):
    def scan(self, target: str, **kwargs):
        with tempfile.TemporaryDirectory(prefix="kics-output-") as output_dir:
            query_path = self._query_path()
            cmd = [
                self.ctx.executable_path,
                "scan",
                "-p",
                target,
                "-o",
                output_dir,
                "--report-formats",
                "json",
                "--output-name",
                "results",
                "--no-progress",
                "--minimal-ui",
                "--ignore-on-exit",
                "results",
            ]
            if not query_path:
                raise ScannerExecutionError(
                    "KICS queries directory was not found. Set ScannerConfig.local_db_path "
                    "or KICS_QUERIES_PATH to the KICS assets/queries directory."
                )
            cmd += ["-q", query_path]
            cmd += self.extra_args
            completed = self.run_cmd(cmd, timeout=1800, allowed_returncodes=(0,))
            json_files = sorted(Path(output_dir).glob("*.json"))
            if json_files:
                return {"tool": "kics", "result": parse_json(json_files[0].read_text(), "KICS")}
            return {"tool": "kics", "result": parse_json(completed.stdout or "{}", "KICS")}

    def _query_path(self) -> str | None:
        candidates = []
        if self.ctx.local_db_path:
            candidates.append(Path(self.ctx.local_db_path))
        if self.env.get("KICS_QUERIES_PATH"):
            candidates.append(Path(self.env["KICS_QUERIES_PATH"]))
        if os.getenv("KICS_QUERIES_PATH"):
            candidates.append(Path(os.environ["KICS_QUERIES_PATH"]))

        executable = shutil.which(self.ctx.executable_path) or self.ctx.executable_path
        executable_path = Path(executable).resolve()
        candidates.extend(
            [
                executable_path.parent.parent / "assets" / "queries",
                executable_path.parent / "assets" / "queries",
                Path.cwd() / "assets" / "queries",
            ]
        )

        for candidate in candidates:
            if candidate.is_dir():
                return str(candidate)
        return None


class HadolintScanner(BaseScanner):
    def scan(self, target: str, **kwargs):
        cmd = [self.ctx.executable_path, "-f", "json", target] + self.extra_args
        completed = self.run_cmd(cmd, timeout=900, allowed_returncodes=(0, 1))
        return {
            "tool": "hadolint",
            "result": parse_json(completed.stdout or "[]", "Hadolint"),
            "stderr": completed.stderr,
            "returncode": completed.returncode,
        }


class ClamAVScanner(BaseScanner):
    def scan(self, target: str, **kwargs):
        cmd = [self.ctx.executable_path, "-r", "--infected", target] + self.extra_args
        completed = self.run_cmd(cmd, timeout=3600, allowed_returncodes=(0, 1, 2))
        matches = [line for line in completed.stdout.splitlines() if line.strip() and line.endswith("FOUND")]
        summary = [
            line
            for line in completed.stdout.splitlines()
            if line.startswith(
                (
                    "Known viruses:",
                    "Engine version:",
                    "Scanned ",
                    "Infected files:",
                    "Total errors:",
                    "Data ",
                    "Time:",
                    "Start Date:",
                    "End Date:",
                )
            )
        ]
        message = "No threats detected" if not matches else None
        return {
            "tool": "clamav",
            "result": {
                "matches": matches,
                "count": len(matches),
                "message": message,
                "stdout": completed.stdout,
                "stderr": completed.stderr,
                "summary": summary,
                "returncode": completed.returncode,
            },
        }


class YaraScanner(BaseScanner):
    def scan(self, target: str, **kwargs):
        rules = list(YaraRule.objects.filter(is_active=True).values_list("file_path", flat=True))
        if self.ctx.local_db_path:
            rule_path = Path(self.ctx.local_db_path)
            if rule_path.is_file():
                rules.append(str(rule_path))
            elif rule_path.is_dir():
                for suffix in ("*.yar", "*.yara", "*.rules"):
                    rules.extend(str(path) for path in rule_path.rglob(suffix))
        if not rules:
            return {
                "tool": "yara",
                "result": {
                    "matches": [],
                    "message": "No active YARA rules. Upload rules or set ScannerConfig.local_db_path.",
                },
            }
        missing = [rule for rule in rules if not Path(rule).exists()]
        if missing:
            raise ScannerExecutionError(f"Missing YARA rules: {missing}")
        cmd = [self.ctx.executable_path, "-w", "-r", "-s"] + rules + [target] + self.extra_args
        completed = self.run_cmd(cmd, timeout=3600, allowed_returncodes=(0, 1))
        lines = [line for line in completed.stdout.splitlines() if line.strip()]
        stderr_lines = [
            line
            for line in completed.stderr.splitlines()
            if line.strip() and not _is_yara_warning_noise(line)
        ]
        return {
            "tool": "yara",
            "result": {
                "matches": lines,
                "count": len(lines),
                "stderr": stderr_lines,
                "rules": rules,
            },
        }


def _is_yara_warning_noise(line: str) -> bool:
    lowered = line.lower()
    warning_markers = (
        "warning:",
        "may slow down scanning",
        "expression is always false",
        "expression always false",
    )
    return any(marker in lowered for marker in warning_markers)


def _output_lines(value: str) -> list[str]:
    return [line for line in value.splitlines() if line.strip()][:50]
