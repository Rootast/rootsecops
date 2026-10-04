from io import BytesIO
from pathlib import Path
from subprocess import CalledProcessError, CompletedProcess
import tarfile
import tempfile
from unittest.mock import patch

from django.test import SimpleTestCase

from .core.preprocessing import container_data_filter, export_image_fs
from .core.scanners.base import ScannerContext, ScannerExecutionError
from .core.scanners.command_scanners import GrypeScanner, OSVScanner, TrivyScanner


class ScannerDeploymentTests(SimpleTestCase):
    def test_trivy_custom_cache_uses_supported_flag(self):
        scanner = TrivyScanner(ScannerContext("trivy", "trivy", local_db_path="/cache/trivy"))
        with patch.object(scanner, "run_cmd", return_value=CompletedProcess([], 0, '{"Results":[]}', "")) as run:
            scanner.scan("demo:latest")
        self.assertIn("--cache-dir", run.call_args.args[0])
        self.assertNotIn("--db-dir", run.call_args.args[0])

    def test_grype_cache_is_passed_in_environment(self):
        scanner = GrypeScanner(ScannerContext("grype", "grype", local_db_path="/cache/grype"))
        with patch.object(scanner, "run_cmd", return_value=CompletedProcess([], 0, '{"matches":[]}', "")) as run:
            scanner.scan("demo:latest")
        self.assertEqual(scanner.env["GRYPE_DB_CACHE_DIR"], "/cache/grype")
        self.assertEqual(scanner.env["GRYPE_DB_AUTO_UPDATE"], "false")
        self.assertNotIn("--db-dir", run.call_args.args[0])

    def test_osv_findings_exit_code_is_accepted(self):
        scanner = OSVScanner(ScannerContext("osv-scanner", "osv-scanner"))
        with tempfile.NamedTemporaryFile(suffix=".cdx.json") as sbom:
            with patch.object(scanner, "run_cmd", return_value=CompletedProcess([], 1, '{"results":[]}', "")) as run:
                result = scanner.scan("demo", cyclonedx_sbom_path=sbom.name)
        self.assertEqual(run.call_args.kwargs["allowed_returncodes"], (0, 1))
        self.assertEqual(result["returncode"], 1)

    def test_osv_invalid_output_does_not_become_clean_results(self):
        scanner = OSVScanner(ScannerContext("osv-scanner", "osv-scanner"))
        with tempfile.NamedTemporaryFile(suffix=".cdx.json") as sbom:
            with patch.object(scanner, "run_cmd", return_value=CompletedProcess([], 1, "broken", "")):
                with self.assertRaises(ScannerExecutionError):
                    scanner.scan("demo", cyclonedx_sbom_path=sbom.name)

    def test_docker_error_reports_daemon_stderr(self):
        with tempfile.TemporaryDirectory() as directory:
            error = CalledProcessError(1, ["docker"], stderr="client API is too old")
            with patch("scanner_engine.core.preprocessing.subprocess.run", side_effect=error):
                with self.assertRaisesRegex(RuntimeError, "client API is too old"):
                    export_image_fs("demo", Path(directory))

    def test_image_archive_cannot_escape_destination(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            def docker(command, **kwargs):
                if command[1] == "create":
                    self.assertIn("--pull=missing", command)
                    return CompletedProcess(command, 0, "synthetic-container\n", "")
                if command[1] == "export":
                    with tarfile.open(fileobj=kwargs["stdout"], mode="w") as archive:
                        member = tarfile.TarInfo("../../escaped")
                        member.size = 1
                        archive.addfile(member, BytesIO(b"x"))
                return CompletedProcess(command, 0, "", "")

            with patch("scanner_engine.core.preprocessing.subprocess.run", side_effect=docker):
                with self.assertRaises(tarfile.FilterError):
                    export_image_fs("demo", root)
            self.assertFalse((root / "escaped").exists())

    def test_container_absolute_symlink_is_rebased_inside_export(self):
        with tempfile.TemporaryDirectory() as directory:
            member = tarfile.TarInfo("usr/bin/tool")
            member.type = tarfile.SYMTYPE
            member.linkname = "/bin/busybox"
            filtered = container_data_filter(member, directory)
            self.assertEqual(filtered.linkname, "../../bin/busybox")
            self.assertEqual(member.linkname, "/bin/busybox")

    def test_relative_symlink_escape_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            member = tarfile.TarInfo("link")
            member.type = tarfile.SYMTYPE
            member.linkname = "../../outside"
            with self.assertRaises(tarfile.LinkOutsideDestinationError):
                container_data_filter(member, directory)
