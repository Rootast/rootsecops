from io import BytesIO
import json
import logging
from subprocess import CompletedProcess
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import override_settings
from rest_framework.test import APITestCase

from .core.normalizers import normalize_results
from .core.orchestrator import _scanner_matches_file
from .core.registry import seed_scanner_configs
from .core.scanners.base import ScannerContext
from .core.scanners.command_scanners import HadolintScanner, TrivyScanner, TrufflehogScanner
from .core.tool_updates import check_tool_version, installed_version, update_tool_binary
from .logging import StructuredJsonFormatter
from .models import ScanTask, ScannerConfig, ToolState


class ScanApiSecurityTests(APITestCase):
    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user(username="analyst", password="password123")
        self.other = User.objects.create_user(username="other", password="password123")
        self.admin = User.objects.create_user(username="admin", password="password123", is_staff=True)

    def test_dashboard_requires_authentication(self):
        response = self.client.get("/api/v1/dashboard/")
        self.assertEqual(response.status_code, 401)

    def test_dashboard_only_returns_current_user_scans(self):
        ScanTask.objects.create(owner=self.user, input_type=ScanTask.InputType.FILE, target="/tmp/a")
        ScanTask.objects.create(owner=self.other, input_type=ScanTask.InputType.FILE, target="/tmp/b")
        self.client.force_authenticate(self.user)

        response = self.client.get("/api/v1/dashboard/")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["metrics"]["totalScans"], 1)

    @override_settings(SCANNER_RUN_INLINE=False)
    @patch("scanner_engine.views.process_scan_task.delay")
    def test_file_scan_upload_creates_owned_task(self, mocked_delay):
        self.client.force_authenticate(self.user)
        upload = BytesIO(b"hello")
        upload.name = "sample.bin"

        response = self.client.post(
            "/api/v1/scans/",
            {"asset_type": "file", "target": "sample.bin", "file": upload, "options": "{}"},
            format="multipart",
        )

        self.assertEqual(response.status_code, 202)
        task = ScanTask.objects.get(id=response.data["id"])
        self.assertEqual(task.owner, self.user)
        self.assertEqual(task.input_type, ScanTask.InputType.FILE)
        mocked_delay.assert_called_once()

    def test_tool_admin_api_requires_admin_role(self):
        self.client.force_authenticate(self.user)
        response = self.client.get("/api/v1/admin/tools/")
        self.assertEqual(response.status_code, 403)

        self.client.force_authenticate(self.admin)
        response = self.client.get("/api/v1/admin/tools/")
        self.assertEqual(response.status_code, 200)

    def test_user_creation_writes_audit_log(self):
        self.client.force_authenticate(self.admin)

        with self.assertLogs("scanner_engine.audit", level="INFO") as captured:
            response = self.client.post(
                "/api/v1/admin/users/",
                {
                    "username": "new-analyst",
                    "email": "new-analyst@example.com",
                    "password": "password123",
                    "roles": ["analyst"],
                    "is_active": True,
                },
                format="json",
            )

        self.assertEqual(response.status_code, 201)
        self.assertTrue(any("User account created: new-analyst" in line for line in captured.output))

    def test_file_targets_are_displayed_as_basename(self):
        task = ScanTask.objects.create(
            owner=self.user,
            input_type=ScanTask.InputType.DOCKERFILE,
            target="/tmp/uploads/secret/path/Dockerfile",
            logs=["[INFO] Running kics against /tmp/uploads/secret/path/Dockerfile."],
            normalized_results={"metadata": {"asset": "/tmp/uploads/secret/path/Dockerfile"}},
        )
        self.client.force_authenticate(self.user)

        dashboard = self.client.get("/api/v1/dashboard/")
        results = self.client.get(f"/api/v1/scans/{task.id}/results/")

        self.assertEqual(dashboard.data["recentScans"][0]["target"], "Dockerfile")
        self.assertEqual(results.data["metadata"]["asset"], "Dockerfile")
        self.assertIn("Dockerfile", results.data["task"]["logs"][0])
        self.assertNotIn("/tmp/uploads", results.data["task"]["logs"][0])

    def test_logout_endpoint_clears_session_without_refresh_token(self):
        self.client.force_authenticate(self.user)
        response = self.client.post("/api/v1/auth/logout/", {}, format="json")
        self.assertEqual(response.status_code, 200)

    def test_grant_is_seeded_as_first_class_tool(self):
        seed_scanner_configs()
        grant = ScannerConfig.objects.get(tool_name="grant")

        self.assertTrue(grant.enabled)
        self.assertTrue(grant.version_crawler_enabled)
        self.assertFalse(grant.db_check_enabled)
        self.assertEqual(grant.state.active, True)

    @override_settings(SCANNER_RUN_INLINE=False)
    @patch("scanner_engine.views.process_tool_action_task.delay")
    def test_admin_can_start_tool_action(self, mocked_delay):
        seed_scanner_configs()
        self.client.force_authenticate(self.admin)

        response = self.client.post("/api/v1/admin/tools/grant/actions/", {"action": "check_version"}, format="json")

        self.assertEqual(response.status_code, 202)
        mocked_delay.assert_called_once_with("grant", "check_version")

    def test_file_scan_malware_score_is_normalized(self):
        task = ScanTask.objects.create(owner=self.user, input_type=ScanTask.InputType.FILE, target="/tmp/sample.bin")
        normalized, _summary = normalize_results(
            task,
            {
                "clamav": {"result": {"matches": ["/tmp/sample.bin: Eicar-Test-Signature FOUND"], "returncode": 1, "summary": []}},
                "yara": {"result": {"matches": ["SuspiciousRule /tmp/sample.bin"], "stderr": []}},
            },
        )

        self.assertEqual(normalized["malwareScore"]["verdict"], "High Risk")
        self.assertEqual(normalized["malwareScore"]["score"], 100)

    def test_scan_score_counts_cves_and_weights_critical_high(self):
        task = ScanTask.objects.create(owner=self.user, input_type=ScanTask.InputType.IMAGE, target="alpine:latest")
        normalized, summary = normalize_results(
            task,
            {
                "trivy": {
                    "result": {
                        "Results": [
                            {
                                "Vulnerabilities": [
                                    {
                                        "VulnerabilityID": "CVE-CRITICAL",
                                        "Severity": "CRITICAL",
                                        "PkgName": "openssl",
                                        "InstalledVersion": "1.0",
                                    },
                                    {
                                        "VulnerabilityID": "CVE-HIGH",
                                        "Severity": "HIGH",
                                        "PkgName": "curl",
                                        "InstalledVersion": "7.0",
                                    },
                                ]
                            }
                        ]
                    }
                }
            },
        )

        self.assertEqual(summary["critical"], 1)
        self.assertEqual(summary["high"], 1)
        self.assertEqual(normalized["scanScore"]["cveCounts"]["total"], 2)
        self.assertGreaterEqual(normalized["scanScore"]["score"], 90)

    def test_pdfinfo_only_matches_pdf_files(self):
        self.assertTrue(_scanner_matches_file("pdfinfo", {"mime_type": "application/pdf"}))
        self.assertFalse(_scanner_matches_file("pdfinfo", {"mime_type": "application/zip"}))
        self.assertTrue(_scanner_matches_file("exiftool", {"mime_type": "application/zip"}))

    def test_hadolint_exit_one_is_findings_not_failure(self):
        scanner = HadolintScanner(ScannerContext(tool_name="hadolint", executable_path="hadolint"))
        stdout = '[{"code":"DL3007","level":"warning","line":1,"message":"Using latest is prone to errors"}]'

        with patch.object(
            scanner,
            "run_cmd",
            return_value=CompletedProcess(args=["hadolint"], returncode=1, stdout=stdout, stderr=""),
        ) as mocked_run:
            result = scanner.scan("/tmp/Dockerfile")

        mocked_run.assert_called_once()
        self.assertEqual(result["returncode"], 1)
        self.assertEqual(result["result"][0]["code"], "DL3007")

    def test_trufflehog_uses_filesystem_and_filters_json_logs(self):
        scanner = TrufflehogScanner(ScannerContext(tool_name="trufflehog", executable_path="trufflehog"))
        stdout = "\n".join(
            [
                '{"level":"info-0","logger":"trufflehog","msg":"running source"}',
                '{"DetectorName":"AWS","Raw":"AKIA...","Verified":false,"SourceMetadata":{"Data":{"Filesystem":{"file":"Dockerfile","line":3}}}}',
            ]
        )

        with patch.object(
            scanner,
            "run_cmd",
            return_value=CompletedProcess(args=["trufflehog"], returncode=0, stdout=stdout, stderr=""),
        ) as mocked_run:
            result = scanner.scan("/tmp/Dockerfile")

        command = mocked_run.call_args.args[0]
        self.assertEqual(command[:3], ["trufflehog", "filesystem", "/tmp/Dockerfile"])
        self.assertIn("--no-verification", command)
        self.assertEqual(len(result["result"]), 1)
        self.assertEqual(result["result"][0]["DetectorName"], "AWS")

    @patch("scanner_engine.core.tool_updates._run_command", return_value="12.80")
    def test_exiftool_version_uses_ver_flag(self, mocked_run):
        config = ScannerConfig(tool_name="exiftool", executable_path="exiftool")

        version = installed_version(config)

        self.assertEqual(version, "12.80")
        mocked_run.assert_called_once_with(["exiftool", "-ver"], timeout=20, allowed_returncodes=(0,))

    @patch("scanner_engine.core.tool_updates._binary_available", return_value=False)
    def test_missing_optional_tool_version_check_is_not_failed(self, _mocked_available):
        config = ScannerConfig.objects.create(
            tool_name="pdfinfo",
            display_name="PDFInfo",
            category=ScannerConfig.Category.METADATA,
            executable_path="pdfinfo",
            supported_input_types=[ScanTask.InputType.FILE],
        )

        state = check_tool_version(config)

        self.assertEqual(state.health_state, state.Health.UNKNOWN)
        self.assertEqual(state.action_state, state.ActionState.IDLE)
        self.assertIn("Executable not found", state.last_error)

    def test_unconfigured_binary_update_does_not_mark_tool_unhealthy(self):
        config = ScannerConfig.objects.create(
            tool_name="clamav",
            display_name="ClamAV",
            category=ScannerConfig.Category.MALWARE,
            executable_path="clamscan",
            supported_input_types=[ScanTask.InputType.FILE],
            binary_update_command=[],
        )
        state = ToolState.objects.create(tool=config)
        state.health_state = state.Health.HEALTHY
        state.save()

        state = update_tool_binary(config)

        self.assertEqual(state.health_state, state.Health.HEALTHY)
        self.assertEqual(state.action_state, state.ActionState.IDLE)
        self.assertEqual(state.last_error, "")
        self.assertIn("Binary update is not configured", state.logs[-1]["message"])

    def test_structured_json_formatter_outputs_structured_fields(self):
        record = logging.LogRecord(
            name="scanner_engine.scan",
            level=logging.INFO,
            pathname=__file__,
            lineno=1,
            msg="Running clamav",
            args=(),
            exc_info=None,
        )
        record.task_id = "task-123"
        record.scanner_name = "clamav"
        record.duration_ms = 42

        payload = json.loads(StructuredJsonFormatter().format(record))

        self.assertEqual(payload["log_level"], "INFO")
        self.assertEqual(payload["levelname"], "INFO")
        self.assertEqual(payload["module"], "orchestrator")
        self.assertEqual(payload["name"], "scanner_engine.scan")
        self.assertEqual(payload["task_id"], "task-123")
        self.assertEqual(payload["scanner_name"], "clamav")
        self.assertEqual(payload["message"], "Running clamav")
        self.assertIn("asctime", payload)
        self.assertEqual(payload["metadata"]["duration_ms"], 42)

    def test_trivy_always_uses_local_vulnerability_databases(self):
        context = ScannerContext(tool_name="trivy", executable_path="trivy", is_offline_mode=False)
        scanner = TrivyScanner(context)
        completed = CompletedProcess(args=[], returncode=0, stdout='{"Results": []}', stderr="")

        with patch.object(scanner, "run_cmd", return_value=completed) as run_cmd:
            scanner.scan("example:latest")

        command = run_cmd.call_args.args[0]
        self.assertIn("--skip-db-update", command)
        self.assertIn("--skip-java-db-update", command)
        self.assertIn("--offline-scan", command)
        self.assertEqual(command[command.index("--scanners") + 1], "vuln")
