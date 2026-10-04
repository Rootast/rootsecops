from scanner_engine.models import ScanTask


def mock_raw_results(task: ScanTask) -> dict:
    base = {
        "syft": {
            "tool": "syft",
            "result": {
                "artifacts": [
                    {"name": "alpine-baselibs", "version": "3.18.4-r0", "licenses": ["MIT"]},
                    {"name": "nginx", "version": "1.25.3-r0", "licenses": ["BSD-2-Clause"]},
                    {"name": "openssl", "version": "1.1.1w-r2", "licenses": ["Apache-2.0"]},
                    {"name": "python", "version": "3.11.7-r0", "licenses": ["PSF-2.0"]},
                    {"name": "gunicorn", "version": "21.2.0", "licenses": ["MIT"]},
                ]
            },
        },
        "trivy": {
            "tool": "trivy",
            "result": {
                "Results": [
                    {
                        "Vulnerabilities": [
                            {
                                "VulnerabilityID": "CVE-2024-10322",
                                "Severity": "CRITICAL",
                                "PkgName": "openssl",
                                "InstalledVersion": "1.1.1l-r9",
                                "FixedVersion": "1.1.1u-r0",
                                "Description": "Heap buffer overflow when parsing client-auth certificates in TLS handshake.",
                                "CVSS": {"nvd": {"V3Score": 9.8}},
                            },
                            {
                                "VulnerabilityID": "CVE-2024-08753",
                                "Severity": "HIGH",
                                "PkgName": "glibc",
                                "InstalledVersion": "2.35-r0",
                                "FixedVersion": "2.38-r0",
                                "Description": "Integer underflow leading to potential RCE when handling locale collations.",
                                "CVSS": {"nvd": {"V3Score": 7.5}},
                            },
                            {
                                "VulnerabilityID": "CVE-2023-55120",
                                "Severity": "MEDIUM",
                                "PkgName": "curl",
                                "InstalledVersion": "8.1.2-r0",
                                "FixedVersion": "8.4.0-r0",
                                "Description": "Cookie injection vulnerability via duplicated cookie names in redirects.",
                                "CVSS": {"nvd": {"V3Score": 5.4}},
                            },
                        ]
                    }
                ]
            },
        },
        "gitleaks": {
            "tool": "gitleaks",
            "result": [
                {"File": "src/config/aws-creds.yml", "StartLine": 42, "RuleID": "AWS Access Key", "Secret": "AKIAEXAMPLEWZ3U"}
            ],
        },
        "trufflehog": {
            "tool": "trufflehog",
            "result": [
                {
                    "DetectorName": "Slack Webhook",
                    "SourceMetadata": {"Data": {"Filesystem": {"file": "helm/values.yaml"}}},
                }
            ],
        },
        "hadolint": {
            "tool": "hadolint",
            "result": [{"code": "DL3025", "message": "Use COPY instead of ADD for local file copies."}],
        },
        "checkov": {
            "tool": "checkov",
            "result": {
                "results": {
                    "failed_checks": [
                        {
                            "check_id": "CKV_DOCKER_2",
                            "check_name": "Ensure container is run with a non-root user.",
                            "guideline": "Add USER app to Dockerfile and ensure directories are owned by that user.",
                        }
                    ]
                }
            },
        },
        "clamav": {"tool": "clamav", "result": {"matches": []}},
        "yara": {"tool": "yara", "result": {"matches": ["AWS_Keys_Light config/secrets.json"], "count": 1}},
    }
    if task.input_type == ScanTask.InputType.DOCKERFILE:
        return {key: base[key] for key in ["hadolint", "checkov"]}
    if task.input_type == ScanTask.InputType.GIT:
        return {key: base[key] for key in ["gitleaks", "trufflehog", "checkov", "yara"]}
    return base
