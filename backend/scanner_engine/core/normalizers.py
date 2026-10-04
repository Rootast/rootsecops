from __future__ import annotations

from typing import Any

from django.utils import timezone

from scanner_engine.display import display_target
from scanner_engine.models import ScanTask


SEVERITY_KEYS = ("critical", "high", "medium", "low")


def empty_summary() -> dict[str, int]:
    return {key: 0 for key in SEVERITY_KEYS}


def normalize_results(task: ScanTask, raw_results: dict[str, Any]) -> tuple[dict[str, Any], dict[str, int]]:
    normalized = {
        "metadata": {
            "asset": display_target(task),
            "taskUuid": str(task.id),
            "triggeredAt": task.created_at.isoformat() if task.created_at else timezone.now().isoformat(),
            "orchestratedBy": "django-rest-framework",
        },
        "cves": [],
        "secrets": [],
        "misconfigurations": [],
        "malware": [],
        "sbom": [],
        "errors": raw_results.get("_errors", []),
        "toolStatus": raw_results.get("_tool_status", []),
    }
    summary = empty_summary()

    for vuln in _trivy_vulns(raw_results.get("trivy", {}).get("result", {})):
        _append_cve(normalized, summary, vuln)
    for vuln in _grype_vulns(raw_results.get("grype", {}).get("result", {})):
        _append_cve(normalized, summary, vuln)
    for vuln in _osv_vulns(raw_results.get("osv-scanner", {}).get("result", {})):
        _append_cve(normalized, summary, vuln)
    for vuln in _clair_vulns(raw_results.get("clair", {}).get("result", {})):
        _append_cve(normalized, summary, vuln)
    for vuln in _anchore_vulns(raw_results.get("anchore", {}).get("result", {})):
        _append_cve(normalized, summary, vuln)

    syft = raw_results.get("syft", {}).get("result", {})
    for artifact in syft.get("artifacts", []) if isinstance(syft, dict) else []:
        normalized["sbom"].append(
            {
                "name": artifact.get("name", ""),
                "version": artifact.get("version", ""),
                "license": _format_license(artifact),
                "source": "Syft",
            }
        )
    _normalize_grant_results(normalized, raw_results)

    _normalize_file_metadata(normalized, raw_results)
    if raw_results.get("_file_profile"):
        normalized["metadata"]["fileProfile"] = raw_results["_file_profile"]

    _normalize_secret_results(normalized, raw_results)
    _normalize_misconfiguration_results(normalized, raw_results)
    _normalize_malware_results(normalized, raw_results)
    normalized["malwareScore"] = _malware_score(task, normalized, raw_results)
    normalized["scanScore"] = _scan_score(normalized, summary)

    return normalized, summary


def _format_license(artifact: dict[str, Any]) -> str:
    licenses = artifact.get("licenses")
    if isinstance(licenses, list):
        values = []
        for item in licenses:
            if isinstance(item, str):
                values.append(item)
            elif isinstance(item, dict):
                value = item.get("value") or item.get("license") or item.get("spdxExpression")
                if value:
                    values.append(str(value))
        return ", ".join(values)
    if isinstance(licenses, str):
        return licenses
    license_value = artifact.get("license", "")
    return str(license_value) if license_value else ""


def _append_cve(normalized, summary, vuln):
    severity = (vuln.get("severity") or "Low").lower()
    if severity in summary:
        summary[severity] += 1
    normalized["cves"].append(
        {
            "id": vuln.get("id", ""),
            "severity": severity.title(),
            "score": float(vuln.get("score") or 0),
            "package": vuln.get("package", ""),
            "version": vuln.get("version", ""),
            "fixed": vuln.get("fixed", ""),
            "description": vuln.get("description", ""),
        }
    )


def _trivy_vulns(result):
    if not isinstance(result, dict):
        return []
    vulns = []
    for section in result.get("Results", []) or []:
        for item in section.get("Vulnerabilities", []) or []:
            vulns.append(
                {
                    "id": item.get("VulnerabilityID"),
                    "severity": item.get("Severity"),
                    "score": (item.get("CVSS") or {}).get("nvd", {}).get("V3Score") or item.get("CVSS", {}).get("redhat", {}).get("V3Score") or 0,
                    "package": item.get("PkgName"),
                    "version": item.get("InstalledVersion"),
                    "fixed": item.get("FixedVersion", ""),
                    "description": item.get("Description", ""),
                }
            )
    return vulns


def _grype_vulns(result):
    if not isinstance(result, dict):
        return []
    vulns = []
    for match in result.get("matches", []) or []:
        vulnerability = match.get("vulnerability") or {}
        artifact = match.get("artifact") or {}
        vulns.append(
            {
                "id": vulnerability.get("id"),
                "severity": vulnerability.get("severity"),
                "score": vulnerability.get("cvss", [{}])[0].get("metrics", {}).get("baseScore", 0) if vulnerability.get("cvss") else 0,
                "package": artifact.get("name"),
                "version": artifact.get("version"),
                "fixed": ", ".join(vulnerability.get("fix", {}).get("versions", []) or []),
                "description": vulnerability.get("description", ""),
            }
        )
    return vulns


def _osv_vulns(result):
    if not isinstance(result, dict):
        return []
    vulns = []
    packages = result.get("results") or result.get("packages") or []
    for package_result in packages:
        package_info = package_result.get("package") or package_result.get("packages", [{}])[0] if isinstance(package_result, dict) else {}
        for vuln in package_result.get("vulnerabilities", []) or []:
            aliases = vuln.get("aliases") or []
            vuln_id = vuln.get("id") or (aliases[0] if aliases else "")
            severity = _osv_severity(vuln)
            vulns.append(
                {
                    "id": vuln_id,
                    "severity": severity,
                    "score": _osv_score(vuln),
                    "package": package_info.get("name", ""),
                    "version": package_info.get("version", ""),
                    "fixed": ", ".join(_fixed_versions(vuln)),
                    "description": vuln.get("summary") or vuln.get("details", ""),
                }
            )
    return vulns


def _osv_score(vuln: dict[str, Any]) -> float:
    for item in vuln.get("severity", []) or []:
        score = str(item.get("score", ""))
        if "/" in score:
            try:
                return float(score.split("/")[0])
            except ValueError:
                return 0
    return 0


def _osv_severity(vuln: dict[str, Any]) -> str:
    score = _osv_score(vuln)
    if score >= 9:
        return "Critical"
    if score >= 7:
        return "High"
    if score >= 4:
        return "Medium"
    return "Low"


def _fixed_versions(vuln: dict[str, Any]) -> list[str]:
    versions = []
    for affected in vuln.get("affected", []) or []:
        for event in affected.get("ranges", [{}])[0].get("events", []) or []:
            if event.get("fixed"):
                versions.append(str(event["fixed"]))
    return versions


def _clair_vulns(result):
    if not isinstance(result, dict):
        return []
    vulns = []
    candidates = result.get("vulnerabilities") or result.get("Vulnerabilities") or []
    for item in candidates:
        package = item.get("package") or item.get("packageName") or item.get("featurename") or {}
        fixed = item.get("fixed") or item.get("fixedBy") or item.get("FixedBy") or ""
        vulns.append(
            {
                "id": item.get("name") or item.get("id") or item.get("vulnerability") or item.get("VulnerabilityID"),
                "severity": item.get("severity") or item.get("Severity"),
                "score": item.get("cvssScore") or item.get("score") or 0,
                "package": package.get("name", "") if isinstance(package, dict) else package,
                "version": item.get("version") or item.get("packageVersion") or item.get("featureversion") or "",
                "fixed": ", ".join(fixed) if isinstance(fixed, list) else fixed,
                "description": item.get("description") or item.get("link") or "",
            }
        )
    return vulns


def _anchore_vulns(result):
    if not isinstance(result, dict):
        return []
    vulns = []
    candidates = result.get("vulnerabilities") or result.get("Vulnerabilities") or result.get("matches") or []
    for item in candidates:
        vuln = item.get("vulnerability", item)
        artifact = item.get("artifact", {})
        vulns.append(
            {
                "id": vuln.get("vuln") or vuln.get("id") or vuln.get("VulnerabilityID"),
                "severity": vuln.get("severity") or vuln.get("Severity"),
                "score": vuln.get("cvssScore") or vuln.get("score") or 0,
                "package": artifact.get("name") or vuln.get("package") or vuln.get("package_name") or "",
                "version": artifact.get("version") or vuln.get("package_version") or vuln.get("version") or "",
                "fixed": vuln.get("fix") or vuln.get("fixed") or vuln.get("fixed_in") or "",
                "description": vuln.get("description") or vuln.get("url") or "",
            }
        )
    return vulns


def _normalize_file_metadata(normalized, raw_results):
    exif = raw_results.get("exiftool", {}).get("result", [])
    if isinstance(exif, list) and exif:
        normalized["metadata"]["exiftool"] = exif[0]
    elif isinstance(exif, dict) and exif:
        normalized["metadata"]["exiftool"] = exif

    pdfinfo = raw_results.get("pdfinfo", {}).get("result", {})
    if isinstance(pdfinfo, dict) and pdfinfo.get("metadata"):
        normalized["metadata"]["pdfinfo"] = pdfinfo["metadata"]


def _normalize_grant_results(normalized, raw_results):
    result = raw_results.get("grant", {}).get("result", {})
    if not isinstance(result, (dict, list)):
        return
    entries = _grant_entries(result)
    for entry in entries[:500]:
        normalized["sbom"].append(
            {
                "name": entry.get("name", ""),
                "version": entry.get("version", ""),
                "license": entry.get("license", ""),
                "source": "Grant",
            }
        )
    if entries:
        normalized["metadata"]["grant"] = {
            "packages": len(entries),
            "licenses": sorted({entry.get("license", "") for entry in entries if entry.get("license")})[:40],
        }


def _grant_entries(payload) -> list[dict[str, str]]:
    entries = []

    def visit(value):
        if isinstance(value, dict):
            name = value.get("name") or value.get("package") or value.get("packageName") or value.get("artifact")
            version = value.get("version") or value.get("packageVersion") or ""
            license_value = value.get("license") or value.get("licenses") or value.get("spdxExpression") or value.get("licenseExpression")
            if name and license_value:
                if isinstance(license_value, list):
                    license_text = ", ".join(str(item.get("value", item)) if isinstance(item, dict) else str(item) for item in license_value)
                else:
                    license_text = str(license_value)
                entries.append({"name": str(name), "version": str(version), "license": license_text})
            for nested in value.values():
                visit(nested)
        elif isinstance(value, list):
            for item in value:
                visit(item)

    visit(payload)
    deduped = []
    seen = set()
    for item in entries:
        key = (item["name"], item["version"], item["license"])
        if key not in seen:
            seen.add(key)
            deduped.append(item)
    return deduped


def _normalize_secret_results(normalized, raw_results):
    for finding in raw_results.get("gitleaks", {}).get("result", []) or []:
        normalized["secrets"].append(
            {
                "tool": "Gitleaks",
                "file": finding.get("File", ""),
                "line": finding.get("StartLine", 0),
                "secretType": finding.get("RuleID") or finding.get("Description") or "Secret",
                "preview": _secret_preview(finding),
                "commit": finding.get("Commit", ""),
                "author": finding.get("Author", ""),
                "message": finding.get("Message", ""),
                "entropy": finding.get("Entropy"),
            }
        )
    for finding in raw_results.get("trufflehog", {}).get("result", []) or []:
        source = _trufflehog_source(finding)
        detector = finding.get("DetectorName", "Secret") if isinstance(finding, dict) else "Secret"
        normalized["secrets"].append(
            {
                "tool": "Trufflehog",
                "file": source.get("file", "") or source.get("path", ""),
                "line": source.get("line", 0) or source.get("line_number", 0) or 0,
                "secretType": detector,
                "preview": finding.get("Raw", "")[:120] if isinstance(finding, dict) and finding.get("Raw") else "verified secret" if finding.get("Verified") else "unverified secret",
                "verified": finding.get("Verified"),
                "source": finding.get("SourceName") or finding.get("SourceTypeName", ""),
            }
        )


def _secret_preview(finding: dict[str, Any]) -> str:
    secret = finding.get("Secret", "")
    if not secret:
        return finding.get("Match", "")[:120]
    if len(secret) <= 12:
        return secret[:2] + "****"
    return secret[:8] + "****" + secret[-4:]


def _trufflehog_source(finding: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(finding, dict):
        return {}
    data = finding.get("SourceMetadata", {}).get("Data", {})
    for value in data.values():
        if isinstance(value, dict):
            return value
    return {}


def _normalize_misconfiguration_results(normalized, raw_results):
    for item in raw_results.get("hadolint", {}).get("result", []) or []:
        normalized["misconfigurations"].append(
            {
                "tool": "Hadolint",
                "rule": item.get("code", ""),
                "description": item.get("message", ""),
                "remediation": "Review Dockerfile instruction and rebuild the image.",
            }
        )
    kics = raw_results.get("kics", {}).get("result", {})
    for query in kics.get("queries", []) if isinstance(kics, dict) else []:
        for file_item in query.get("files", []) or []:
            normalized["misconfigurations"].append(
                {
                    "tool": "KICS",
                    "rule": query.get("query_id") or query.get("query_name") or "",
                    "description": query.get("query_name") or query.get("description") or "",
                    "remediation": query.get("remediation") or file_item.get("expected_value") or "Review the flagged Dockerfile/IaC instruction.",
                }
            )
    checkov = raw_results.get("checkov", {}).get("result", {})
    for item in checkov.get("results", {}).get("failed_checks", []) if isinstance(checkov, dict) else []:
        normalized["misconfigurations"].append(
            {
                "tool": "Checkov",
                "rule": item.get("check_id", ""),
                "description": item.get("check_name", ""),
                "remediation": item.get("guideline", ""),
            }
        )


def _normalize_malware_results(normalized, raw_results):
    if "clamav" in raw_results:
        result = raw_results["clamav"].get("result", {})
        matches = result.get("matches", [])
        returncode = result.get("returncode", 0)
        summary = result.get("summary", [])
        status = "Alert" if matches else "Clean"
        description = "Malware signatures matched." if matches else "No malware signatures matched."
        if returncode == 2 and not matches:
            status = "Warning"
            description = "ClamAV scanned the target but reported engine or file access errors."
        normalized["malware"].append(
            {
                "engine": "ClamAV",
                "status": status,
                "signature": matches[0] if matches else None,
                "description": description,
                "matches": matches,
                "stderr": summary,
            }
        )
    if "yara" in raw_results:
        matches = raw_results["yara"].get("result", {}).get("matches", [])
        stderr = raw_results["yara"].get("result", {}).get("stderr", [])
        normalized["malware"].append(
            {
                "engine": "YARA",
                "status": "Alert" if matches else "Clean",
                "signature": matches[0] if matches else None,
                "description": "YARA rule matched." if matches else "No YARA rules matched.",
                "matches": matches,
                "stderr": stderr,
            }
        )


def _malware_score(task: ScanTask, normalized: dict[str, Any], raw_results: dict[str, Any]) -> dict[str, Any]:
    if task.input_type != ScanTask.InputType.FILE:
        return {}
    score = 0
    findings = []
    clamav_matches = raw_results.get("clamav", {}).get("result", {}).get("matches", [])
    if clamav_matches:
        score = max(score, 95)
        findings.append({"source": "ClamAV", "impact": 95, "reason": clamav_matches[0]})

    yara_matches = raw_results.get("yara", {}).get("result", {}).get("matches", [])
    high_severity_yara = [match for match in yara_matches if _is_high_severity_yara(match)]
    yara_impact = min(90, len(high_severity_yara or yara_matches) * 25)
    if yara_impact:
        score += yara_impact
        findings.append({"source": "YARA", "impact": yara_impact, "reason": f"{len(yara_matches)} rule matches"})

    file_profile = raw_results.get("_file_profile", {})
    suspicious_pdf_tags = file_profile.get("suspicious_pdf_tags", [])
    if suspicious_pdf_tags:
        score += 30
        findings.append({"source": "PDF", "impact": 30, "reason": f"Suspicious PDF tags: {', '.join(suspicious_pdf_tags)}"})

    if normalized.get("secrets"):
        impact = len(normalized["secrets"]) * 20
        score += impact
        findings.append({"source": "Secrets", "impact": impact, "reason": f"{len(normalized['secrets'])} exposed credential findings"})

    if file_profile.get("extension_mismatch"):
        score += 15
        findings.append(
            {
                "source": "Metadata",
                "impact": 15,
                "reason": f"Extension {file_profile.get('extension')} does not match magic type {file_profile.get('mime_type')}",
            }
        )

    score = min(score, 100)
    if score >= 86:
        verdict = "High Risk"
    elif score >= 51:
        verdict = "Malicious"
    elif score >= 11:
        verdict = "Suspicious"
    else:
        verdict = "Clean"
    return {"score": score, "verdict": verdict, "findings": findings}


def _is_high_severity_yara(match: str) -> bool:
    lowered = str(match).lower()
    markers = ("high", "critical", "malware", "trojan", "ransom", "stealer", "backdoor", "shellcode", "exploit")
    return any(marker in lowered for marker in markers)


def _scan_score(normalized: dict[str, Any], summary: dict[str, int]) -> dict[str, Any]:
    critical = int(summary.get("critical", 0))
    high = int(summary.get("high", 0))
    medium = int(summary.get("medium", 0))
    low = int(summary.get("low", 0))
    score = min(100, critical * 30 + high * 15 + medium * 6 + low * 2)
    findings = []
    if critical:
        score = max(score, 90)
        findings.append({"source": "CVE", "impact": 90, "reason": f"{critical} critical vulnerabilities"})
    if high:
        findings.append({"source": "CVE", "impact": min(45, high * 15), "reason": f"{high} high vulnerabilities"})
    if medium:
        findings.append({"source": "CVE", "impact": min(30, medium * 6), "reason": f"{medium} medium vulnerabilities"})
    if normalized.get("secrets"):
        score = min(100, score + min(30, len(normalized["secrets"]) * 10))
        findings.append({"source": "Secrets", "impact": min(30, len(normalized["secrets"]) * 10), "reason": f"{len(normalized['secrets'])} credential findings"})
    if normalized.get("misconfigurations"):
        score = min(100, score + min(25, len(normalized["misconfigurations"]) * 5))
        findings.append({"source": "Misconfiguration", "impact": min(25, len(normalized["misconfigurations"]) * 5), "reason": f"{len(normalized['misconfigurations'])} policy findings"})
    if score >= 86:
        verdict = "High Risk"
    elif score >= 51:
        verdict = "Malicious"
    elif score >= 11:
        verdict = "Suspicious"
    else:
        verdict = "Clean"
    return {
        "score": score,
        "verdict": verdict,
        "cveCounts": {"critical": critical, "high": high, "medium": medium, "low": low, "total": critical + high + medium + low},
        "findings": findings,
    }
