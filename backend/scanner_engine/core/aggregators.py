from typing import Dict, Any


def _severity_bucket() -> Dict[str, int]:
    return {"critical": 0, "high": 0, "medium": 0, "low": 0}


def summarize_results(raw_results: Dict[str, Any]) -> Dict[str, int]:
    """
    Normalize counts for dashboard charts.
    Extend parsers per tool output schema.
    """
    summary = _severity_bucket()

    # Trivy parser
    trivy = raw_results.get("trivy", {}).get("result", {})
    for r in trivy.get("Results", []) if isinstance(trivy, dict) else []:
        for v in r.get("Vulnerabilities", []) or []:
            sev = (v.get("Severity") or "").lower()
            if sev in summary:
                summary[sev] += 1

    # Grype parser
    grype = raw_results.get("grype", {}).get("result", {})
    for m in grype.get("matches", []) if isinstance(grype, dict) else []:
        sev = (((m.get("vulnerability") or {}).get("severity")) or "").lower()
        if sev in summary:
            summary[sev] += 1

    # YARA does not map to CVE severity by default
     # Clair
    clair = raw_results.get("clair", {}).get("result", {})
    for vuln in clair.get("vulnerabilities", []):
        sev = (vuln.get("severity") or "").lower()
        if sev in summary:
            summary[sev] += 1

    anchore = raw_results.get("anchore", {}).get("result", {})
    for pkg in anchore.get("vulnerabilities", []):
        sev = (pkg.get("severity") or "").lower()
        if sev in summary:
            summary[sev] += 1

    osv = raw_results.get("osv-scanner", {}).get("result", {})
    for vuln in osv.get("vulnerabilities", []):
        sev = (vuln.get("severity") or "").lower()
        if sev in summary:
            summary[sev] += 1

    return summary
