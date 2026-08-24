"""
Advanced findings analyzer – deduplication, severity ranking, CVSS estimation.
"""

import json
import logging
from pathlib import Path

import config

logger = logging.getLogger("evilscan")


def _severity_from_finding(finding: dict) -> str:
    """Extract normalized severity string from a nuclei finding dict."""
    info = finding.get("info", {})
    sev = info.get("severity", "unknown").lower()
    return sev if sev in config.SEVERITY_SCORES else "unknown"


def _normalize_nuclei_finding(finding: dict, domain: str) -> dict:
    """Flatten a raw nuclei JSON finding into a standard analysis record."""
    info = finding.get("info", {})
    severity = _severity_from_finding(finding)
    return {
        "source": "nuclei",
        "domain": domain,
        "template_id": finding.get("template-id", ""),
        "name": info.get("name", ""),
        "severity": severity,
        "severity_score": config.SEVERITY_SCORES.get(severity, 0),
        "cvss_estimate": config.CVSS_ESTIMATES.get(severity, 0.0),
        "matched_at": finding.get("matched-at", ""),
        "description": info.get("description", ""),
        "tags": info.get("tags", []),
        "reference": info.get("reference", []),
        "category": _categorize(info.get("tags", []), info.get("name", "")),
    }


def _normalize_nikto_finding(line: str, domain: str) -> dict:
    """Create a standard analysis record from a nikto interesting line."""
    lower = line.lower()
    if any(k in lower for k in ("cve", "osvdb", "vulnerable", "injection", "xss")):
        severity = "high"
    elif any(k in lower for k in ("admin", "login", "password", "backup", "config", "upload")):
        severity = "medium"
    else:
        severity = "info"

    return {
        "source": "nikto",
        "domain": domain,
        "template_id": "",
        "name": line[:120],
        "severity": severity,
        "severity_score": config.SEVERITY_SCORES.get(severity, 0),
        "cvss_estimate": config.CVSS_ESTIMATES.get(severity, 0.0),
        "matched_at": domain,
        "description": line,
        "tags": [],
        "reference": [],
        "category": _categorize([], line),
    }


def _categorize(tags: list, name: str) -> str:
    """Assign a risk category based on tags and finding name."""
    combined = " ".join(tags + [name]).lower()
    if any(k in combined for k in ("sqli", "sql", "injection")):
        return "Injection"
    if any(k in combined for k in ("xss", "cross-site")):
        return "XSS"
    if any(k in combined for k in ("rce", "remote-code", "command")):
        return "RCE"
    if any(k in combined for k in ("ssrf",)):
        return "SSRF"
    if any(k in combined for k in ("lfi", "path-traversal", "directory-traversal")):
        return "Path Traversal"
    if any(k in combined for k in ("exposure", "disclosure", "leak", "info")):
        return "Information Disclosure"
    if any(k in combined for k in ("auth", "login", "password", "admin", "bypass")):
        return "Authentication"
    if any(k in combined for k in ("config", "misconfiguration", "default")):
        return "Misconfiguration"
    if any(k in combined for k in ("cve", "osvdb", "vulnerable", "outdated")):
        return "Known CVE"
    return "Other"


def _dedup(findings: list[dict]) -> list[dict]:
    """Remove duplicate findings based on (domain, template_id, matched_at, name)."""
    seen: set[tuple] = set()
    unique = []
    for f in findings:
        key = (
            f.get("domain", ""),
            f.get("template_id", ""),
            f.get("matched_at", ""),
            f.get("name", "")[:80],
        )
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def analyze(
    nuclei_results: dict[str, dict],
    nikto_results: dict[str, dict],
) -> dict:
    """
    Aggregate, normalize, deduplicate, and rank all findings.
    Writes ranked_findings.json and high_priority.json.
    Returns analysis summary dict.
    """
    logger.info("[cyan]▶ Analyzing findings…[/cyan]")

    all_findings: list[dict] = []

    # Nuclei findings
    for domain, data in nuclei_results.items():
        for raw in data.get("findings", []):
            all_findings.append(_normalize_nuclei_finding(raw, domain))

    # Nikto findings
    for domain, data in nikto_results.items():
        for line in data.get("interesting", []):
            all_findings.append(_normalize_nikto_finding(line, domain))

    # Deduplicate
    all_findings = _dedup(all_findings)

    # Sort by severity_score descending, then cvss descending
    all_findings.sort(
        key=lambda x: (x["severity_score"], x["cvss_estimate"]),
        reverse=True,
    )

    # High priority = critical + high
    high_priority = [
        f for f in all_findings if f["severity"] in ("critical", "high")
    ]

    # Category summary
    category_counts: dict[str, int] = {}
    severity_counts: dict[str, int] = {}
    for f in all_findings:
        category_counts[f["category"]] = category_counts.get(f["category"], 0) + 1
        severity_counts[f["severity"]] = severity_counts.get(f["severity"], 0) + 1

    summary = {
        "total_findings": len(all_findings),
        "high_priority_count": len(high_priority),
        "severity_breakdown": severity_counts,
        "category_breakdown": category_counts,
        "top_10_critical": all_findings[:10],
    }

    # Write output files
    config.RANKED_FINDINGS.write_text(
        json.dumps(all_findings, indent=2), encoding="utf-8"
    )
    config.HIGH_PRIORITY.write_text(
        json.dumps(high_priority, indent=2), encoding="utf-8"
    )

    logger.info(
        f"[green]✔ Analysis complete – {len(all_findings)} total, "
        f"{len(high_priority)} high/critical findings.[/green]"
    )
    return summary
