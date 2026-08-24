"""
Final report generator – Markdown, JSON, CSV.
"""

import csv
import json
import logging
from datetime import datetime
from pathlib import Path

import config

logger = logging.getLogger("evilscan")


def _severity_badge(severity: str) -> str:
    badges = {
        "critical": "🔴 CRITICAL",
        "high": "🟠 HIGH",
        "medium": "🟡 MEDIUM",
        "low": "🟢 LOW",
        "info": "🔵 INFO",
        "unknown": "⚪ UNKNOWN",
    }
    return badges.get(severity.lower(), severity.upper())


def generate_reports(
    domains: list[str],
    live_hosts: list[str],
    nmap_results: dict,
    nuclei_results: dict,
    nikto_results: dict,
    analysis_summary: dict,
) -> None:
    """Generate final_report.md, final_report.json, and final_report.csv."""
    logger.info("[cyan]▶ Generating final reports…[/cyan]")

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Load ranked findings
    ranked: list[dict] = []
    if config.RANKED_FINDINGS.exists():
        try:
            ranked = json.loads(config.RANKED_FINDINGS.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            pass

    high_priority: list[dict] = []
    if config.HIGH_PRIORITY.exists():
        try:
            high_priority = json.loads(config.HIGH_PRIORITY.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            pass

    severity_breakdown: dict = analysis_summary.get("severity_breakdown", {})
    category_breakdown: dict = analysis_summary.get("category_breakdown", {})
    top10: list[dict] = analysis_summary.get("top_10_critical", [])

    # ── Markdown Report ──────────────────────────────────────────────────────
    md_lines = [
        "# EvilScan – UltraRecon Final Report",
        "",
        f"> **Generated:** {timestamp}  ",
        "> **For authorized security testing only.**",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| Total Targets | {len(domains)} |",
        f"| Live Hosts | {len(live_hosts)} |",
        f"| Total Findings | {analysis_summary.get('total_findings', 0)} |",
        f"| High / Critical | {analysis_summary.get('high_priority_count', 0)} |",
        "",
        "---",
        "",
        "## Domains Scanned",
        "",
    ]
    for d in domains:
        status = "🟢 Live" if d in live_hosts else "🔴 Down"
        md_lines.append(f"- `{d}` – {status}")

    md_lines += [
        "",
        "---",
        "",
        "## Findings by Severity",
        "",
        "| Severity | Count |",
        "|----------|-------|",
    ]
    for sev in ("critical", "high", "medium", "low", "info", "unknown"):
        count = severity_breakdown.get(sev, 0)
        if count:
            md_lines.append(f"| {_severity_badge(sev)} | {count} |")

    md_lines += [
        "",
        "---",
        "",
        "## Findings by Category",
        "",
        "| Category | Count |",
        "|----------|-------|",
    ]
    for cat, cnt in sorted(category_breakdown.items(), key=lambda x: -x[1]):
        md_lines.append(f"| {cat} | {cnt} |")

    md_lines += [
        "",
        "---",
        "",
        "## Top 10 Critical Issues",
        "",
    ]
    for i, f in enumerate(top10, 1):
        md_lines += [
            f"### {i}. {f.get('name', 'Unknown')}",
            "",
            f"- **Domain:** `{f.get('domain', '')}`",
            f"- **Severity:** {_severity_badge(f.get('severity', 'unknown'))}",
            f"- **CVSS Estimate:** {f.get('cvss_estimate', 0.0):.1f}",
            f"- **Category:** {f.get('category', '')}",
            f"- **Matched At:** `{f.get('matched_at', '')}`",
            f"- **Source:** {f.get('source', '').upper()}",
            f"- **Description:** {f.get('description', '')[:300]}",
            "",
        ]

    md_lines += [
        "---",
        "",
        "## Per-Domain Breakdown",
        "",
    ]
    for domain in domains:
        nmap_data = nmap_results.get(domain, {})
        nuclei_data = nuclei_results.get(domain, {})
        nikto_data = nikto_results.get(domain, {})

        open_ports = nmap_data.get("open_ports", [])
        nuclei_count = len(nuclei_data.get("findings", []))
        nikto_count = len(nikto_data.get("interesting", []))

        md_lines += [
            f"### `{domain}`",
            "",
            f"- **Open Ports:** {len(open_ports)}",
        ]
        if open_ports:
            for p in open_ports[:10]:
                md_lines.append(
                    f"  - `{p['port']}/{p['protocol']}` – {p['service']} {p.get('version', '')}".rstrip()
                )
        md_lines += [
            f"- **Nuclei Findings:** {nuclei_count}",
            f"- **Nikto Interesting:** {nikto_count}",
            "",
        ]

    md_lines += [
        "---",
        "",
        "*EvilScan – For authorized security testing only.*",
        "",
    ]

    config.REPORT_MD.write_text("\n".join(md_lines), encoding="utf-8")

    # ── JSON Report ──────────────────────────────────────────────────────────
    json_report = {
        "meta": {
            "generated": timestamp,
            "tool": "EvilScan UltraRecon",
            "disclaimer": "For authorized security testing only.",
        },
        "summary": {
            "total_targets": len(domains),
            "live_hosts": len(live_hosts),
            "total_findings": analysis_summary.get("total_findings", 0),
            "high_priority_count": analysis_summary.get("high_priority_count", 0),
            "severity_breakdown": severity_breakdown,
            "category_breakdown": category_breakdown,
        },
        "domains": domains,
        "live_hosts": live_hosts,
        "top_10_critical": top10,
        "all_findings": ranked,
        "per_domain": {
            domain: {
                "open_ports": nmap_results.get(domain, {}).get("open_ports", []),
                "nuclei_findings": nuclei_results.get(domain, {}).get("findings", []),
                "nikto_interesting": nikto_results.get(domain, {}).get("interesting", []),
            }
            for domain in domains
        },
    }
    config.REPORT_JSON.write_text(
        json.dumps(json_report, indent=2), encoding="utf-8"
    )

    # ── CSV Report ───────────────────────────────────────────────────────────
    csv_fields = [
        "domain", "source", "name", "severity", "cvss_estimate",
        "category", "matched_at", "template_id", "description",
    ]
    with config.REPORT_CSV.open("w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=csv_fields, extrasaction="ignore")
        writer.writeheader()
        for f in ranked:
            writer.writerow(
                {k: (", ".join(v) if isinstance(v, list) else v) for k, v in f.items()
                 if k in csv_fields}
            )

    logger.info(
        f"[green]✔ Reports saved:[/green]\n"
        f"  [cyan]{config.REPORT_MD}[/cyan]\n"
        f"  [cyan]{config.REPORT_JSON}[/cyan]\n"
        f"  [cyan]{config.REPORT_CSV}[/cyan]"
    )
