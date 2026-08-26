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


def _severity_color(severity: str) -> str:
    colors = {
        "critical": "#dc3545",
        "high": "#fd7e14",
        "medium": "#ffc107",
        "low": "#28a745",
        "info": "#17a2b8",
        "unknown": "#6c757d",
    }
    return colors.get(severity.lower(), "#6c757d")


def _generate_html_report(
    timestamp: str, domains: list[str], live_hosts: list[str],
    analysis_summary: dict, severity_breakdown: dict,
    category_breakdown: dict, top10: list[dict],
    nmap_results: dict, nuclei_results: dict, nikto_results: dict,
    subdomain_results: dict = None, dns_results: dict = None,
    tech_results: dict = None, dir_results: dict = None
) -> str:
    """Generate an HTML report with styling."""
    html = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>EvilScan – UltraRecon Report</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f8f9fa;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            text-align: center;
        }
        .summary {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }
        .metric-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 15px;
        }
        .metric {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
            text-align: center;
        }
        .metric-value {
            font-size: 2em;
            font-weight: bold;
            color: #667eea;
        }
        .metric-label {
            color: #666;
            font-size: 0.9em;
        }
        .section {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }
        .section h2 {
            color: #667eea;
            border-bottom: 2px solid #667eea;
            padding-bottom: 10px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #667eea;
            color: white;
        }
        tr:hover {
            background-color: #f5f5f5;
        }
        .severity-critical { background-color: #dc3545; color: white; }
        .severity-high { background-color: #fd7e14; color: white; }
        .severity-medium { background-color: #ffc107; color: black; }
        .severity-low { background-color: #28a745; color: white; }
        .severity-info { background-color: #17a2b8; color: white; }
        .severity-unknown { background-color: #6c757d; color: white; }
        .disclaimer {
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 15px;
            margin-top: 30px;
            border-radius: 5px;
        }
        .badge {
            padding: 5px 10px;
            border-radius: 15px;
            font-size: 0.85em;
            font-weight: bold;
        }
        .domain-card {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 10px;
            border-left: 4px solid #667eea;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔍 EvilScan – UltraRecon Report</h1>
        <p>Generated: """ + timestamp + """</p>
        <p><strong>For authorized security testing only.</strong></p>
    </div>

    <div class="summary">
        <h2>📊 Executive Summary</h2>
        <div class="metric-grid">
            <div class="metric">
                <div class="metric-value">""" + str(len(domains)) + """</div>
                <div class="metric-label">Total Targets</div>
            </div>
            <div class="metric">
                <div class="metric-value">""" + str(len(live_hosts)) + """</div>
                <div class="metric-label">Live Hosts</div>
            </div>
            <div class="metric">
                <div class="metric-value">""" + str(analysis_summary.get('total_findings', 0)) + """</div>
                <div class="metric-label">Total Findings</div>
            </div>
            <div class="metric">
                <div class="metric-value">""" + str(analysis_summary.get('high_priority_count', 0)) + """</div>
                <div class="metric-label">High/Critical</div>
            </div>
        </div>
    </div>

    <div class="section">
        <h2>🎯 Domains Scanned</h2>
"""

    for domain in domains:
        status = "🟢 Live" if domain in live_hosts else "🔴 Down"
        html += f'        <div class="domain-card"><strong>{domain}</strong> – {status}</div>\n'

    html += """    </div>

    <div class="section">
        <h2>⚠️ Findings by Severity</h2>
        <table>
            <tr>
                <th>Severity</th>
                <th>Count</th>
            </tr>
"""

    for sev in ("critical", "high", "medium", "low", "info", "unknown"):
        count = severity_breakdown.get(sev, 0)
        if count:
            html += f'            <tr><td><span class="badge severity-{sev}">{sev.upper()}</span></td><td>{count}</td></tr>\n'

    html += """        </table>
    </div>

    <div class="section">
        <h2>📁 Findings by Category</h2>
        <table>
            <tr>
                <th>Category</th>
                <th>Count</th>
            </tr>
"""

    for cat, cnt in sorted(category_breakdown.items(), key=lambda x: -x[1]):
        html += f'            <tr><td>{cat}</td><td>{cnt}</td></tr>\n'

    html += """        </table>
    </div>

    <div class="section">
        <h2>🔥 Top 10 Critical Issues</h2>
"""

    for i, f in enumerate(top10, 1):
        sev = f.get('severity', 'unknown')
        html += f"""        <div class="domain-card">
            <h3>{i}. {f.get('name', 'Unknown')}</h3>
            <p><strong>Domain:</strong> {f.get('domain', '')}</p>
            <p><strong>Severity:</strong> <span class="badge severity-{sev}">{sev.upper()}</span></p>
            <p><strong>CVSS Estimate:</strong> {f.get('cvss_estimate', 0.0):.1f}</p>
            <p><strong>Category:</strong> {f.get('category', '')}</p>
            <p><strong>Matched At:</strong> {f.get('matched_at', '')}</p>
            <p><strong>Source:</strong> {f.get('source', '').upper()}</p>
            <p><strong>Description:</strong> {f.get('description', '')[:300]}</p>
        </div>
"""

    html += """    </div>

    <div class="section">
        <h2>🖥️ Per-Domain Breakdown</h2>
"""

    for domain in domains:
        nmap_data = nmap_results.get(domain, {})
        nuclei_data = nuclei_results.get(domain, {})
        nikto_data = nikto_results.get(domain, {})

        open_ports = nmap_data.get("open_ports", [])
        nuclei_count = len(nuclei_data.get("findings", []))
        nikto_count = len(nikto_data.get("interesting", []))

        html += f"""        <div class="domain-card">
            <h3>{domain}</h3>
            <p><strong>Open Ports:</strong> {len(open_ports)}</p>
"""

        if open_ports:
            html += "            <ul>\n"
            for p in open_ports[:10]:
                html += f'                <li>{p["port"]}/{p["protocol"]} – {p["service"]} {p.get("version", "")}</li>\n'
            html += "            </ul>\n"

        html += f"""            <p><strong>Nuclei Findings:</strong> {nuclei_count}</p>
            <p><strong>Nikto Interesting:</strong> {nikto_count}</p>
        </div>
"""

    html += """    </div>

    <div class="disclaimer">
        <strong>⚠️ Disclaimer:</strong> This tool is intended solely for authorized penetration testing and bug bounty programs. Always obtain explicit written permission before scanning any target. The authors assume no liability for misuse.
    </div>
</body>
</html>"""

    return html


def generate_reports(
    domains: list[str],
    live_hosts: list[str],
    nmap_results: dict,
    nuclei_results: dict,
    nikto_results: dict,
    analysis_summary: dict,
    subdomain_results: dict = None,
    dns_results: dict = None,
    tech_results: dict = None,
    dir_results: dict = None,
) -> None:
    """Generate final_report.md, final_report.json, final_report.csv, and final_report.html."""
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
    ]

    # Add new metrics if available
    if subdomain_results:
        total_subs = sum(len(subs) for subs in subdomain_results.values())
        md_lines.append(f"| Subdomains Found | {total_subs} |")

    if dns_results:
        total_dns = sum(len(data.get("records", [])) for data in dns_results.values())
        md_lines.append(f"| DNS Records | {total_dns} |")

    if tech_results:
        total_tech = sum(data.get("tech_count", 0) for data in tech_results.values())
        md_lines.append(f"| Technologies Detected | {total_tech} |")

    if dir_results:
        total_dirs = sum(data.get("directory_count", 0) for data in dir_results.values())
        md_lines.append(f"| Directories Found | {total_dirs} |")

    md_lines += [
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
        "## Subdomain Enumeration",
        "",
    ]

    if subdomain_results:
        for domain, subdomains in subdomain_results.items():
            if subdomains:
                md_lines.append(f"### `{domain}`")
                md_lines.append(f"**Found {len(subdomains)} subdomains:**")
                for sub in subdomains[:20]:  # Show first 20
                    md_lines.append(f"- {sub}")
                if len(subdomains) > 20:
                    md_lines.append(f"- ... and {len(subdomains) - 20} more")
                md_lines.append("")
    else:
        md_lines.append("No subdomain enumeration performed.")

    md_lines += [
        "",
        "---",
        "",
        "## DNS Analysis",
        "",
    ]

    if dns_results:
        for domain, dns_data in dns_results.items():
            records = dns_data.get("records", [])
            if records:
                md_lines.append(f"### `{domain}`")
                md_lines.append(f"**Found {len(records)} DNS records:**")
                for record in records[:10]:  # Show first 10
                    md_lines.append(f"- {record.get('host', '')} - {record.get('type', '')}: {record.get('data', '')}")
                if len(records) > 10:
                    md_lines.append(f"- ... and {len(records) - 10} more")
                md_lines.append("")
    else:
        md_lines.append("No DNS enumeration performed.")

    md_lines += [
        "",
        "---",
        "",
        "## Technology Detection",
        "",
    ]

    if tech_results:
        for domain, tech_data in tech_results.items():
            technologies = tech_data.get("technologies", [])
            if technologies:
                md_lines.append(f"### `{domain}`")
                md_lines.append(f"**Detected {len(technologies)} technologies:**")
                categories = tech_data.get("categories", {})
                for cat, techs in categories.items():
                    if techs:
                        md_lines.append(f"**{cat}:** {', '.join(techs)}")
                md_lines.append("")
    else:
        md_lines.append("No technology detection performed.")

    md_lines += [
        "",
        "---",
        "",
        "## Directory Enumeration",
        "",
    ]

    if dir_results:
        for domain, dir_data in dir_results.items():
            directories = dir_data.get("directories", [])
            if directories:
                md_lines.append(f"### `{domain}`")
                md_lines.append(f"**Found {len(directories)} directories:**")
                for dir_entry in directories[:15]:  # Show first 15
                    md_lines.append(f"- {dir_entry.get('path', '')} (Status: {dir_entry.get('status', 0)})")
                if len(directories) > 15:
                    md_lines.append(f"- ... and {len(directories) - 15} more")
                md_lines.append("")
    else:
        md_lines.append("No directory enumeration performed.")

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
                "subdomains": subdomain_results.get(domain, []) if subdomain_results else [],
                "dns_records": dns_results.get(domain, {}).get("records", []) if dns_results else [],
                "technologies": tech_results.get(domain, {}).get("technologies", []) if tech_results else [],
                "directories": dir_results.get(domain, {}).get("directories", []) if dir_results else [],
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

    # ── HTML Report ─────────────────────────────────────────────────────────
    html_content = _generate_html_report(
        timestamp, domains, live_hosts, analysis_summary,
        severity_breakdown, category_breakdown, top10,
        nmap_results, nuclei_results, nikto_results,
        subdomain_results, dns_results, tech_results, dir_results
    )
    config.REPORT_HTML.write_text(html_content, encoding="utf-8")

    logger.info(
        f"[green]✔ Reports saved:[/green]\n"
        f"  [cyan]{config.REPORT_MD}[/cyan]\n"
        f"  [cyan]{config.REPORT_JSON}[/cyan]\n"
        f"  [cyan]{config.REPORT_CSV}[/cyan]\n"
        f"  [cyan]{config.REPORT_HTML}[/cyan]"
    )
