"""
Technology detection using wappalyzer.

Install on Kali:
    go install github.com/projectdiscovery/wappalyzergo/cmd/wappalyzergo@latest
"""

import json
import logging
import subprocess
from pathlib import Path

from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)

import config
from core.utils import already_scanned

logger = logging.getLogger("evilscan")


def detect_technologies(domains: list[str], resume: bool) -> dict[str, dict]:
    """
    Run wappalyzer against all domains and return detected technologies.
    Returns a dict keyed by domain with technology analysis results.
    """
    results: dict[str, dict] = {}

    for domain in domains:
        fname = domain.replace(".", "_")
        out_file: Path = config.TECH_DIR / f"{fname}.json"

        if resume and already_scanned(out_file):
            logger.info(f"[yellow]Resuming – loading existing tech data for {domain}[/yellow]")
            try:
                tech_data = json.loads(out_file.read_text(encoding="utf-8"))
                results[domain] = tech_data
                logger.info(f"[green]Technology data loaded for {domain}[/green]")
            except json.JSONDecodeError:
                logger.warning(f"[yellow]Invalid tech data for {domain}, rescanning[/yellow]")
                results[domain] = _run_tech_scan(domain, out_file)
            continue

        results[domain] = _run_tech_scan(domain, out_file)

    return results


def _run_tech_scan(domain: str, out_file: Path) -> dict:
    """Run wappalyzer against a single domain."""
    logger.info(f"[cyan]Detecting technologies for {domain} using wappalyzer[/cyan]")

    # Ensure domain has a scheme
    target = domain if domain.startswith("http") else f"https://{domain}"

    cmd = [
        config.WAPPALYZER_BIN,
        "-u", target,
        "-json",
        "-o", str(out_file),
    ]

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TimeElapsedColumn(),
            TimeRemainingColumn(),
            transient=True,
        ) as progress:
            task = progress.add_task(
                f"[cyan]Analyzing technologies for {domain}..."
            )

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=config.WAPPALYZER_TIMEOUT,
            )

            if result.returncode not in (0, 1):
                logger.warning(
                    f"[yellow]wappalyzer returned {result.returncode} for {domain}[/yellow]"
                )
            if result.stderr:
                logger.debug(f"wappalyzer stderr: {result.stderr[:500]}")

            progress.update(task, completed=1)

    except FileNotFoundError:
        logger.error(
            "[red][!] wappalyzer not found.\n"
            "    Install: go install github.com/projectdiscovery/wappalyzergo/cmd/wappalyzergo@latest[/red]"
        )
        return {"domain": domain, "error": "wappalyzer not found", "technologies": []}
    except subprocess.TimeoutExpired:
        logger.warning(f"[yellow]wappalyzer timed out for {domain}[/yellow]")
        return {"domain": domain, "error": "timeout", "technologies": []}
    except KeyboardInterrupt:
        raise

    # Parse results
    if out_file.exists():
        try:
            tech_data = json.loads(out_file.read_text(encoding="utf-8"))
            technologies = tech_data.get("technologies", [])

            # Categorize technologies
            categories = {
                "Web Servers": [],
                "Programming Languages": [],
                "Databases": [],
                "Frameworks": [],
                "Analytics": [],
                "CDN": [],
                "Security": [],
                "Other": []
            }

            for tech in technologies:
                name = tech.get("name", "Unknown")
                tech_cats = tech.get("categories", [])
                if not tech_cats:
                    categories["Other"].append(name)
                else:
                    for cat in tech_cats:
                        if cat in categories:
                            categories[cat].append(name)
                        else:
                            categories["Other"].append(name)

            return {
                "domain": domain,
                "technologies": technologies,
                "categories": categories,
                "tech_count": len(technologies),
            }
        except Exception as exc:
            logger.warning(f"[yellow]Error parsing tech data for {domain}: {exc}[/yellow]")
            return {"domain": domain, "error": str(exc), "technologies": []}
    else:
        return {"domain": domain, "technologies": [], "tech_count": 0}