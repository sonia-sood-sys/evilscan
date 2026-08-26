"""
DNS enumeration and analysis using dnsx.

Install on Kali:
    go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
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


def enumerate_dns(domains: list[str], resume: bool) -> dict[str, dict]:
    """
    Run dnsx against all domains and return DNS records.
    Returns a dict keyed by domain with DNS analysis results.
    """
    results: dict[str, dict] = {}

    for domain in domains:
        fname = domain.replace(".", "_")
        out_file: Path = config.DNS_DIR / f"{fname}.json"

        if resume and already_scanned(out_file):
            logger.info(f"[yellow]Resuming – loading existing DNS data for {domain}[/yellow]")
            try:
                dns_data = json.loads(out_file.read_text(encoding="utf-8"))
                results[domain] = dns_data
                logger.info(f"[green]DNS data loaded for {domain}[/green]")
            except json.JSONDecodeError:
                logger.warning(f"[yellow]Invalid DNS data for {domain}, rescanning[/yellow]")
                results[domain] = _run_dns_scan(domain, out_file)
            continue

        results[domain] = _run_dns_scan(domain, out_file)

    return results


def _run_dns_scan(domain: str, out_file: Path) -> dict:
    """Run dnsx against a single domain."""
    logger.info(f"[cyan]Enumerating DNS records for {domain} using dnsx[/cyan]")

    cmd = [
        config.DNSX_BIN,
        "-d", domain,
        "-json",
        "-o", str(out_file),
        "-r", config.DNSX_RESOLVERS,
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
                f"[cyan]Resolving DNS for {domain}..."
            )

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=config.DNSX_TIMEOUT,
            )

            if result.returncode not in (0, 1):
                logger.warning(
                    f"[yellow]dnsx returned {result.returncode} for {domain}[/yellow]"
                )
            if result.stderr:
                logger.debug(f"dnsx stderr: {result.stderr[:500]}")

            progress.update(task, completed=1)

    except FileNotFoundError:
        logger.error(
            "[red][!] dnsx not found.\n"
            "    Install: go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest[/red]"
        )
        return {"domain": domain, "error": "dnsx not found", "records": []}
    except subprocess.TimeoutExpired:
        logger.warning(f"[yellow]dnsx timed out for {domain}[/yellow]")
        return {"domain": domain, "error": "timeout", "records": []}
    except KeyboardInterrupt:
        raise

    # Parse results
    if out_file.exists():
        try:
            dns_records = []
            for line in out_file.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    dns_records.append(json.loads(line))
                except json.JSONDecodeError:
                    pass

            return {
                "domain": domain,
                "records": dns_records,
                "record_count": len(dns_records),
            }
        except Exception as exc:
            logger.warning(f"[yellow]Error parsing DNS data for {domain}: {exc}[/yellow]")
            return {"domain": domain, "error": str(exc), "records": []}
    else:
        return {"domain": domain, "records": [], "record_count": 0}