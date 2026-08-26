"""
Subdomain enumeration using subfinder.

Install on Kali:
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
"""

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


def enumerate_subdomains(domains: list[str], resume: bool) -> dict[str, list[str]]:
    """
    Run subfinder against all domains and return discovered subdomains.
    Returns a dict keyed by domain with list of subdomains.
    """
    results: dict[str, list[str]] = {}

    for domain in domains:
        fname = domain.replace(".", "_")
        out_file: Path = config.SUBDOMAIN_DIR / f"{fname}.txt"

        if resume and already_scanned(out_file):
            logger.info(f"[yellow]Resuming – loading existing subdomains for {domain}[/yellow]")
            subdomains = [
                line.strip()
                for line in out_file.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            results[domain] = subdomains
            logger.info(f"[green]{len(subdomains)} subdomains loaded for {domain}[/green]")
            continue

        logger.info(f"[cyan]Enumerating subdomains for {domain} using subfinder[/cyan]")

        cmd = [
            config.SUBFINDER_BIN,
            "-d", domain,
            "-silent",
            "-o", str(out_file),
        ]

        if config.SUBFINDER_ALL_SOURCES:
            cmd.extend(["-all"])

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
                    f"[cyan]Finding subdomains for {domain}..."
                )

                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=config.SUBFINDER_TIMEOUT,
                )

                if result.returncode not in (0, 1):
                    logger.warning(
                        f"[yellow]subfinder returned {result.returncode} for {domain}[/yellow]"
                    )
                if result.stderr:
                    logger.debug(f"subfinder stderr: {result.stderr[:500]}")

                progress.update(task, completed=1)

        except FileNotFoundError:
            logger.error(
                "[red][!] subfinder not found.\n"
                "    Install: go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest[/red]"
            )
            results[domain] = []
            continue
        except subprocess.TimeoutExpired:
            logger.warning(f"[yellow]subfinder timed out for {domain}[/yellow]")
            results[domain] = []
            continue
        except KeyboardInterrupt:
            raise

        # Read results
        if out_file.exists():
            subdomains = [
                line.strip()
                for line in out_file.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            results[domain] = subdomains
            logger.info(
                f"[green]Found {len(subdomains)} subdomains for {domain}[/green]"
            )
        else:
            results[domain] = []

    return results