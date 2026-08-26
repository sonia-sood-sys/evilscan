"""
Directory enumeration using ffuf.

Install on Kali:
    go install github.com/ffuf/ffuf/v2/cmd/ffuf@latest
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
from core.utils import already_scanned, safe_filename

logger = logging.getLogger("evilscan")


def enumerate_directories(domains: list[str], resume: bool, wordlist: str = None) -> dict[str, dict]:
    """
    Run ffuf against all domains and return discovered directories.
    Returns a dict keyed by domain with directory enumeration results.
    """
    results: dict[str, dict] = {}

    for domain in domains:
        fname = safe_filename(domain)
        out_file: Path = config.DIRS_DIR / f"{fname}.json"

        if resume and already_scanned(out_file):
            logger.info(f"[yellow]Resuming – loading existing directory data for {domain}[/yellow]")
            try:
                dir_data = json.loads(out_file.read_text(encoding="utf-8"))
                results[domain] = dir_data
                logger.info(f"[green]Directory data loaded for {domain}[/green]")
            except json.JSONDecodeError:
                logger.warning(f"[yellow]Invalid directory data for {domain}, rescanning[/yellow]")
                results[domain] = _run_dir_scan(domain, out_file, wordlist)
            continue

        results[domain] = _run_dir_scan(domain, out_file, wordlist)

    return results


def _run_dir_scan(domain: str, out_file: Path, wordlist: str = None) -> dict:
    """Run ffuf against a single domain."""
    logger.info(f"[cyan]Enumerating directories for {domain} using ffuf[/cyan]")

    # Ensure domain has a scheme
    target = domain if domain.startswith("http") else f"https://{domain}"

    # Use custom wordlist if provided, otherwise use default
    wordlist_path = wordlist or config.FFUF_WORDLIST

    cmd = [
        config.FFUF_BIN,
        "-u", f"{target}/FUZZ",
        "-w", wordlist_path,
        "-e", config.FFUF_EXTENSIONS,
        "-t", str(config.FFUF_THREADS),
        "-maxtime", str(config.FFUF_MAX_TIME),
        "-json",
        "-o", str(out_file),
        "-s",  # Silent mode
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
                f"[cyan]Enumerating directories for {domain}..."
            )

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=config.FFUF_TIMEOUT,
            )

            if result.returncode not in (0, 1):
                logger.warning(
                    f"[yellow]ffuf returned {result.returncode} for {domain}[/yellow]"
                )
            if result.stderr:
                logger.debug(f"ffuf stderr: {result.stderr[:500]}")

            progress.update(task, completed=1)

    except FileNotFoundError:
        logger.error(
            "[red][!] ffuf not found.\n"
            "    Install: go install github.com/ffuf/ffuf/v2/cmd/ffuf@latest[/red]"
        )
        return {"domain": domain, "error": "ffuf not found", "directories": []}
    except subprocess.TimeoutExpired:
        logger.warning(f"[yellow]ffuf timed out for {domain}[/yellow]")
        return {"domain": domain, "error": "timeout", "directories": []}
    except KeyboardInterrupt:
        raise

    # Parse results
    if out_file.exists():
        try:
            directories = []
            for line in out_file.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    result = json.loads(line)
                    if result.get("status") not in [404, 429]:  # Filter out 404s and rate limits
                        directories.append({
                            "path": result.get("result", {}).get("path", ""),
                            "status": result.get("status", 0),
                            "size": result.get("result", {}).get("words", 0),
                            "time": result.get("result", {}).get("duration", 0),
                        })
                except json.JSONDecodeError:
                    pass

            return {
                "domain": domain,
                "directories": directories,
                "directory_count": len(directories),
            }
        except Exception as exc:
            logger.warning(f"[yellow]Error parsing directory data for {domain}: {exc}[/yellow]")
            return {"domain": domain, "error": str(exc), "directories": []}
    else:
        return {"domain": domain, "directories": [], "directory_count": 0}