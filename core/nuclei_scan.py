"""
Phase 3 – Nuclei vulnerability scanning.

Install on Kali:
    go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
    nuclei -update-templates
"""

import json
import logging
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)

import config
from core.utils import already_scanned, safe_filename

logger = logging.getLogger("evilscan")


def _parse_jsonl(jsonl_file: Path) -> list[dict]:
    """Parse a .jsonl file and return a list of finding dicts."""
    findings = []
    if not jsonl_file.exists():
        return findings
    for line in jsonl_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            findings.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return findings


def _scan_single(domain: str, resume: bool) -> dict:
    """Run nuclei against a single domain."""
    fname = safe_filename(domain)
    raw_file: Path = config.NUCLEI_RAW_DIR / f"{fname}.txt"
    json_file: Path = config.NUCLEI_JSON_DIR / f"{fname}.jsonl"

    if resume and already_scanned(json_file):
        logger.debug(
            f"[yellow]Skipping nuclei for {domain} (already scanned)[/yellow]"
        )
        return {
            "domain": domain,
            "findings": _parse_jsonl(json_file),
            "skipped": True,
        }

    cmd = [
        config.NUCLEI_BIN,
        "-u", domain,
        "-severity", config.NUCLEI_SEVERITY,
        "-rl", str(config.NUCLEI_RATE_LIMIT),
        "-c", str(config.NUCLEI_CONCURRENCY),
        "-bulk-size", str(config.NUCLEI_BULK_SIZE),
        "-ss", "host-spray",
        "-o", str(raw_file),
        "-je", str(json_file),
        "-silent",
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600,
        )
        if result.returncode not in (0, 1):
            logger.warning(
                f"[yellow]nuclei returned {result.returncode} for {domain}[/yellow]"
            )
    except FileNotFoundError:
        logger.error(
            "[red][!] nuclei not found.\n"
            "    Install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest[/red]"
        )
        return {"domain": domain, "error": "nuclei not found", "findings": []}
    except subprocess.TimeoutExpired:
        logger.warning(f"[yellow]nuclei timed out for {domain}[/yellow]")
        return {"domain": domain, "error": "timeout", "findings": []}
    except KeyboardInterrupt:
        raise

    findings = _parse_jsonl(json_file)
    return {
        "domain": domain,
        "findings": findings,
        "raw_file": str(raw_file),
        "json_file": str(json_file),
        "skipped": False,
    }


def run_nuclei(
    domains: list[str],
    threads: int,
    resume: bool,
) -> dict[str, dict]:
    """
    Run nuclei against all domains in parallel.
    Returns a dict keyed by domain with findings.
    """
    logger.info(
        f"[cyan]Phase 3 – Nuclei [{config.NUCLEI_SEVERITY}] | "
        f"{len(domains)} target(s) | {threads} thread(s)[/cyan]"
    )

    results: dict[str, dict] = {}

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[cyan]{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        transient=True,
    ) as progress:
        task = progress.add_task("[cyan]Running nuclei...", total=len(domains))

        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {
                executor.submit(_scan_single, d, resume): d
                for d in domains
            }
            for future in as_completed(futures):
                domain = futures[future]
                try:
                    res = future.result()
                    results[domain] = res
                    count = len(res.get("findings", []))
                    if count:
                        logger.info(
                            f"[bold red]nuclei {domain} – {count} finding(s)[/bold red]"
                        )
                    else:
                        logger.info(
                            f"[green]nuclei {domain} – no findings[/green]"
                        )
                except KeyboardInterrupt:
                    executor.shutdown(wait=False, cancel_futures=True)
                    raise
                except Exception as exc:
                    logger.warning(
                        f"[yellow]nuclei error for {domain}: {exc}[/yellow]"
                    )
                    results[domain] = {
                        "domain": domain,
                        "error": str(exc),
                        "findings": [],
                    }
                finally:
                    progress.advance(task)

    total = sum(len(v.get("findings", [])) for v in results.values())
    logger.info(
        f"[green]Phase 3 complete – {total} nuclei finding(s) across "
        f"{len(domains)} host(s).[/green]"
    )
    return results
