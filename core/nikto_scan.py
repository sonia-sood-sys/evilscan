"""
Phase 4 – Nikto web server scanning.

Install on Kali:
    sudo apt install nikto
"""

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

INTERESTING_KEYWORDS = [
    "OSVDB", "CVE", "vulnerable", "outdated", "default",
    "admin", "login", "password", "backup", "config",
    "phpinfo", "debug", "test", "shell", "upload",
    "directory indexing", "XSS", "SQL", "injection",
    "disclosure", "exposed", "insecure", "misconfiguration",
]


def _extract_interesting(text: str) -> list[str]:
    """Return lines from nikto output that contain interesting keywords."""
    hits = []
    for line in text.splitlines():
        lower = line.lower()
        if any(kw.lower() in lower for kw in INTERESTING_KEYWORDS):
            hits.append(line.strip())
    return hits


def _scan_single(domain: str, resume: bool) -> dict:
    """Run nikto against a single domain."""
    fname = safe_filename(domain)
    out_file: Path = config.NIKTO_DIR / f"{fname}.txt"

    if resume and already_scanned(out_file):
        logger.debug(
            f"[yellow]Skipping nikto for {domain} (already scanned)[/yellow]"
        )
        raw = out_file.read_text(encoding="utf-8")
        return {
            "domain": domain,
            "interesting": _extract_interesting(raw),
            "skipped": True,
        }

    # Ensure domain has a scheme for nikto
    target = domain if domain.startswith("http") else f"http://{domain}"

    cmd = [
        config.NIKTO_BIN,
        "-h", target,
        "-maxtime", str(config.NIKTO_MAXTIME),
        "-nointeractive",
        "-output", str(out_file),
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=config.NIKTO_MAXTIME + 30,
        )
        output = result.stdout
        if result.returncode not in (0, 1):
            logger.warning(
                f"[yellow]nikto returned {result.returncode} for {domain}[/yellow]"
            )
    except FileNotFoundError:
        logger.error(
            "[red][!] nikto not found. Install: sudo apt install nikto[/red]"
        )
        return {"domain": domain, "error": "nikto not found", "interesting": []}
    except subprocess.TimeoutExpired:
        logger.warning(f"[yellow]nikto timed out for {domain}[/yellow]")
        return {"domain": domain, "error": "timeout", "interesting": []}
    except KeyboardInterrupt:
        raise

    # nikto writes its own output file; fall back to stdout if needed
    if not out_file.exists() or out_file.stat().st_size == 0:
        out_file.write_text(output, encoding="utf-8")

    raw = out_file.read_text(encoding="utf-8") if out_file.exists() else output
    interesting = _extract_interesting(raw)

    return {
        "domain": domain,
        "output_file": str(out_file),
        "interesting": interesting,
        "skipped": False,
    }


def run_nikto(
    domains: list[str],
    threads: int,
    resume: bool,
) -> dict[str, dict]:
    """
    Run nikto against all domains in parallel.
    Returns a dict keyed by domain with results.
    """
    logger.info(
        f"[cyan]Phase 4 – Nikto [maxtime={config.NIKTO_MAXTIME}s] | "
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
        task = progress.add_task("[cyan]Running nikto...", total=len(domains))

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
                    count = len(res.get("interesting", []))
                    if count:
                        logger.info(
                            f"[yellow]nikto {domain} – {count} interesting finding(s)[/yellow]"
                        )
                    else:
                        logger.info(
                            f"[green]nikto {domain} – nothing notable[/green]"
                        )
                except KeyboardInterrupt:
                    executor.shutdown(wait=False, cancel_futures=True)
                    raise
                except Exception as exc:
                    logger.warning(
                        f"[yellow]nikto error for {domain}: {exc}[/yellow]"
                    )
                    results[domain] = {
                        "domain": domain,
                        "error": str(exc),
                        "interesting": [],
                    }
                finally:
                    progress.advance(task)

    total = sum(len(v.get("interesting", [])) for v in results.values())
    logger.info(
        f"[green]Phase 4 complete – {total} interesting nikto finding(s) across "
        f"{len(domains)} host(s).[/green]"
    )
    return results
