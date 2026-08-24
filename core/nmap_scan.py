"""
Phase 2 – Nmap port scanning.

Install on Kali:
    sudo apt install nmap
"""

import json
import logging
import re
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


def _parse_open_ports(nmap_output: str) -> list[dict]:
    """Extract open port entries from raw nmap text output."""
    ports = []
    for line in nmap_output.splitlines():
        # Matches: 80/tcp   open  http   Apache httpd 2.4.41
        match = re.match(
            r"(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)", line.strip()
        )
        if match:
            ports.append(
                {
                    "port": int(match.group(1)),
                    "protocol": match.group(2),
                    "service": match.group(3),
                    "version": match.group(4).strip(),
                }
            )
    return ports


def _scan_single(domain: str, aggressive: bool, resume: bool) -> dict:
    """Run nmap against a single domain and return a result dict."""
    fname = safe_filename(domain)
    out_file: Path = config.NMAP_DIR / f"{fname}.txt"

    if resume and already_scanned(out_file):
        logger.debug(f"[yellow]Skipping nmap for {domain} (already scanned)[/yellow]")
        raw = out_file.read_text(encoding="utf-8")
        return {
            "domain": domain,
            "output_file": str(out_file),
            "open_ports": _parse_open_ports(raw),
            "skipped": True,
        }

    flags = ["-sVC", "-T4"] if aggressive else ["-F", "-T4"]
    cmd = [config.NMAP_BIN] + flags + [domain]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
        )
        output = result.stdout
        if result.returncode != 0:
            logger.warning(
                f"[yellow]nmap returned {result.returncode} for {domain}[/yellow]"
            )
            output += f"\n[STDERR]\n{result.stderr}"
    except FileNotFoundError:
        logger.error(
            "[red][!] nmap not found. Install: sudo apt install nmap[/red]"
        )
        return {"domain": domain, "error": "nmap not found", "open_ports": []}
    except subprocess.TimeoutExpired:
        logger.warning(f"[yellow]nmap timed out for {domain}[/yellow]")
        return {"domain": domain, "error": "timeout", "open_ports": []}
    except KeyboardInterrupt:
        raise

    out_file.write_text(output, encoding="utf-8")
    open_ports = _parse_open_ports(output)

    return {
        "domain": domain,
        "output_file": str(out_file),
        "open_ports": open_ports,
        "skipped": False,
    }


def run_nmap(
    domains: list[str],
    threads: int,
    aggressive: bool,
    resume: bool,
) -> dict[str, dict]:
    """
    Run nmap against all domains in parallel.
    Returns a dict keyed by domain with scan results.
    Saves per-domain output and a summary.json.
    """
    mode = "aggressive (-sVC)" if aggressive else "fast (-F -T4)"
    logger.info(
        f"[cyan]Phase 2 – Nmap [{mode}] | {len(domains)} target(s) | "
        f"{threads} thread(s)[/cyan]"
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
        task = progress.add_task("[cyan]Running nmap...", total=len(domains))

        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {
                executor.submit(_scan_single, d, aggressive, resume): d
                for d in domains
            }
            for future in as_completed(futures):
                domain = futures[future]
                try:
                    res = future.result()
                    results[domain] = res
                    port_count = len(res.get("open_ports", []))
                    logger.info(
                        f"[green]nmap {domain} – {port_count} open port(s)[/green]"
                    )
                except KeyboardInterrupt:
                    executor.shutdown(wait=False, cancel_futures=True)
                    raise
                except Exception as exc:
                    logger.warning(
                        f"[yellow]nmap error for {domain}: {exc}[/yellow]"
                    )
                    results[domain] = {
                        "domain": domain,
                        "error": str(exc),
                        "open_ports": [],
                    }
                finally:
                    progress.advance(task)

    # Write summary JSON
    summary = {
        domain: {
            "open_ports": data.get("open_ports", []),
            "error": data.get("error"),
        }
        for domain, data in results.items()
    }
    config.NMAP_SUMMARY.write_text(
        json.dumps(summary, indent=2), encoding="utf-8"
    )

    total_ports = sum(len(v.get("open_ports", [])) for v in results.values())
    logger.info(
        f"[green]Phase 2 complete – {total_ports} open port(s) across "
        f"{len(domains)} host(s).[/green]"
    )
    return results
