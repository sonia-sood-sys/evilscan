"""
Phase 1 – Live host detection using httpx.

Install on Kali:
    go install github.com/projectdiscovery/httpx/cmd/httpx@latest
    # or: sudo apt install golang && go install ...
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
)

import config
from core.utils import already_scanned

logger = logging.getLogger("evilscan")


def detect_live_hosts(domains: list[str], threads: int, resume: bool) -> list[str]:
    """
    Run httpx against all domains and return the list of live hosts.
    Domains are piped via stdin; results saved to config.LIVE_FILE.
    """
    live_file: Path = config.LIVE_FILE

    if resume and already_scanned(live_file):
        logger.info("[yellow]Resuming – loading existing live hosts.[/yellow]")
        live = [
            line.strip()
            for line in live_file.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        logger.info(f"[green]{len(live)} live hosts loaded from cache.[/green]")
        return live

    logger.info(
        f"[cyan]Phase 1 – Probing {len(domains)} target(s) with httpx[/cyan]"
    )

    domain_input = "\n".join(domains)

    cmd = [
        config.HTTPX_BIN,
        "-silent",
        "-threads", str(threads),
        "-o", str(live_file),
    ]

    live: list[str] = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[cyan]{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        transient=True,
    ) as progress:
        task = progress.add_task(
            "[cyan]Probing live hosts...", total=len(domains)
        )

        try:
            proc = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            stdout, stderr = proc.communicate(input=domain_input, timeout=600)

            if proc.returncode not in (0, 1):
                logger.warning(
                    f"[yellow]httpx exited with code {proc.returncode}[/yellow]"
                )
            if stderr:
                logger.debug(f"httpx stderr: {stderr[:500]}")

        except FileNotFoundError:
            logger.error(
                "[red][!] httpx not found.\n"
                "    Install: go install github.com/projectdiscovery/httpx/cmd/httpx@latest[/red]"
            )
            progress.update(task, completed=len(domains))
            return []
        except subprocess.TimeoutExpired:
            logger.error("[red][!] httpx timed out.[/red]")
            proc.kill()
            progress.update(task, completed=len(domains))
            return []
        except KeyboardInterrupt:
            proc.terminate()
            raise

        progress.update(task, completed=len(domains))

    if live_file.exists():
        live = [
            line.strip()
            for line in live_file.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    logger.info(
        f"[green]Phase 1 complete – {len(live)} live host(s) found.[/green]"
    )
    return live
