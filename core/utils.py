"""
Utility helpers – input parsing, domain normalization, logging setup.
"""

import logging
import re
import sys
from pathlib import Path

from rich.console import Console
from rich.logging import RichHandler

import config

console = Console()


def setup_logging() -> logging.Logger:
    """Configure root logger with file + rich console handlers."""
    config.LOGS_DIR.mkdir(parents=True, exist_ok=True)

    log_format = "%(asctime)s | %(levelname)-8s | %(message)s"
    date_fmt = "%Y-%m-%d %H:%M:%S"

    file_handler = logging.FileHandler(config.LOG_FILE, encoding="utf-8")
    file_handler.setFormatter(logging.Formatter(log_format, datefmt=date_fmt))

    rich_handler = RichHandler(
        console=console,
        show_time=False,
        show_path=False,
        markup=True,
    )

    logging.basicConfig(
        level=logging.INFO,
        handlers=[file_handler, rich_handler],
    )
    return logging.getLogger("evilscan")


def normalize_domain(raw: str) -> str:
    """Strip protocol, trailing slashes, and whitespace from a domain string."""
    domain = raw.strip()
    domain = re.sub(r"^https?://", "", domain, flags=re.IGNORECASE)
    domain = domain.rstrip("/")
    return domain.lower()


def load_targets(filepath: str) -> list[str]:
    """
    Load, normalize, deduplicate, and validate domains from a TXT file.
    Returns a sorted list of unique domain strings.
    """
    path = Path(filepath)
    if not path.exists():
        console.print(
            f"[bold red][!] Target file not found:[/bold red] {filepath}"
        )
        sys.exit(1)
    if not path.is_file():
        console.print(
            f"[bold red][!] Path is not a file:[/bold red] {filepath}"
        )
        sys.exit(1)

    raw_lines = path.read_text(encoding="utf-8").splitlines()
    domains: list[str] = []
    seen: set[str] = set()

    for line in raw_lines:
        domain = normalize_domain(line)
        if not domain:
            continue
        if domain in seen:
            continue
        seen.add(domain)
        domains.append(domain)

    if not domains:
        console.print(
            "[bold red][!] No valid targets found in file.[/bold red]"
        )
        sys.exit(1)

    return domains


def safe_filename(domain: str) -> str:
    """Convert a domain to a filesystem-safe filename stem."""
    return re.sub(r"[^\w\-.]", "_", domain)


def ensure_dirs() -> None:
    """Create all required output directories."""
    for d in config.ALL_DIRS:
        d.mkdir(parents=True, exist_ok=True)


def already_scanned(output_file: Path) -> bool:
    """Return True if output file exists and is non-empty."""
    return output_file.exists() and output_file.stat().st_size > 0
