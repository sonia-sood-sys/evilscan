#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
EvilScan – UltraRecon Framework
Main CLI entry point.

DISCLAIMER: For authorized security testing only.
Unauthorized use is illegal and unethical.

Usage:
    python3 ultrarecon.py -t targets.txt [OPTIONS]
"""

import argparse
import sys

from rich.console import Console

import config
from core.scanner import Scanner
from core.utils import load_targets, setup_logging

console = Console()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ultrarecon",
        description=(
            "EvilScan UltraRecon - Modular Reconnaissance Framework\n"
            "[!] For authorized security testing only."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 ultrarecon.py -t targets.txt\n"
            "  python3 ultrarecon.py -t targets.txt --fast --threads 20\n"
            "  python3 ultrarecon.py -t targets.txt --nmap-only --aggressive\n"
            "  python3 ultrarecon.py -t targets.txt --nuclei-only\n"
            "  python3 ultrarecon.py -t targets.txt --nikto-only\n"
            "  python3 ultrarecon.py -t targets.txt --resume\n"
        ),
    )

    parser.add_argument(
        "-t", "--targets",
        metavar="FILE",
        required=True,
        help="Path to TXT file containing target domains (one per line)",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=config.DEFAULT_THREADS,
        metavar="N",
        help=f"Number of parallel threads (default: {config.DEFAULT_THREADS})",
    )
    parser.add_argument(
        "--fast",
        action="store_true",
        default=True,
        help="Fast nmap scan mode: -F -T4 (default)",
    )
    parser.add_argument(
        "--aggressive",
        action="store_true",
        default=False,
        help="Aggressive nmap scan mode: -sVC (overrides --fast)",
    )
    parser.add_argument(
        "--nmap-only",
        action="store_true",
        default=False,
        help="Run nmap phase only (skips live detection, nuclei, nikto)",
    )
    parser.add_argument(
        "--nuclei-only",
        action="store_true",
        default=False,
        help="Run nuclei phase only",
    )
    parser.add_argument(
        "--nikto-only",
        action="store_true",
        default=False,
        help="Run nikto phase only",
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        default=False,
        help="Resume previous scan – skip already scanned domains",
    )
    parser.add_argument(
        "--profile",
        choices=["quick", "comprehensive", "stealth", "bugbounty"],
        help="Use predefined scan profile (overrides individual flags)",
    )
    parser.add_argument(
        "--subdomain-enum",
        action="store_true",
        default=False,
        help="Enable subdomain enumeration using subfinder",
    )
    parser.add_argument(
        "--dns-enum",
        action="store_true",
        default=False,
        help="Enable DNS enumeration using dnsx",
    )
    parser.add_argument(
        "--tech-detect",
        action="store_true",
        default=False,
        help="Enable technology detection using wappalyzer",
    )
    parser.add_argument(
        "--dir-enum",
        action="store_true",
        default=False,
        help="Enable directory enumeration using ffuf",
    )
    parser.add_argument(
        "--nuclei-severity",
        type=str,
        default=None,
        help="Nuclei severity levels (e.g., 'critical,high', 'medium,high,critical')",
    )
    parser.add_argument(
        "--wordlist",
        type=str,
        default=None,
        help="Custom wordlist for directory enumeration",
    )

    return parser


def validate_args(args: argparse.Namespace) -> None:
    """Validate mutually exclusive flags and thread count."""
    exclusive = [args.nmap_only, args.nuclei_only, args.nikto_only]
    if sum(exclusive) > 1:
        console.print(
            "[bold red][!] Only one of --nmap-only, --nuclei-only, --nikto-only "
            "can be used at a time.[/bold red]"
        )
        sys.exit(1)

    if args.threads < 1 or args.threads > 200:
        console.print(
            "[bold red][!] --threads must be between 1 and 200.[/bold red]"
        )
        sys.exit(1)

    # Validate nuclei severity
    if args.nuclei_severity:
        valid_severities = ["critical", "high", "medium", "low", "info"]
        for sev in args.nuclei_severity.split(","):
            sev = sev.strip().lower()
            if sev not in valid_severities:
                console.print(
                    f"[bold red][!] Invalid severity '{sev}'. Valid: {', '.join(valid_severities)}[/bold red]"
                )
                sys.exit(1)


def _confirm_authorization() -> None:
    """Ask user to confirm they have authorization before scanning."""
    console.print(config.DISCLAIMER)
    console.print(
        "[bold yellow][?] Do you have explicit written authorization "
        "to scan these targets? (yes/no):[/bold yellow]"
    )
    try:
        answer = input("    > ").strip().lower()
    except (KeyboardInterrupt, EOFError):
        console.print("\n[yellow]Exiting.[/yellow]")
        sys.exit(0)

    if answer not in ("yes", "y"):
        console.print(
            "[bold red][!] Authorization not confirmed. Aborting.[/bold red]"
        )
        sys.exit(1)


def main() -> None:
    logger = setup_logging()

    # Interactive mode when called with no arguments
    if len(sys.argv) == 1:
        console.print(
            "\n[bold cyan]╔══════════════════════════════════════════╗[/bold cyan]"
        )
        console.print(
            "[bold cyan]║    EvilScan – UltraRecon Framework       ║[/bold cyan]"
        )
        console.print(
            "[bold cyan]╚══════════════════════════════════════════╝[/bold cyan]\n"
        )
        console.print(
            "[bold]Usage:[/bold] "
            "[cyan]python3 ultrarecon.py -t <targets.txt> [OPTIONS][/cyan]\n"
        )
        console.print(
            "[bold]Enter the path to your targets file to begin "
            "(Ctrl+C to exit):[/bold]"
        )
        try:
            target_path = input("    Targets file > ").strip()
        except (KeyboardInterrupt, EOFError):
            console.print("\n[yellow]Exiting.[/yellow]")
            sys.exit(0)

        if not target_path:
            console.print("[bold red][!] No path provided. Exiting.[/bold red]")
            sys.exit(1)

        sys.argv.extend(["-t", target_path])

    parser = build_parser()
    args = parser.parse_args()
    validate_args(args)

    _confirm_authorization()

    domains = load_targets(args.targets)
    logger.info(
        f"[bold green]Loaded {len(domains)} unique target(s) from {args.targets}[/bold green]"
    )

    scanner = Scanner(
        domains=domains,
        threads=args.threads,
        fast=args.fast,
        aggressive=args.aggressive,
        nmap_only=args.nmap_only,
        nuclei_only=args.nuclei_only,
        nikto_only=args.nikto_only,
        resume=args.resume,
        profile=args.profile,
        subdomain_enum=args.subdomain_enum,
        dns_enum=args.dns_enum,
        tech_detect=args.tech_detect,
        dir_enum=args.dir_enum,
        nuclei_severity=args.nuclei_severity,
        wordlist=args.wordlist,
    )

    scanner.run()


if __name__ == "__main__":
    main()
