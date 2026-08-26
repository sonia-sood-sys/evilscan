"""
Main Scanner orchestrator class.
"""

import logging
import signal
import sys

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

import config
from core.analyzer import analyze
from core.dir_enum import enumerate_directories
from core.dns_enum import enumerate_dns
from core.live import detect_live_hosts
from core.nikto_scan import run_nikto
from core.nmap_scan import run_nmap
from core.nuclei_scan import run_nuclei
from core.reporter import generate_reports
from core.subdomain_enum import enumerate_subdomains
from core.tech_detect import detect_technologies
from core.utils import ensure_dirs

logger = logging.getLogger("evilscan")
console = Console()


class Scanner:
    """
    Orchestrates all reconnaissance phases for a list of domains.
    """

    def __init__(
        self,
        domains: list[str],
        threads: int = config.DEFAULT_THREADS,
        fast: bool = True,
        aggressive: bool = False,
        nmap_only: bool = False,
        nuclei_only: bool = False,
        nikto_only: bool = False,
        resume: bool = False,
        profile: str = None,
        subdomain_enum: bool = False,
        dns_enum: bool = False,
        tech_detect: bool = False,
        dir_enum: bool = False,
        nuclei_severity: str = None,
        wordlist: str = None,
    ) -> None:
        self.domains = domains
        self.threads = threads
        self.fast = fast
        self.aggressive = aggressive
        self.nmap_only = nmap_only
        self.nuclei_only = nuclei_only
        self.nikto_only = nikto_only
        self.resume = resume
        self.profile = profile
        self.subdomain_enum = subdomain_enum
        self.dns_enum = dns_enum
        self.tech_detect = tech_detect
        self.dir_enum = dir_enum
        self.nuclei_severity = nuclei_severity or config.NUCLEI_SEVERITY
        self.wordlist = wordlist

        # Apply scan profile if specified
        if profile and profile in config.SCAN_PROFILES:
            self._apply_profile(profile)

        self.live_hosts: list[str] = []
        self.nmap_results: dict = {}
        self.nuclei_results: dict = {}
        self.nikto_results: dict = {}
        self.subdomain_results: dict = {}
        self.dns_results: dict = {}
        self.tech_results: dict = {}
        self.dir_results: dict = {}
        self.analysis_summary: dict = {}

        self._setup_signal_handler()

    def _setup_signal_handler(self) -> None:
        """Register graceful SIGINT (Ctrl+C) handler."""
        def _handler(sig, frame):
            console.print(
                "\n[bold yellow][!] Scan interrupted (Ctrl+C). "
                "Partial results have been saved.[/bold yellow]"
            )
            sys.exit(0)

        signal.signal(signal.SIGINT, _handler)

    def _apply_profile(self, profile: str) -> None:
        """Apply scan profile settings."""
        profile_config = config.SCAN_PROFILES[profile]
        console.print(
            f"[bold cyan]Applying profile:[/bold cyan] [white]{profile}[/white] - "
            f"[yellow]{profile_config['description']}[/yellow]"
        )

        # Apply profile settings
        self.nmap_mode = profile_config.get("nmap_mode", "fast")
        self.aggressive = (self.nmap_mode == "aggressive")
        self.fast = (self.nmap_mode == "fast")

        self.nuclei_severity = profile_config.get("nuclei_severity", config.NUCLEI_SEVERITY)
        self.nikto_enabled = profile_config.get("nikto_enabled", True)
        self.subdomain_enum = profile_config.get("subdomain_enum", False)
        self.dns_enum = profile_config.get("dns_enum", False)
        self.tech_detect = profile_config.get("tech_detect", False)
        self.dir_enum = profile_config.get("dir_enum", False)

        # Set scan phases based on profile
        phases = profile_config.get("phases", [])
        self.use_nmap = "nmap" in phases
        self.use_nuclei = "nuclei" in phases
        self.use_nikto = "nikto" in phases

    def _banner(self) -> None:
        text = Text()
        text.append(
            "  ███████╗██╗   ██╗██╗██╗     ███████╗ ██████╗ █████╗ ███╗   ██╗\n",
            style="bold red",
        )
        text.append(
            "  ██╔════╝██║   ██║██║██║     ██╔════╝██╔════╝██╔══██╗████╗  ██║\n",
            style="bold red",
        )
        text.append(
            "  █████╗  ██║   ██║██║██║     ███████╗██║     ███████║██╔██╗ ██║\n",
            style="bold yellow",
        )
        text.append(
            "  ██╔══╝  ╚██╗ ██╔╝██║██║     ╚════██║██║     ██╔══██║██║╚██╗██║\n",
            style="bold yellow",
        )
        text.append(
            "  ███████╗ ╚████╔╝ ██║███████╗███████║╚██████╗██║  ██║██║ ╚████║\n",
            style="bold green",
        )
        text.append(
            "  ╚══════╝  ╚═══╝  ╚═╝╚══════╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝\n",
            style="bold green",
        )
        text.append(
            "\n  UltraRecon Framework  |  v1.0.0  |  Bug Bounty Edition\n",
            style="bold cyan",
        )
        text.append(
            "  [!] For authorized security testing only.\n",
            style="bold red",
        )
        console.print(Panel(text, border_style="bold blue", padding=(0, 2)))

    def _phase_header(self, phase: str, description: str) -> None:
        console.rule(
            f"[bold cyan]{phase}[/bold cyan] [white]{description}[/white]"
        )

    def run(self) -> None:
        """Execute the full reconnaissance pipeline."""
        ensure_dirs()
        self._banner()

        mode = "aggressive (-sVC)" if self.aggressive else "fast (-F -T4)"
        profile_info = f"Profile: {self.profile}" if self.profile else "Custom mode"
        console.print(
            f"[bold white]Targets:[/bold white] [cyan]{len(self.domains)}[/cyan]  "
            f"[bold white]Threads:[/bold white] [cyan]{self.threads}[/cyan]  "
            f"[bold white]Mode:[/bold white] [cyan]{mode}[/cyan]  "
            f"[bold white]Resume:[/bold white] [cyan]{self.resume}[/cyan]  "
            f"[bold white]{profile_info}[/white]\n"
        )

        only_mode = self.nmap_only or self.nuclei_only or self.nikto_only

        # Determine which phases to run
        use_nmap = getattr(self, 'use_nmap', True) and not self.nuclei_only and not self.nikto_only
        use_nuclei = getattr(self, 'use_nuclei', True) and not self.nmap_only and not self.nikto_only
        use_nikto = getattr(self, 'use_nikto', True) and not self.nmap_only and not self.nuclei_only

        # ── Phase 0: Subdomain Enumeration ────────────────────────────────────
        if self.subdomain_enum:
            self._phase_header("Phase 0", "Subdomain Enumeration")
            try:
                self.subdomain_results = enumerate_subdomains(
                    self.domains, self.resume
                )
                # Collect all discovered subdomains
                all_subdomains = []
                for domain, subs in self.subdomain_results.items():
                    all_subdomains.extend(subs)
                if all_subdomains:
                    console.print(f"[green]Found {len(all_subdomains)} subdomains total[/green]")
                    self.domains = list(set(self.domains + all_subdomains))
            except Exception as exc:
                console.print(f"[yellow]Subdomain enumeration failed: {exc}[/yellow]")
                logger.warning(f"Subdomain enumeration error: {exc}")

        # ── Phase 1: Live Detection ──────────────────────────────────────────
        if not only_mode:
            self._phase_header("Phase 1", "Live Host Detection")
            self.live_hosts = detect_live_hosts(
                self.domains, self.threads, self.resume
            )
            scan_targets = self.live_hosts if self.live_hosts else self.domains
        else:
            scan_targets = self.domains
            self.live_hosts = self.domains

        if not scan_targets:
            console.print("[bold red][!] No live hosts found. Exiting.[/bold red]")
            return

        # ── Phase 1.5: DNS Enumeration ────────────────────────────────────────
        if self.dns_enum:
            self._phase_header("Phase 1.5", "DNS Enumeration")
            try:
                self.dns_results = enumerate_dns(
                    scan_targets, self.resume
                )
            except Exception as exc:
                console.print(f"[yellow]DNS enumeration failed: {exc}[/yellow]")
                logger.warning(f"DNS enumeration error: {exc}")

        # ── Phase 2: Nmap ────────────────────────────────────────────────────
        if use_nmap:
            self._phase_header("Phase 2", "Nmap Port Scanning")
            self.nmap_results = run_nmap(
                scan_targets,
                threads=self.threads,
                aggressive=self.aggressive,
                resume=self.resume,
            )

        # ── Phase 2.5: Technology Detection ───────────────────────────────────
        if self.tech_detect:
            self._phase_header("Phase 2.5", "Technology Detection")
            try:
                self.tech_results = detect_technologies(
                    scan_targets, self.resume
                )
            except Exception as exc:
                console.print(f"[yellow]Technology detection failed: {exc}[/yellow]")
                logger.warning(f"Technology detection error: {exc}")

        # ── Phase 3: Nuclei ──────────────────────────────────────────────────
        if use_nuclei:
            self._phase_header("Phase 3", "Nuclei Vulnerability Scanning")
            self.nuclei_results = run_nuclei(
                scan_targets,
                threads=self.threads,
                resume=self.resume,
                severity=self.nuclei_severity,
            )

        # ── Phase 3.5: Directory Enumeration ─────────────────────────────────
        if self.dir_enum:
            self._phase_header("Phase 3.5", "Directory Enumeration")
            try:
                self.dir_results = enumerate_directories(
                    scan_targets, self.resume, self.wordlist
                )
            except Exception as exc:
                console.print(f"[yellow]Directory enumeration failed: {exc}[/yellow]")
                logger.warning(f"Directory enumeration error: {exc}")

        # ── Phase 4: Nikto ───────────────────────────────────────────────────
        if use_nikto:
            self._phase_header("Phase 4", "Nikto Web Scanning")
            self.nikto_results = run_nikto(
                scan_targets,
                threads=self.threads,
                resume=self.resume,
            )

        # ── Analysis ─────────────────────────────────────────────────────────
        console.rule("[bold magenta]Analysis[/bold magenta]")
        self.analysis_summary = analyze(self.nuclei_results, self.nikto_results)

        # ── Reports ──────────────────────────────────────────────────────────
        console.rule("[bold magenta]Report Generation[/bold magenta]")
        generate_reports(
            domains=self.domains,
            live_hosts=self.live_hosts,
            nmap_results=self.nmap_results,
            nuclei_results=self.nuclei_results,
            nikto_results=self.nikto_results,
            analysis_summary=self.analysis_summary,
            subdomain_results=self.subdomain_results,
            dns_results=self.dns_results,
            tech_results=self.tech_results,
            dir_results=self.dir_results,
        )

        self._print_summary()

    def _print_summary(self) -> None:
        """Print a final summary table to the console."""
        table = Table(
            title="[bold green]Scan Complete – Summary[/bold green]",
            border_style="green",
            show_header=True,
            header_style="bold cyan",
        )
        table.add_column("Metric", style="bold white", min_width=25)
        table.add_column("Value", style="cyan")

        table.add_row("Total Targets", str(len(self.domains)))
        table.add_row("Live Hosts", str(len(self.live_hosts)))
        table.add_row(
            "Total Findings",
            str(self.analysis_summary.get("total_findings", 0)),
        )
        table.add_row(
            "High / Critical",
            str(self.analysis_summary.get("high_priority_count", 0)),
        )

        # New results
        if self.subdomain_results:
            total_subs = sum(len(subs) for subs in self.subdomain_results.values())
            table.add_row("Subdomains Found", str(total_subs))

        if self.dns_results:
            total_dns = sum(len(data.get("records", [])) for data in self.dns_results.values())
            table.add_row("DNS Records", str(total_dns))

        if self.tech_results:
            total_tech = sum(data.get("tech_count", 0) for data in self.tech_results.values())
            table.add_row("Technologies Detected", str(total_tech))

        if self.dir_results:
            total_dirs = sum(data.get("directory_count", 0) for data in self.dir_results.values())
            table.add_row("Directories Found", str(total_dirs))

        sev = self.analysis_summary.get("severity_breakdown", {})
        for s in ("critical", "high", "medium", "low", "info"):
            if sev.get(s):
                table.add_row(f"  {s.capitalize()}", str(sev[s]))

        table.add_row("Report (Markdown)", str(config.REPORT_MD))
        table.add_row("Report (JSON)", str(config.REPORT_JSON))
        table.add_row("Report (CSV)", str(config.REPORT_CSV))
        table.add_row("Log File", str(config.LOG_FILE))

        console.print()
        console.print(table)
        console.print(
            "\n[bold red][!] Remember:[/bold red] Use this tool only on targets "
            "you have [bold]explicit written permission[/bold] to test.\n"
        )
