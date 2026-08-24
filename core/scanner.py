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
from core.live import detect_live_hosts
from core.nikto_scan import run_nikto
from core.nmap_scan import run_nmap
from core.nuclei_scan import run_nuclei
from core.reporter import generate_reports
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
    ) -> None:
        self.domains = domains
        self.threads = threads
        self.fast = fast
        self.aggressive = aggressive
        self.nmap_only = nmap_only
        self.nuclei_only = nuclei_only
        self.nikto_only = nikto_only
        self.resume = resume

        self.live_hosts: list[str] = []
        self.nmap_results: dict = {}
        self.nuclei_results: dict = {}
        self.nikto_results: dict = {}
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
        console.print(
            f"[bold white]Targets:[/bold white] [cyan]{len(self.domains)}[/cyan]  "
            f"[bold white]Threads:[/bold white] [cyan]{self.threads}[/cyan]  "
            f"[bold white]Mode:[/bold white] [cyan]{mode}[/cyan]  "
            f"[bold white]Resume:[/bold white] [cyan]{self.resume}[/cyan]\n"
        )

        only_mode = self.nmap_only or self.nuclei_only or self.nikto_only

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

        # ── Phase 2: Nmap ────────────────────────────────────────────────────
        if not self.nuclei_only and not self.nikto_only:
            self._phase_header("Phase 2", "Nmap Port Scanning")
            self.nmap_results = run_nmap(
                scan_targets,
                threads=self.threads,
                aggressive=self.aggressive,
                resume=self.resume,
            )

        # ── Phase 3: Nuclei ──────────────────────────────────────────────────
        if not self.nmap_only and not self.nikto_only:
            self._phase_header("Phase 3", "Nuclei Vulnerability Scanning")
            self.nuclei_results = run_nuclei(
                scan_targets,
                threads=self.threads,
                resume=self.resume,
            )

        # ── Phase 4: Nikto ───────────────────────────────────────────────────
        if not self.nmap_only and not self.nuclei_only:
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
