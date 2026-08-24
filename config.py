"""
EvilScan - UltraRecon Framework Configuration
For authorized security testing only.
"""

from pathlib import Path

# Base directory (resolves to wherever the project lives on disk)
BASE_DIR = Path(__file__).parent.resolve()

# Results directories
RESULTS_DIR = BASE_DIR / "results"
LIVE_DIR = RESULTS_DIR / "live"
NMAP_DIR = RESULTS_DIR / "nmap"
NUCLEI_DIR = RESULTS_DIR / "nuclei"
NUCLEI_RAW_DIR = NUCLEI_DIR / "raw"
NUCLEI_JSON_DIR = NUCLEI_DIR / "json"
NIKTO_DIR = RESULTS_DIR / "nikto"
ANALYSIS_DIR = RESULTS_DIR / "analysis"
REPORTS_DIR = RESULTS_DIR / "reports"
LOGS_DIR = RESULTS_DIR / "logs"

ALL_DIRS = [
    LIVE_DIR,
    NMAP_DIR,
    NUCLEI_RAW_DIR,
    NUCLEI_JSON_DIR,
    NIKTO_DIR,
    ANALYSIS_DIR,
    REPORTS_DIR,
    LOGS_DIR,
]

# Output files
LIVE_FILE = LIVE_DIR / "live.txt"
LOG_FILE = LOGS_DIR / "scan.log"
NMAP_SUMMARY = NMAP_DIR / "summary.json"
RANKED_FINDINGS = ANALYSIS_DIR / "ranked_findings.json"
HIGH_PRIORITY = ANALYSIS_DIR / "high_priority.json"
REPORT_MD = REPORTS_DIR / "final_report.md"
REPORT_JSON = REPORTS_DIR / "final_report.json"
REPORT_CSV = REPORTS_DIR / "final_report.csv"

# External tool binaries (must be in $PATH on Kali Linux)
# Kali: sudo apt install nmap nikto
# ProjectDiscovery: go install github.com/projectdiscovery/httpx/cmd/httpx@latest
#                   go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
HTTPX_BIN = "httpx"
NMAP_BIN = "nmap"
NUCLEI_BIN = "nuclei"
NIKTO_BIN = "nikto"

# Scan defaults
DEFAULT_THREADS = 10
NUCLEI_RATE_LIMIT = 300
NUCLEI_CONCURRENCY = 50
NUCLEI_BULK_SIZE = 50
NUCLEI_SEVERITY = "high,critical"
NIKTO_MAXTIME = 120

# Severity scoring
SEVERITY_SCORES = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
    "unknown": 0,
}

CVSS_ESTIMATES = {
    "critical": 9.5,
    "high": 7.5,
    "medium": 5.0,
    "low": 2.5,
    "info": 0.0,
    "unknown": 0.0,
}

DISCLAIMER = (
    "\n[bold red][!] DISCLAIMER:[/bold red] "
    "This tool is for [bold]authorized security testing only[/bold]. "
    "Unauthorized use is illegal and unethical.\n"
)
