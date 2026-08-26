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
SUBDOMAIN_DIR = RESULTS_DIR / "subdomains"
DNS_DIR = RESULTS_DIR / "dns"
TECH_DIR = RESULTS_DIR / "tech"
SSL_DIR = RESULTS_DIR / "ssl"
DIRS_DIR = RESULTS_DIR / "directories"

ALL_DIRS = [
    LIVE_DIR,
    NMAP_DIR,
    NUCLEI_RAW_DIR,
    NUCLEI_JSON_DIR,
    NIKTO_DIR,
    ANALYSIS_DIR,
    REPORTS_DIR,
    LOGS_DIR,
    SUBDOMAIN_DIR,
    DNS_DIR,
    TECH_DIR,
    SSL_DIR,
    DIRS_DIR,
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
REPORT_HTML = REPORTS_DIR / "final_report.html"
SUBDOMAIN_FILE = SUBDOMAIN_DIR / "subdomains.txt"
DNS_FILE = DNS_DIR / "dns.json"
TECH_FILE = TECH_DIR / "tech.json"
SSL_FILE = SSL_DIR / "ssl.json"
DIRS_FILE = DIRS_DIR / "directories.json"

# External tool binaries (must be in $PATH on Kali Linux)
# Kali: sudo apt install nmap nikto
# ProjectDiscovery: go install github.com/projectdiscovery/httpx/cmd/httpx@latest
#                   go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
#                   go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
#                   go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
# Subdomain enumeration: go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
# DNS enumeration: go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
# Technology detection: go install github.com/projectdiscovery/wappalyzergo/cmd/wappalyzergo@latest
# Directory enumeration: go install github.com/ffuf/ffuf/v2/cmd/ffuf@latest
HTTPX_BIN = "httpx"
NMAP_BIN = "nmap"
NUCLEI_BIN = "nuclei"
NIKTO_BIN = "nikto"
SUBFINDER_BIN = "subfinder"
DNSX_BIN = "dnsx"
WAPPALYZER_BIN = "wappalyzergo"
FFUF_BIN = "ffuf"

# Scan defaults
DEFAULT_THREADS = 10
NUCLEI_RATE_LIMIT = 300
NUCLEI_CONCURRENCY = 50
NUCLEI_BULK_SIZE = 50
NUCLEI_SEVERITY = "high,critical"
NIKTO_MAXTIME = 120

# Subdomain enumeration settings
SUBFINDER_TIMEOUT = 300
SUBFINDER_ALL_SOURCES = True

# DNS enumeration settings
DNSX_TIMEOUT = 60
DNSX_RESOLVERS = "8.8.8.8,1.1.1.1"

# Technology detection settings
WAPPALYZER_TIMEOUT = 60

# Directory enumeration settings
FFUF_TIMEOUT = 300
FFUF_WORDLIST = "/usr/share/wordlists/dirb/common.txt"
FFUF_THREADS = 20
FFUF_EXTENSIONS = "php,html,js,txt,asp,aspx,jsp"
FFUF_MAX_TIME = 120

# Custom wordlist (can be overridden via CLI)
CUSTOM_WORDLIST = None

# Scan profiles
SCAN_PROFILES = {
    "quick": {
        "description": "Fast reconnaissance - minimal scanning",
        "phases": ["live", "nmap"],
        "nmap_mode": "fast",
        "nuclei_severity": "critical",
        "nikto_enabled": False,
        "subdomain_enum": False,
        "dns_enum": False,
        "tech_detect": False,
        "dir_enum": False,
    },
    "comprehensive": {
        "description": "Full reconnaissance - all phases",
        "phases": ["live", "nmap", "nuclei", "nikto"],
        "nmap_mode": "aggressive",
        "nuclei_severity": "medium,high,critical",
        "nikto_enabled": True,
        "subdomain_enum": True,
        "dns_enum": True,
        "tech_detect": True,
        "dir_enum": True,
    },
    "stealth": {
        "description": "Stealthy scanning - lower profile",
        "phases": ["live", "nmap", "nuclei"],
        "nmap_mode": "fast",
        "nuclei_severity": "critical,high",
        "nikto_enabled": False,
        "subdomain_enum": False,
        "dns_enum": True,
        "tech_detect": True,
        "dir_enum": False,
    },
    "bugbounty": {
        "description": "Bug bounty focused - web application focus",
        "phases": ["live", "nuclei", "nikto"],
        "nmap_mode": "fast",
        "nuclei_severity": "low,medium,high,critical",
        "nikto_enabled": True,
        "subdomain_enum": True,
        "dns_enum": True,
        "tech_detect": True,
        "dir_enum": True,
    },
}

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
