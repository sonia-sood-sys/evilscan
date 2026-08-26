# EvilScan – UltraRecon Framework

> **[!] For authorized security testing only. Unauthorized use is illegal.**

Advanced modular Python reconnaissance CLI framework built for **Kali Linux** and professional bug bounty workflows with enhanced capabilities and smoother operation.

---

## Features

### Core Reconnaissance
- **Phase 0** – Subdomain enumeration via `subfinder`
- **Phase 1** – Live host detection via `httpx`
- **Phase 1.5** – DNS enumeration via `dnsx`
- **Phase 2** – Port scanning via `nmap` (fast & aggressive modes)
- **Phase 2.5** – Technology detection via `wappalyzer`
- **Phase 3** – Vulnerability scanning via `nuclei` (customizable severity)
- **Phase 3.5** – Directory enumeration via `ffuf`
- **Phase 4** – Web server scanning via `nikto`

### Advanced Features
- **Scan Profiles** – Pre-configured scanning modes (quick, comprehensive, stealth, bugbounty)
- **Enhanced Progress Bars** – ETA tracking for better time estimation
- **Better Error Handling** – Graceful degradation with detailed error messages
- **Severity Filtering** – Customizable nuclei severity levels
- **Custom Wordlists** – Support for custom directory enumeration wordlists
- **Automated Analysis** – Findings deduplication, severity ranking & CVSS estimation
- **Rich Reporting** – Reports in **HTML**, **Markdown**, **JSON**, and **CSV**
- **Resume Capability** – Skip already scanned domains
- **Rich Terminal UI** – Colored output with detailed progress tracking
- **Structured Logging** – Comprehensive logging to file
- **Graceful Ctrl+C Handling** – Clean interruption with partial results

---

## Installation

### 1. Clone the repo

```bash
git clone https://github.com/sonia-sood-sys/evilscan.git
cd evilscan
```

### 2. Install Python dependencies

```bash
pip3 install -r requirements.txt
```

### 3. Install external tools (Kali Linux)

```bash
# nmap and nikto are pre-installed on Kali, but just in case:
sudo apt update
sudo apt install nmap nikto -y

# httpx (ProjectDiscovery)
go install github.com/projectdiscovery/httpx/cmd/httpx@latest

# nuclei (ProjectDiscovery)
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# subfinder (for subdomain enumeration)
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# dnsx (for DNS enumeration)
go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest

# wappalyzer (for technology detection)
go install github.com/projectdiscovery/wappalyzergo/cmd/wappalyzergo@latest

# ffuf (for directory enumeration)
go install github.com/ffuf/ffuf/v2/cmd/ffuf@latest

# Update nuclei templates
nuclei -update-templates
```

> Make sure `~/go/bin` is in your `$PATH`:
> ```bash
> export PATH=$PATH:~/go/bin
> echo 'export PATH=$PATH:~/go/bin' >> ~/.bashrc
> ```

---

## Usage

```bash
python3 ultrarecon.py -t targets.txt [OPTIONS]
```

### Prepare your targets file

Create a plain text file with one domain per line:

```
example.com
sub.example.com
https://another.com
192.168.1.1
```

The tool automatically:
- Strips `http://` / `https://`
- Removes duplicates
- Removes empty lines

### Options

| Flag | Description |
|------|-------------|
| `-t / --targets FILE` | Path to targets TXT file **(required)** |
| `--threads N` | Parallel threads (default: 10) |
| `--fast` | Fast nmap scan: `-F -T4` (default) |
| `--aggressive` | Aggressive nmap scan: `-sVC` |
| `--nmap-only` | Run nmap phase only |
| `--nuclei-only` | Run nuclei phase only |
| `--nikto-only` | Run nikto phase only |
| `--resume` | Resume scan, skip already scanned domains |
| `--profile` | Use predefined scan profile (quick, comprehensive, stealth, bugbounty) |
| `--subdomain-enum` | Enable subdomain enumeration using subfinder |
| `--dns-enum` | Enable DNS enumeration using dnsx |
| `--tech-detect` | Enable technology detection using wappalyzer |
| `--dir-enum` | Enable directory enumeration using ffuf |
| `--nuclei-severity` | Custom nuclei severity levels (e.g., 'critical,high') |
| `--wordlist` | Custom wordlist for directory enumeration |

### Examples

```bash
# Full scan (all phases)
python3 ultrarecon.py -t targets.txt

# Fast scan with 20 threads
python3 ultrarecon.py -t targets.txt --fast --threads 20

# Aggressive nmap only
python3 ultrarecon.py -t targets.txt --nmap-only --aggressive

# Nuclei only
python3 ultrarecon.py -t targets.txt --nuclei-only

# Resume a previous scan
python3 ultrarecon.py -t targets.txt --resume

# Using scan profiles
python3 ultrarecon.py -t targets.txt --profile comprehensive
python3 ultrarecon.py -t targets.txt --profile stealth
python3 ultrarecon.py -t targets.txt --profile bugbounty

# Advanced scanning with all features
python3 ultrarecon.py -t targets.txt --subdomain-enum --dns-enum --tech-detect --dir-enum

# Custom nuclei severity
python3 ultrarecon.py -t targets.txt --nuclei-severity "critical,high"

# Custom wordlist for directory enumeration
python3 ultrarecon.py -t targets.txt --dir-enum --wordlist /path/to/custom-wordlist.txt
```

---

## Scan Profiles

EvilScan includes pre-configured scan profiles for different scenarios:

### Quick Profile
```bash
python3 ultrarecon.py -t targets.txt --profile quick
```
- Fast reconnaissance with minimal scanning
- Nmap fast mode only
- Critical severity nuclei scans
- No nikto, subdomain, DNS, tech, or directory enumeration

### Comprehensive Profile
```bash
python3 ultrarecon.py -t targets.txt --profile comprehensive
```
- Full reconnaissance with all phases
- Aggressive nmap scanning
- Medium+ severity nuclei scans
- Nikto web scanning enabled
- Subdomain enumeration enabled
- DNS enumeration enabled
- Technology detection enabled
- Directory enumeration enabled

### Stealth Profile
```bash
python3 ultrarecon.py -t targets.txt --profile stealth
```
- Lower profile scanning for stealthy operations
- Fast nmap mode
- Critical+High severity nuclei scans
- No nikto scanning
- DNS enumeration enabled
- Technology detection enabled
- No directory enumeration

### Bug Bounty Profile
```bash
python3 ultrarecon.py -t targets.txt --profile bugbounty
```
- Focused on web application security
- Fast nmap mode
- All severity nuclei scans
- Nikto web scanning enabled
- Subdomain enumeration enabled
- DNS enumeration enabled
- Technology detection enabled
- Directory enumeration enabled

---

## Output Structure

```
results/
├── live/
│   └── live.txt                    # Live hosts found by httpx
├── nmap/
│   ├── example_com.txt             # Per-domain nmap output
│   └── summary.json                # Open ports summary (all domains)
├── nuclei/
│   ├── raw/example_com.txt         # Raw nuclei output
│   └── json/example_com.jsonl      # JSON findings per domain
├── nikto/
│   └── example_com.txt             # Per-domain nikto output
├── subdomains/
│   └── example_com.txt             # Discovered subdomains
├── dns/
│   └── example_com.json            # DNS records and analysis
├── tech/
│   └── example_com.json            # Technology detection results
├── ssl/
│   └── example_com.json            # SSL/TLS certificate analysis
├── directories/
│   └── example_com.json            # Directory enumeration results
├── analysis/
│   ├── ranked_findings.json        # All findings ranked by severity
│   └── high_priority.json          # Critical + High findings only
├── reports/
│   ├── final_report.md             # Executive Markdown report
│   ├── final_report.json           # Machine-readable full report
│   ├── final_report.csv            # Spreadsheet-friendly report
│   └── final_report.html           # Interactive HTML report
└── logs/
    └── scan.log                    # Full scan log
```

---

## Project Structure

```
evilscan/
├── ultrarecon.py        # Main CLI entry point
├── config.py            # All paths, tool names, scan settings, profiles
├── requirements.txt
├── README.md
└── core/
    ├── __init__.py
    ├── scanner.py       # Main Scanner orchestrator class
    ├── live.py          # Phase 1 – httpx live detection
    ├── nmap_scan.py     # Phase 2 – nmap port scanning
    ├── nuclei_scan.py   # Phase 3 – nuclei vuln scanning
    ├── nikto_scan.py    # Phase 4 – nikto web scanning
    ├── subdomain_enum.py # Phase 0 – subfinder subdomain enumeration
    ├── dns_enum.py      # Phase 1.5 – dnsx DNS enumeration
    ├── tech_detect.py   # Phase 2.5 – wappalyzer technology detection
    ├── dir_enum.py      # Phase 3.5 – ffuf directory enumeration
    ├── analyzer.py      # Findings analysis, dedup, CVSS ranking
    ├── reporter.py      # Report generation (MD/JSON/CSV/HTML)
    └── utils.py         # Helpers: logging, domain parsing, etc.
```

---

## Disclaimer

This tool is intended **solely for authorized penetration testing and bug bounty programs**.

- Always obtain **explicit written permission** before scanning any target.
- The authors assume **no liability** for misuse.
- Scanning systems without authorization is **illegal** under the Computer Fraud and Abuse Act (CFAA), Computer Misuse Act, and equivalent laws worldwide.