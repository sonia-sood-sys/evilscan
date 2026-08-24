# EvilScan – UltraRecon Framework

> **[!] For authorized security testing only. Unauthorized use is illegal.**

modular Python reconnaissance CLI framework built for **Kali Linux** and professional bug bounty workflows.

---

## Features

- **Phase 1** – Live host detection via `httpx`
- **Phase 2** – Port scanning via `nmap` (fast & aggressive modes)
- **Phase 3** – Vulnerability scanning via `nuclei` (high/critical severities)
- **Phase 4** – Web server scanning via `nikto`
- Automated findings analysis with severity ranking & CVSS estimation
- Final reports in **Markdown**, **JSON**, and **CSV**
- Resume capability – skips already scanned domains
- Rich colored terminal UI with progress bars
- Structured logging to file
- Graceful Ctrl+C handling

---

## Installation

### 1. Clone the repo

```bash
git clone https://github.com/yourusername/evilscan.git
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
```

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
├── analysis/
│   ├── ranked_findings.json        # All findings ranked by severity
│   └── high_priority.json          # Critical + High findings only
├── reports/
│   ├── final_report.md             # Executive Markdown report
│   ├── final_report.json           # Machine-readable full report
│   └── final_report.csv            # Spreadsheet-friendly report
└── logs/
    └── scan.log                    # Full scan log
```

---

## Project Structure

```
evilscan/
├── ultrarecon.py        # Main CLI entry point
├── config.py            # All paths, tool names, scan settings
├── requirements.txt
├── README.md
└── core/
    ├── __init__.py
    ├── scanner.py       # Main Scanner orchestrator class
    ├── live.py          # Phase 1 – httpx live detection
    ├── nmap_scan.py     # Phase 2 – nmap port scanning
    ├── nuclei_scan.py   # Phase 3 – nuclei vuln scanning
    ├── nikto_scan.py    # Phase 4 – nikto web scanning
    ├── analyzer.py      # Findings analysis, dedup, CVSS ranking
    ├── reporter.py      # Report generation (MD/JSON/CSV)
    └── utils.py         # Helpers: logging, domain parsing, etc.
```

---

## Disclaimer

This tool is intended **solely for authorized penetration testing and bug bounty programs**.

- Always obtain **explicit written permission** before scanning any target.
- The authors assume **no liability** for misuse.
- Scanning systems without authorization is **illegal** under the Computer Fraud and Abuse Act (CFAA), Computer Misuse Act, and equivalent laws worldwide.
