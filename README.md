# 🔍 ShadowRecon

<p align="center">
  <img src="https://img.shields.io/badge/Version-1.0.0-cyan?style=for-the-badge" alt="Version">
  <img src="https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python" alt="Python">
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20Kali%20%7C%20Termux-green?style=for-the-badge" alt="Platform">
  <img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge" alt="License">
  <img src="https://img.shields.io/badge/Use-Educational%20Only-red?style=for-the-badge" alt="Use">
</p>

<p align="center">
  <strong>Professional OSINT Reconnaissance Toolkit for Ethical Hackers, Bug Bounty Hunters & Security Researchers</strong>
</p>

```
 ╔═══════════════════════════════════════════════════════════════════╗
 ║  ██████╗ ██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗           ║
 ║  ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║           ║
 ║  ╚█████╗ ███████║███████║██║  ██║██║   ██║██║ █╗ ██║           ║
 ║   ╚═══██╗██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║           ║
 ║  ██████╔╝██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝           ║
 ║  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝           ║
 ║  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗                   ║
 ║  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║                   ║
 ║  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║                   ║
 ║  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║                   ║
 ║  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║                   ║
 ║  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝╚═╝  ╚═══╝                   ║
 ╠═══════════════════════════════════════════════════════════════════╣
 ║  ┌─ OSINT Reconnaissance Toolkit v1.0.0                         ║
 ║  ├─ Platform: Linux / Kali Linux / Ubuntu / Android Termux      ║
 ║  ├─ Purpose : Ethical Security Research & Bug Bounty            ║
 ║  └─ ⚠ For AUTHORIZED USE and EDUCATION ONLY                    ║
 ╚═══════════════════════════════════════════════════════════════════╝
```

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Folder Structure](#-folder-structure)
- [Installation](#-installation)
  - [Linux / Kali / Ubuntu / Debian](#linux--kali--ubuntu--debian)
  - [Android Termux](#android-termux)
  - [Manual Installation](#manual-installation)
- [Usage](#-usage)
  - [Quick Start](#quick-start)
  - [Module Examples](#module-examples)
  - [Command Reference](#command-reference)
- [Sample Output](#-sample-output)
- [Export Formats](#-export-formats)
- [Configuration](#-configuration)
- [Troubleshooting](#-troubleshooting)
- [Disclaimer](#-disclaimer)
- [Contributing](#-contributing)
- [License](#-license)
- [Future Improvements](#-future-improvements)

---

## 🌐 Overview

**ShadowRecon** is a modular, professional-grade OSINT (Open Source Intelligence) and reconnaissance toolkit built in Python. Designed for ethical hackers, bug bounty hunters, penetration testers, and security students, it consolidates 10 essential recon techniques into a single, fast, beautifully formatted CLI tool.

Runs natively on **Linux, Kali Linux, Ubuntu, Debian**, and **Android Termux** — making it one of the few recon tools with first-class mobile support.

### Who is this for?

| Audience | Use Case |
|----------|----------|
| 🎓 Security Students | Learn reconnaissance methodology hands-on |
| 🐛 Bug Bounty Hunters | Initial target profiling and attack surface mapping |
| 🔐 Penetration Testers | Pre-engagement OSINT and fingerprinting |
| 🔬 OSINT Researchers | Passive information gathering |
| 📱 Mobile Hackers | Full feature set on Android Termux |

---

## ✨ Features

### 10 Built-in Reconnaissance Modules

| # | Module | Description |
|---|--------|-------------|
| 1 | `--whois` | **Whois Lookup** — Registrar, creation/expiry dates, registrant, nameservers |
| 2 | `--dns` | **DNS Records** — A, AAAA, MX, NS, TXT, CNAME, SOA + zone transfer test |
| 3 | `--subdomains` | **Subdomain Finder** — DNS brute-force + crt.sh certificate transparency |
| 4 | `--geo` | **IP Geolocation** — Country, city, ISP, ASN, proxy/VPN detection |
| 5 | `--headers` | **HTTP Headers** — Full response header analysis + interesting headers |
| 6 | `--ports` | **Port Scanner** — Multi-threaded TCP scanner with banner grabbing |
| 7 | `--rdns` | **Reverse DNS** — PTR records + forward-confirmed reverse DNS check |
| 8 | `--tech` | **Technology Detection** — CMS, framework, WAF, CDN, language fingerprinting |
| 9 | `--robots` | **Robots.txt Checker** — Disallowed paths, sitemaps, security.txt |
| 10 | `--secheaders` | **Security Headers Audit** — OWASP security header grading (A+ to F) |

### Core Capabilities

- ⚡ **Multi-threaded** — Port scanning and subdomain enumeration run in parallel
- 🎨 **Cyberpunk CLI** — Full ANSI color, styled banner, progress bars
- 📦 **Modular Architecture** — Each module is independent and extensible
- 💾 **Export** — JSON and TXT report generation
- 📝 **Logging** — File-based audit log with verbose/debug modes
- 🌐 **crt.sh Integration** — Passive subdomain discovery via certificate logs
- 🔒 **Security Grading** — Automatic A+ to F header audit scoring
- 📱 **Termux Native** — Tested and optimized for Android
- 🛡️ **Error Handling** — Graceful failures with informative messages

---

## 📁 Folder Structure

```
shadowrecon/
│
├── main.py                    # Entry point — argument parsing, module dispatch
│
├── modules/                   # Reconnaissance modules (plug-and-play)
│   ├── __init__.py
│   ├── whois_lookup.py        # WHOIS domain/IP lookup
│   ├── dns_lookup.py          # DNS records enumeration
│   ├── subdomain_finder.py    # Subdomain brute-force + crt.sh
│   ├── ip_geolocation.py      # IP geolocation (ip-api.com + ipinfo.io)
│   ├── http_headers.py        # HTTP response headers analysis
│   ├── port_scanner.py        # Multi-threaded TCP port scanner
│   ├── reverse_dns.py         # Reverse DNS (PTR) + FCrDNS check
│   ├── tech_detection.py      # Technology fingerprinting
│   ├── robots_checker.py      # robots.txt + sitemap + security.txt
│   └── security_headers.py    # OWASP security headers audit
│
├── utils/                     # Shared utilities
│   ├── __init__.py
│   ├── banner.py              # ASCII banner, colors, output formatting
│   ├── logger.py              # Logging setup (file + verbose console)
│   ├── helpers.py             # Validation, port parsing, URL building
│   └── exporter.py            # JSON and TXT export
│
├── config/
│   └── config.ini             # Tool configuration (timeouts, threads, APIs)
│
├── output/                    # Generated reports (JSON/TXT)
├── logs/                      # Audit logs
├── assets/                    # Icons, assets
├── screenshots/               # Demo screenshots
│
├── requirements.txt           # Python dependencies
├── install.sh                 # One-command installer (Linux + Termux)
├── README.md                  # This file
├── LICENSE                    # MIT License
└── .gitignore                 # Git exclusions
```

---

## ⚙️ Installation

### Linux / Kali / Ubuntu / Debian

**One-command install:**

```bash
git clone https://github.com/scp2801/shadowrecon.git
cd shadowrecon
chmod +x install.sh
./install.sh
```

**Manual install:**

```bash
git clone https://github.com/scp2801/shadowrecon.git
cd shadowrecon
pip3 install -r requirements.txt
python3 main.py --help
```

### Android Termux

```bash
# Update Termux packages
pkg update && pkg upgrade -y

# Install dependencies
pkg install python git curl -y

# Clone the tool
git clone https://github.com/scp2801/shadowrecon.git
cd shadowrecon

# Install Python packages
pip install -r requirements.txt --break-system-packages

# Run it
python main.py --help
```

### Manual Installation (No install.sh)

```bash
# Clone repository
git clone https://github.com/scp2801/shadowrecon.git
cd shadowrecon

# Create virtual environment (recommended on Linux)
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Create required directories
mkdir -p output logs

# Test installation
python3 main.py --version
```

---

## 🚀 Usage

### Quick Start

```bash
# Full scan — all 10 modules
python3 main.py -t example.com --all

# Full scan + export to files
python3 main.py -t example.com --all --output results --format both

# Quick info (whois + dns + geo)
python3 main.py -t example.com --whois --dns --geo
```

### Module Examples

```bash
# ── WHOIS Lookup ──────────────────────────────────────────────────
python3 main.py -t example.com --whois

# ── DNS Enumeration ───────────────────────────────────────────────
python3 main.py -t example.com --dns

# ── Subdomain Finder (with custom wordlist) ───────────────────────
python3 main.py -t example.com --subdomains
python3 main.py -t example.com --subdomains --wordlist /path/to/wordlist.txt
python3 main.py -t example.com --subdomains --sub-threads 100

# ── IP Geolocation ────────────────────────────────────────────────
python3 main.py -t example.com --geo
python3 main.py -t 8.8.8.8 --geo

# ── HTTP Headers ──────────────────────────────────────────────────
python3 main.py -t example.com --headers

# ── Port Scanner ──────────────────────────────────────────────────
python3 main.py -t example.com --ports
python3 main.py -t example.com --ports --port-range 1-65535
python3 main.py -t example.com --ports --port-range 80,443,8080,8443
python3 main.py -t example.com --ports --threads 200 --timeout 0.5

# ── Reverse DNS ───────────────────────────────────────────────────
python3 main.py -t 1.1.1.1 --rdns

# ── Technology Detection ──────────────────────────────────────────
python3 main.py -t example.com --tech

# ── Robots.txt ───────────────────────────────────────────────────
python3 main.py -t example.com --robots

# ── Security Headers Audit ────────────────────────────────────────
python3 main.py -t example.com --secheaders
```

### Command Reference

```
usage: shadowrecon [-h] [-t TARGET] [--all] [--whois] [--dns] [--subdomains]
                   [--geo] [--headers] [--ports] [--rdns] [--tech]
                   [--robots] [--secheaders] [--port-range RANGE]
                   [--threads N] [--timeout T] [--wordlist FILE]
                   [--sub-threads N] [--output FILENAME] [--format FORMAT]
                   [--no-color] [--verbose] [--quiet] [--version] [--log FILE]

Scan Modules:
  --all               Run all 10 reconnaissance modules
  --whois             Whois domain/IP lookup
  --dns               DNS records lookup (A, MX, NS, TXT, CNAME, SOA)
  --subdomains        Subdomain enumeration (brute-force + crt.sh)
  --geo               IP geolocation lookup
  --headers           HTTP response headers analysis
  --ports             Port scanner (multi-threaded)
  --rdns              Reverse DNS lookup
  --tech              Technology stack detection
  --robots            Robots.txt & sitemap checker
  --secheaders        Security headers audit (OWASP grading)

Port Scanner Options:
  --port-range RANGE  Port range: 1-1024, 1-65535, or 80,443,8080
  --threads N         Scan threads (default: 100)
  --timeout T         Socket timeout in seconds (default: 1.0)

Subdomain Options:
  --wordlist FILE     Custom wordlist file for brute-forcing
  --sub-threads N     Subdomain threads (default: 50)

Output Options:
  --output FILENAME   Save results to output/<filename>.[json|txt]
  --format FORMAT     Export format: json, txt, or both (default: both)
  --no-color          Disable colored output (for piping)

Misc:
  --verbose / -v      Verbose/debug output
  --quiet / -q        Suppress banner and info
  --log FILE          Custom log file path
  --version           Show version info
```

---

## 📊 Sample Output

```
══════════════════════════════════════════════════════════════════════

  [»] Target     : example.com
  [»] Start Time : 2025-06-01 14:32:01
  [»] Version    : ShadowRecon v1.0.0

  [»] Modules    : 10 selected
  [»] Threads    : 100 (port scan) / 50 (subdomains)

┌─[ Whois Lookup ]
│────────────────────────────────────────────────────────────────────
│   Domain Name              example.com
│   Registrar                ICANN
│   Created                  1995-08-14 04:00:00 UTC
│   Expires                  2024-08-13 04:00:00 UTC
│   Name Servers             a.iana-servers.net, b.iana-servers.net
│   DNSSEC                   signedDelegation

┌─[ DNS Records ]
│────────────────────────────────────────────────────────────────────
│   A        93.184.216.34
│   AAAA     2606:2800:220:1:248:1893:25c8:1946
│   MX       0 .
│   NS       a.iana-servers.net
│            b.iana-servers.net
│   TXT      v=spf1 -all
│   SOA      MNAME=ns.icann.org RNAME=noc.dns.icann.org Serial=2022091302

┌─[ IP Geolocation ]
│────────────────────────────────────────────────────────────────────
│   IP Address               93.184.216.34
│   Country                  United States (US)
│   Region                   Massachusetts
│   City                     Norwell
│   ISP                      Edgecast Inc.
│   Organization             AS15133 Edgecast Networks
│   Proxy/VPN                False
│   Hosting/DC               True

┌─[ Security Headers Audit ]
│────────────────────────────────────────────────────────────────────
│   ✓  Strict-Transport-Security     max-age=31536000
│   ✗  Content-Security-Policy       MISSING
│   ✓  X-Content-Type-Options        nosniff
│   ✓  X-Frame-Options               DENY
│   ✗  Referrer-Policy               MISSING
│   ✗  Permissions-Policy            MISSING
│
│   Security Grade: C (57/100)

┌─[ Scan Summary ]
│────────────────────────────────────────────────────────────────────
  [✓] Completed  : 10/10 modules
  [»] Total Time : 18.4s
  [✓] JSON report saved: output/results.json
  [✓] TXT  report saved: output/results.txt
```

---

## 💾 Export Formats

### JSON Export (`--format json`)
```json
{
    "meta": {
        "tool": "ShadowRecon",
        "version": "1.0.0",
        "target": "example.com",
        "timestamp": "2025-06-01 14:32:01"
    },
    "results": {
        "Whois Lookup": {
            "status": "success",
            "elapsed": 1.23,
            "data": {
                "Domain Name": "example.com",
                "Registrar": "ICANN",
                "Created": "1995-08-14 04:00:00 UTC"
            }
        }
    }
}
```

### TXT Export (`--format txt`)
```
======================================================================
  SHADOWRECON — OSINT Reconnaissance Report
======================================================================
  Tool      : ShadowRecon v1.0.0
  Target    : example.com
  Timestamp : 2025-06-01 14:32:01
======================================================================

──────────────────────────────────────────────────────────────────────
  MODULE: WHOIS LOOKUP
  Status : success
  Elapsed: 1.23s
──────────────────────────────────────────────────────────────────────
  Domain Name: example.com
  Registrar: ICANN
  Created: 1995-08-14 04:00:00 UTC
```

---

## ⚙️ Configuration

Edit `config/config.ini` to customize defaults:

```ini
[network]
http_timeout = 10        # HTTP request timeout
dns_timeout = 5          # DNS query timeout
port_timeout = 1.0       # Port scan socket timeout
default_port_range = 1-1024

[threading]
port_threads = 100
subdomain_threads = 50

[output]
default_format = both    # json, txt, or both
```

---

## 🔧 Troubleshooting

### `ModuleNotFoundError: No module named 'dns'`
```bash
pip3 install dnspython
# Termux:
pip install dnspython --break-system-packages
```

### `ModuleNotFoundError: No module named 'whois'`
```bash
pip3 install python-whois
# Termux:
pip install python-whois --break-system-packages
```

### Port scan is slow
Increase threads and reduce timeout:
```bash
python3 main.py -t example.com --ports --threads 200 --timeout 0.5
```

### Subdomain finder misses results
Use a larger wordlist:
```bash
# Download SecLists
wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt
python3 main.py -t example.com --subdomains --wordlist subdomains-top1million-5000.txt
```

### Permission denied on Termux
```bash
chmod +x install.sh main.py
# If pip fails:
pip install -r requirements.txt --break-system-packages
```

### SSL errors
Already handled — ShadowRecon disables SSL verification for research purposes. If you encounter issues, ensure your Python version is 3.8+.

### Colors not showing
```bash
# Force color output:
export TERM=xterm-256color
python3 main.py -t example.com --all

# Or disable colors for piping:
python3 main.py -t example.com --all --no-color | tee output.txt
```

---

## ⚠️ Disclaimer

> **ShadowRecon is developed for EDUCATIONAL PURPOSES and AUTHORIZED SECURITY TESTING ONLY.**

By using this tool, you agree to:

1. **Only scan systems you own** or have **explicit written permission** to test
2. Not use this tool for unauthorized access, data theft, or any illegal activity
3. Comply with all applicable local, state, national, and international laws
4. Follow responsible disclosure practices if you discover vulnerabilities

Unauthorized scanning of computer systems may violate laws such as:
- Computer Fraud and Abuse Act (CFAA) — USA
- Computer Misuse Act — UK
- IT Act 2000 — India
- Similar laws in your jurisdiction

**The developers assume NO liability for misuse of this tool.**

---

## 🤝 Contributing

Contributions are welcome! Here's how to help:

1. **Fork** the repository
2. **Create** a feature branch: `git checkout -b feature/new-module`
3. **Commit** your changes: `git commit -m 'Add: new_module.py for X'`
4. **Push** to the branch: `git push origin feature/new-module`
5. **Open** a Pull Request

### Adding a New Module

```python
# modules/your_module.py
class YourModule:
    def __init__(self, target: str):
        self.target = target
        self.logger = get_logger()

    def run(self) -> dict:
        """Return a dictionary of results."""
        # Your implementation
        return {"key": "value"}
```

Then register it in `main.py` under `build_module_queue()`.

### Code Style
- Follow PEP 8
- Add docstrings to all classes and methods
- Handle all exceptions gracefully
- Test on both Linux and Termux before submitting

---

## 🔮 Future Improvements

| Feature | Status |
|---------|--------|
| Shodan API integration | 🔄 Planned |
| ASN enumeration | 🔄 Planned |
| Email harvesting (OSINT) | 🔄 Planned |
| WAF fingerprinting | 🔄 Planned |
| CVE lookup for detected tech | 🔄 Planned |
| HTML report generation | 🔄 Planned |
| Async I/O (asyncio) mode | 🔄 Planned |
| Docker container | 🔄 Planned |
| Web UI (Flask) | 🔄 Planned |
| Plugin API for custom modules | 🔄 Planned |

---

## 📜 License

This project is licensed under the **MIT License** — see [LICENSE](LICENSE) for details.

---

<p align="center">
  <strong>ShadowRecon</strong> — Built for the cybersecurity community 🛡️<br>
  <em>Star ⭐ this repo if you find it useful!</em>
</p>
