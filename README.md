# 🛡️ Advanced Network Port Scanner & Vulnerability Intelligence Tool

<div align="center">

![Version](https://img.shields.io/badge/version-1.0.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.8+-green.svg)
![License](https://img.shields.io/badge/license-MIT-orange.svg)

**Professional-grade security assessment framework for network reconnaissance and vulnerability analysis**

</div>

---

## 🎯 Features

### Core Scanning Capabilities
- ✅ **Multiple Scan Types**: TCP Connect, TCP SYN (stealth), UDP, Custom stealth modes
- ✅ **High Performance**: Async I/O with dynamic concurrency (up to 5000 concurrent connections)
- ✅ **Intelligent Rate Limiting**: Adaptive throttling to avoid IDS/IPS detection
- ✅ **Flexible Targeting**: Single IP, CIDR ranges, hostname resolution, custom ranges

### Service & OS Detection
- 🔍 **Banner Grabbing**: Automatic service banner extraction
- 🔍 **Version Detection**: Identify service versions with signature matching
- 🔍 **OS Fingerprinting**: TCP/IP stack analysis for OS identification
- 🔍 **Protocol Awareness**: Smart probing for HTTP, FTP, SSH, SMTP, databases

### Vulnerability Intelligence
- 🚨 **CVE Mapping**: Automatic vulnerability lookup for detected services
- 🚨 **Risk Scoring**:  CVSS-based risk assessment with severity levels
- 🚨 **Attack Surface Analysis**: Comprehensive security posture evaluation
- 🚨 **Actionable Recommendations**: Prioritized security remediation guidance

### Professional Reporting
- 📊 **CLI Output**: Beautiful, colorized terminal output with Rich library
- 📊 **JSON Export**: Machine-readable format for automation/integration
- 📊 **HTML Reports**: Professional pentest-ready reports with charts
- 📊 **Real-time Progress**: Live progress bars and scan statistics

### Stealth & Evasion
- 🥷 **Timing Profiles**: 6 timing modes from paranoid to insane
- 🥷 **Randomization**: Port order, delays, packet sizes
- 🥷 **Adaptive Timeouts**: Per-host RTT learning
- 🥷 **Safe Mode**: Protection against accidental public IP scanning

---

## 📋 Requirements

- Python 3.8+
- Root/Administrator privileges (for SYN scans)
- Linux/macOS/Windows

---

## 🚀 Installation

```bash
# Clone repository
git clone https://github.com/hx010207/project-1-. git
cd project-1-

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

---

## 📖 Usage

### Basic Examples

```bash
# Fast scan on common ports
python main. py -t 192.168.1.1 --port-range fast

# Full port scan with service detection
python main. py -t 192.168.1.1 --port-range full -sV

# Scan CIDR range
python main.py -t 192.168.1.0/24 --port-range common

# Stealth scan with timing control
python main.py -t example.com --scan-type stealth --timing sneaky

# Vulnerability assessment with HTML report
python main.py -t 10.0.0.1 -sV --vuln --output-html report.html
```

### Advanced Usage

```bash
# Custom port range
python main.py -t 192.168.1.1 -p 20-25,80,443,8000-8100

# Multiple output formats
python main.py -t 192.168.1.1 -sV --output-json scan.json --output-html report. html

# High-speed aggressive scan
python main.py -t 192.168.1.1 --timing aggressive --concurrency 2000

# Safe mode (blocks public IPs)
python main.py -t 192.168.1.1 --safe-mode

# Scan from target file
python main.py -T targets.txt --port-range common -sV
```

### Command-Line Options

```
Target Specification:
  -t, --target          Target IP, hostname, or CIDR
  -T, --target-file     File containing target list

Port Specification:
  -p, --ports          Ports to scan (e.g., 22,80,443 or 1-1000)
  --port-range         Predefined range:  fast, common, full, top100

Scan Type:
  --scan-type          Technique:  tcp, syn, udp, stealth

Performance:
  --timing             Profile: paranoid, sneaky, polite, normal, aggressive, insane
  --concurrency        Maximum concurrent connections (default: 500)

Detection:
  -sV                  Enable service/version detection
  --os-detection       Enable OS fingerprinting

Vulnerability Assessment:
  --vuln               Enable vulnerability scanning
  --risk-assessment    Perform risk assessment

Output:
  -oJ, --output-json   Save results as JSON
  -oH, --output-html   Generate HTML report
  -q, --quiet          Minimal output
  --log-file           Log file path

Safety:
  --safe-mode          Block scanning of public IPs
  --accept-disclaimer  Accept legal disclaimer without prompt
```

---

## 🏗️ Architecture

```
scanner/
├── core/                    # Core engine
│   ├── scanner_engine.py    # Main orchestration
│   ├── concurrency_manager.py
│   └── timeout_handler.py
│
├── scan_types/              # Scan implementations
│   ├── tcp_connect.py       # TCP connect scan
│   ├── tcp_syn.py           # SYN stealth scan
│   ├── udp_scan.py          # UDP scan
│   └── stealth_scan.py      # Advanced stealth
│
├── detection/               # Fingerprinting
│   ├── banner_grabber.py
│   ├── service_fingerprint.py
│   └── os_fingerprint.py
│
├── intelligence/            # Vulnerability analysis
│   ├── cve_mapper.py        # CVE database
│   └── risk_scoring.py      # Risk assessment
│
├── output/                  # Reporting
│   ├── cli_renderer.py      # Terminal output
│   ├── json_exporter.py     # JSON export
│   └── html_report.py       # HTML reports
│
├── utils/                   # Utilities
│   ├── ip_range_parser.py
│   ├── rate_limiter.py
│   └── logger.py
│
└── main.py                  # CLI entry point
```

### Design Principles

- **Modular Architecture**: Clean separation of concerns, easy to extend
- **Async-First**: Built on asyncio for maximum performance
- **Production-Ready**: Error handling, logging, resource management
- **Security-Focused**: Built-in safety mechanisms and ethical guidelines

---

## 🔐 Security Justification

### Scan Type Security Implications

1. **TCP Connect Scan**
   - Most reliable, completes full handshake
   - Logged by target systems
   - Recommended for authorized assessments

2. **TCP SYN Scan**
   - Stealth - doesn't complete handshake
   - Requires raw socket privileges
   - Less detectable, faster than connect scan

3. **UDP Scan**
   - Unreliable protocol, responses vary
   - Slower due to ICMP rate limiting
   - Essential for DNS, SNMP, etc.

4. **Stealth Scan**
   - Randomized timing and order
   - Evades pattern-based IDS
   - Use for covert reconnaissance

---

## ⚠️ Legal & Ethical Disclaimer

```
╔══════════════════════════════════════════════════════════════════╗
║          LEGAL DISCLAIMER & ETHICAL USE AGREEMENT                ║
╚══════════════════════════════════════════════════════════════════╝

This tool is designed for AUTHORIZED security assessments ONLY. 

YOU MUST: 
✓ Have explicit written permission to scan target systems
✓ Comply with all applicable laws and regulations
✓ Use responsibly within scope of engagement
✓ Respect rate limits and system resources

UNAUTHORIZED scanning may be ILLEGAL and subject to: 
- Criminal prosecution
- Civil liability
- Network access termination

By using this tool, you accept FULL RESPONSIBILITY for your actions.
```

**This tool is intended for:**
- Authorized penetration testing
- Security research on owned systems
- Educational purposes in controlled environments
- Vulnerability assessments with permission

**Do NOT use for:**
- Unauthorized network scanning
- Malicious reconnaissance
- Denial of service attacks
- Any illegal activities

---

## 🧪 Testing

```bash
# Test on local machine (safe)
python main.py -t 127.0.0.1 --port-range fast

# Test on private network
python main.py -t 192.168.1.1 --safe-mode --port-range common

# Full feature test
python main.py -t 192.168.1.1 -sV --vuln --output-html test_report.html
```

---

## 🛣️ Roadmap

### Future Enhancements

- [ ] **Plugin System**:  Extensible exploit modules
- [ ] **Passive Scanning**: Traffic analysis mode
- [ ] **API Integration**:  Shodan, Censys, VirusTotal
- [ ] **Resume Capability**: Continue interrupted scans
- [ ] **Diff Mode**: Compare scan results over time
- [ ] **Distributed Scanning**: Multi-host coordination
- [ ] **GUI Interface**: Web-based control panel
- [ ] **Cloud Integration**: AWS, Azure, GCP scanning
- [ ] **Compliance Checks**: CIS, NIST, PCI-DSS benchmarks

---

## 🤝 Contributing

Contributions welcome! Please: 
1. Fork the repository
2. Create a feature branch
3. Submit a pull request

---

## 📄 License

MIT License - see LICENSE file for details

---

## 👨‍💻 Author

**Harshit S Jain**
- GitHub: [@hx010207](https://github.com/hx010207)
- Project: [project-1-](https://github.com/hx010207/project-1-)

---

## 🙏 Acknowledgments

- Inspired by nmap, masscan, and other legendary security tools
- Built with Python's asyncio ecosystem
- Rich library for beautiful CLI output

---

<div align="center">

**⭐ Star this repo if you find it useful! ⭐**

</div>