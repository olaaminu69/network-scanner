# 🔍 Network Security Scanner

A comprehensive network security assessment tool with vulnerability detection, service identification, and professional reporting capabilities. Built with Python and Flask.

![Python Version](https://img.shields.io/badge/python-3.7+-blue.svg)
![Flask Version](https://img.shields.io/badge/flask-3.0.0-green.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

## 🎯 Features

### Network Discovery
- ✅ **ARP Scanning** - Discover active hosts on local network
- ✅ **Hostname Resolution** - Identify devices by name
- ✅ **MAC Address Detection** - Vendor identification
- ✅ **Network Topology Mapping** - Visual network layout

### Port Scanning
- ✅ **Multi-threaded Scanning** - Fast parallel port checking (100+ threads)
- ✅ **Flexible Port Ranges** - Quick, common, or full scans
- ✅ **Service Detection** - Identify running services on open ports
- ✅ **Banner Grabbing** - Extract service version information

### Security Assessment
- ✅ **Vulnerability Detection** - Identify known CVEs and misconfigurations
- ✅ **SSL/TLS Analysis** - Check for weak encryption protocols
- ✅ **HTTP Security Headers** - Detect missing security headers
- ✅ **Default Credentials Check** - Test for common weak passwords
- ✅ **OS Fingerprinting** - Identify target operating systems

### Reporting
- ✅ **HTML Reports** - Professional, print-ready security reports
- ✅ **JSON Export** - Machine-readable data format
- ✅ **CSV Export** - Spreadsheet-compatible format
- ✅ **Executive Summary** - High-level overview with statistics
- ✅ **Risk Scoring** - Prioritize vulnerabilities by severity

### Web Dashboard
- ✅ **Real-time Progress** - Live scan status updates
- ✅ **Interactive Results** - Click to explore findings
- ✅ **Dark Theme UI** - Modern, professional interface
- ✅ **Responsive Design** - Works on desktop and mobile

---

## 🚀 Quick Start

### Prerequisites

- Python 3.7 or higher
- Linux (Kali, Ubuntu, Debian) or macOS
- Root/sudo access (for network scanning)
- nmap installed (`sudo apt-get install nmap`)

### Installation

1. **Clone the repository**
```bash
   git clone https://github.com/olaaminu69/network-scanner.git
   cd network-scanner
```

2. **Create virtual environment**
```bash
   python3 -m venv venv
   source venv/bin/activate
```

3. **Install dependencies**
```bash
   pip install -r requirements.txt
```

4. **Run the web dashboard**
```bash
   sudo python app.py
```

5. **Access the dashboard**
```
   http://localhost:5000
```

---

## 📖 Usage

### Web Interface

1. **Start the server** (requires root for network scanning)
```bash
   sudo python app.py
```

2. **Open browser** to `http://localhost:5000`

3. **Configure scan**
   - Enter target IP or leave empty for network scan
   - Select scan type (Quick, Common, or Full)
   - Click "Start Scan"

4. **View results**
   - Real-time progress updates
   - Detailed host information
   - Color-coded vulnerabilities
   - Export reports (HTML/JSON/CSV)

### Command Line

#### Network Discovery
```bash
sudo python scanner/network_discovery.py
```

#### Port Scanning
```bash
python scanner/port_scanner.py
# Follow prompts to enter target and scan type
```

#### Service Detection
```bash
python scanner/service_detector.py
```

#### Vulnerability Scanning
```bash
python scanner/vuln_scanner.py
```

#### OS Fingerprinting
```bash
sudo python scanner/os_fingerprint.py
```

#### Generate Reports
```bash
python scanner/report_generator.py
```

---

## 🛠️ Technical Architecture

### Project Structure
```
network-scanner/
│
├── app.py                          # Flask web application
├── requirements.txt                # Python dependencies
├── README.md                       # This file
│
├── scanner/
│   ├── __init__.py
│   ├── network_discovery.py       # ARP scanning & host discovery
│   ├── port_scanner.py             # Multi-threaded port scanning
│   ├── service_detector.py         # Service & version detection
│   ├── os_fingerprint.py           # Operating system identification
│   ├── vuln_scanner.py             # Vulnerability detection
│   ├── cve_lookup.py               # CVE database integration
│   └── report_generator.py         # Report generation (HTML/JSON/CSV)
│
├── templates/
│   └── index.html                  # Web dashboard UI
│
├── static/
│   ├── css/
│   │   └── style.css              # Dashboard styling
│   └── js/
│       └── main.js                # Dashboard interactivity
│
└── reports/                        # Generated reports directory
```

### Technology Stack

**Backend:**
- Python 3.7+
- Flask 3.0.0 (Web framework)
- Scapy (Packet manipulation)
- Requests (HTTP requests)
- Threading (Parallel processing)

**Frontend:**
- HTML5
- CSS3 (Custom dark theme)
- Vanilla JavaScript (No frameworks)
- Fetch API (AJAX requests)

**Security Tools:**
- nmap (Port scanning)
- python-nmap (Nmap wrapper)
- Scapy (Network packet analysis)
- Netifaces (Network interface info)

---

## 🔒 Security Features

### Vulnerability Detection

The scanner checks for:

- **Known CVEs** - Cross-references service versions with vulnerability databases
- **Weak Protocols** - SSLv2, SSLv3, TLSv1.0, TLSv1.1
- **Missing Security Headers** - X-Frame-Options, HSTS, CSP, etc.
- **Directory Listing** - Exposed directory indexes
- **Default Credentials** - Common username/password combinations
- **Anonymous FTP** - Unsecured file transfer access
- **Outdated Software** - Known vulnerable versions

### Privacy & Safety

- **No Data Storage** - All scanning is real-time, no data persisted
- **Local Processing** - All analysis happens on your machine
- **K-Anonymity** - CVE lookups use privacy-preserving methods
- **Responsible Disclosure** - Tool designed for authorized testing only

---

## 📊 Sample Output

### Console Output
```
======================================================================
NETWORK DISCOVERY TEST
======================================================================

Local IP: 192.168.1.100
Network Range: 192.168.1.0/24

[*] Performing ARP scan...

[+] Found 5 active hosts in 2.34 seconds

======================================================================
IP Address       MAC Address        Hostname              Vendor
======================================================================
192.168.1.1      52:54:00:12:35:00  gateway               QEMU/KVM
192.168.1.10     08:00:27:ab:cd:ef  workstation           VirtualBox
192.168.1.50     dc:a6:32:01:02:03  raspberry-pi          Raspberry Pi
======================================================================
```

### Web Dashboard
- Real-time progress bars
- Color-coded vulnerability severity
- Interactive host cards
- Export buttons for reports

### HTML Report
- Executive summary with statistics
- Vulnerability breakdown by severity
- Detailed findings per host
- Professional, print-ready format

---

## 🎓 What I Learned

Building this project taught me:

- **Network Protocols** - Deep understanding of TCP/IP, ARP, ICMP
- **Concurrent Programming** - Multi-threaded scanning with Python
- **Web Development** - Real-time updates with Flask and AJAX
- **Security Concepts** - Vulnerability assessment methodologies
- **API Integration** - Working with external CVE databases
- **Report Generation** - Creating professional security documentation
- **UI/UX Design** - Building intuitive security interfaces

---

## ⚠️ Disclaimer

**FOR EDUCATIONAL AND AUTHORIZED USE ONLY**

This tool is designed for:
- Security professionals conducting authorized assessments
- Network administrators auditing their own networks
- Educational purposes and cybersecurity training
- Penetration testing with explicit written permission

**Unauthorized scanning of networks you do not own or have permission to test is illegal.**

- Always obtain written authorization before scanning
- Respect rate limits and avoid overwhelming targets
- Follow responsible disclosure practices
- Comply with local laws and regulations

The author is not responsible for misuse of this tool.

---

## 🐛 Known Limitations

- ARP scanning only works on local network
- OS fingerprinting requires root/admin privileges
- Full port scans (1-65535) can be very slow
- CVE database requires internet connection
- Some services may not be detected accurately
- SSL/TLS checks may trigger security alerts

---

## 🚧 Future Enhancements

- [ ] Advanced stealth scanning techniques
- [ ] Integration with Metasploit framework
- [ ] Automated exploit suggestions
- [ ] Network topology visualization
- [ ] Scheduled scanning capabilities
- [ ] Email alerts for critical findings
- [ ] Docker containerization
- [ ] API for programmatic access
- [ ] Machine learning for anomaly detection

---

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### Development Setup
```bash
git clone https://github.com/YOUR_USERNAME/network-scanner.git
cd network-scanner
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## 📝 License

This project is licensed under the MIT License - see below:
```
MIT License

Copyright (c) 2026 Olaoluwa Aminu Taiwo

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## 👨‍💻 Author

**Olaoluwa Aminu-Taiwo**

- GitHub: [@olaaminu69](https://github.com/olaaminu69)
- LinkedIn: [Olaoluwa Aminu Taiwo](https://linkedin.com/in/olaoluwa-aminu-taiwo-b6963a154/)
- Portfolio: [View Projects](https://github.com/olaaminu69)
- X: [@amintemi69](https://x.com/amintemi69)
---

## 🙏 Acknowledgments

- Inspired by Nmap, Metasploit, and other industry-standard security tools
- Built for educational purposes and cybersecurity awareness
- Thanks to the open-source security community

---

## 📚 References

- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CVE Database](https://cve.mitre.org/)
- [Python Scapy Documentation](https://scapy.readthedocs.io/)
- [PTES - Penetration Testing Execution Standard](http://www.pentest-standard.org/)

---

## ⭐ Star This Project

If you found this project helpful, please give it a star! It helps others discover the project and motivates continued development.

---

**Built with ❤️ for cybersecurity education and network security awareness**
