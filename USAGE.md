# Usage Guide - Network Security Scanner

## Table of Contents
1. [Getting Started](#getting-started)
2. [Web Dashboard](#web-dashboard)
3. [Command Line Tools](#command-line-tools)
4. [Report Generation](#report-generation)
5. [Troubleshooting](#troubleshooting)

---

## Getting Started

### First Time Setup

1. **Install dependencies**
```bash
   pip install -r requirements.txt
```

2. **Test network access**
```bash
   sudo python scanner/network_discovery.py
```

3. **Start web dashboard**
```bash
   sudo python app.py
```

---

## Web Dashboard

### Starting the Server
```bash
# With virtual environment activated
sudo python app.py
```

Access at: `http://localhost:5000`

### Running a Scan

1. **Quick Scan** (Fastest - 20 ports)
   - Leave target empty for network scan
   - Select "Quick Scan"
   - Click "Start Scan"

2. **Common Ports** (18 common services)
   - Enter specific IP or hostname
   - Select "Common Ports"
   - Click "Start Scan"

3. **Full Scan** (All 65535 ports - SLOW!)
   - Only for single hosts
   - Can take 30+ minutes
   - Use with caution

### Understanding Results

**Color Coding:**
- 🔴 **Red (Critical)** - Immediate action required
- 🟠 **Orange (High)** - High priority fixes
- 🟡 **Yellow (Medium)** - Should be addressed
- 🟢 **Green (Low)** - Low risk, monitor

**Statistics:**
- **Hosts Found** - Number of active devices
- **Open Ports** - Total accessible services
- **Vulnerabilities** - Security issues detected
- **Services** - Identified applications

---

## Command Line Tools

### Network Discovery
```bash
# Scan local network
sudo python scanner/network_discovery.py
```

**Output:** List of active hosts with MAC addresses and vendors

### Port Scanning
```bash
# Scan specific host
python scanner/port_scanner.py

# When prompted:
# - Enter target: scanme.nmap.org
# - Select option: 1 (Quick scan)
```

### Service Detection
```bash
# Detect services on open ports
python scanner/service_detector.py
```

### Vulnerability Scanning
```bash
# Check for vulnerabilities
python scanner/vuln_scanner.py
```

### OS Fingerprinting
```bash
# Identify operating system (requires root)
sudo python scanner/os_fingerprint.py
```

### CVE Lookup
```bash
# Look up specific CVE
python scanner/cve_lookup.py
```

---

## Report Generation

### Manual Report Generation
```bash
python scanner/report_generator.py
```

This generates sample reports in `reports/` directory:
- `scan_report_TIMESTAMP.html` - Web viewable
- `scan_report_TIMESTAMP.json` - Machine readable
- `scan_report_TIMESTAMP.csv` - Spreadsheet compatible

### From Web Dashboard

After scan completes:
1. Click "Export HTML" for professional report
2. Click "Export JSON" for data analysis
3. Click "Export CSV" for spreadsheet

---

## Troubleshooting

### Permission Errors
```bash
# Error: Operation not permitted
# Solution: Run with sudo
sudo python app.py
```

### Port Already in Use
```bash
# Error: Address already in use
# Solution: Kill existing process
sudo lsof -i :5000
sudo kill -9 <PID>
```

### Scapy Errors
```bash
# Error: No module named 'scapy'
# Solution: Reinstall
pip uninstall scapy
pip install scapy==2.5.0
```

### Slow Scanning

**If scans are very slow:**
- Use Quick Scan mode
- Scan specific targets instead of entire network
- Reduce thread count in port_scanner.py
- Check network connectivity

### No Hosts Found

**If ARP scan finds nothing:**
- Verify you're on the correct network
- Check firewall isn't blocking
- Try ping sweep instead
- Ensure running as root

---

## Best Practices

1. **Always get permission** before scanning networks
2. **Start with quick scans** to minimize impact
3. **Scan during off-hours** for production networks
4. **Document everything** - save all reports
5. **Review findings carefully** before taking action
6. **Test in lab environment** first

---

## Common Workflows

### Audit Home Network
```bash
# 1. Start dashboard
sudo python app.py

# 2. Leave target empty
# 3. Select "Quick Scan"
# 4. Review findings
# 5. Export HTML report
```

### Test Single Server
```bash
# 1. Use command line
python scanner/port_scanner.py

# 2. Enter server IP
# 3. Select "Common Ports"
# 4. Check for vulnerabilities
sudo python scanner/vuln_scanner.py
```

### Security Assessment
```bash
# 1. Discover network
sudo python scanner/network_discovery.py

# 2. Scan each host
python scanner/port_scanner.py

# 3. Detect services
python scanner/service_detector.py

# 4. Check vulnerabilities
python scanner/vuln_scanner.py

# 5. Generate report
python scanner/report_generator.py
```

---

## Advanced Usage

### Custom Port Ranges

Edit `scanner/port_scanner.py`:
```python
# Scan specific ports
custom_ports = [80, 443, 8080, 8443, 3000, 5000]
results = scanner.scan_ports(host, custom_ports)
```

### Modify Scan Speed

Edit threading settings:
```python
# In port_scanner.py
self.max_workers = 50  # Reduce for slower, more reliable scans
self.timeout = 2.0     # Increase for slower networks
```

---

**Need more help? Open an issue on GitHub!**
