#!/usr/bin/env python3
"""
Report Generator Module
Author: Olaoluwa Aminu-Taiwo
Description: Generate professional security assessment reports
"""

from datetime import datetime
from typing import Dict, List
import json
import csv
import os

class ReportGenerator:
    """Generate security assessment reports in multiple formats"""
    
    def __init__(self):
        self.reports_dir = 'reports'
        self._ensure_reports_dir()
    
    def _ensure_reports_dir(self):
        """Create reports directory if it doesn't exist"""
        if not os.path.exists(self.reports_dir):
            os.makedirs(self.reports_dir)
    
    def generate_html_report(self, scan_results: Dict, filename: str = None) -> str:
        """Generate HTML report"""
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"{self.reports_dir}/scan_report_{timestamp}.html"
        
        # Calculate statistics
        hosts = scan_results.get('hosts', [])
        total_hosts = len(hosts)
        total_ports = sum(len(h.get('ports', [])) for h in hosts)
        total_vulns = sum(len(h.get('vulnerabilities', [])) for h in hosts)
        total_services = sum(len(h.get('services', [])) for h in hosts)
        
        # Count vulnerabilities by severity
        vuln_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for host in hosts:
            for vuln in host.get('vulnerabilities', []):
                severity = vuln.get('severity', 'LOW')
                vuln_counts[severity] = vuln_counts.get(severity, 0) + 1
        
        # Generate HTML
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Security Assessment Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #f5f5f5;
            color: #333;
            line-height: 1.6;
            padding: 2rem;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 3rem 2rem;
        }}
        
        .header h1 {{
            font-size: 2.5rem;
            margin-bottom: 0.5rem;
        }}
        
        .header p {{
            opacity: 0.9;
            font-size: 1.1rem;
        }}
        
        .meta {{
            background: #f8f9fa;
            padding: 1.5rem 2rem;
            border-bottom: 2px solid #e9ecef;
        }}
        
        .meta-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
        }}
        
        .meta-item {{
            display: flex;
            flex-direction: column;
        }}
        
        .meta-label {{
            font-size: 0.875rem;
            color: #6c757d;
            margin-bottom: 0.25rem;
        }}
        
        .meta-value {{
            font-size: 1.1rem;
            font-weight: 600;
            color: #667eea;
        }}
        
        .section {{
            padding: 2rem;
            border-bottom: 1px solid #e9ecef;
        }}
        
        .section h2 {{
            font-size: 1.75rem;
            margin-bottom: 1.5rem;
            color: #2d3748;
            border-bottom: 3px solid #667eea;
            padding-bottom: 0.5rem;
        }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1.5rem;
            margin-bottom: 2rem;
        }}
        
        .stat-card {{
            background: #f8f9fa;
            padding: 1.5rem;
            border-radius: 8px;
            border-left: 4px solid #667eea;
        }}
        
        .stat-value {{
            font-size: 2rem;
            font-weight: 700;
            color: #667eea;
            margin-bottom: 0.25rem;
        }}
        
        .stat-label {{
            font-size: 0.875rem;
            color: #6c757d;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        
        .severity-grid {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 1rem;
            margin-top: 1rem;
        }}
        
        .severity-card {{
            padding: 1rem;
            border-radius: 8px;
            text-align: center;
        }}
        
        .severity-card.critical {{
            background: #fee;
            border: 2px solid #dc3545;
        }}
        
        .severity-card.high {{
            background: #fff3cd;
            border: 2px solid #ffc107;
        }}
        
        .severity-card.medium {{
            background: #fff8e1;
            border: 2px solid #ff9800;
        }}
        
        .severity-card.low {{
            background: #e8f5e9;
            border: 2px solid #4caf50;
        }}
        
        .severity-count {{
            font-size: 2rem;
            font-weight: 700;
            margin-bottom: 0.25rem;
        }}
        
        .severity-label {{
            font-size: 0.875rem;
            text-transform: uppercase;
            font-weight: 600;
        }}
        
        .host-card {{
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
        }}
        
        .host-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1rem;
            padding-bottom: 1rem;
            border-bottom: 2px solid #dee2e6;
        }}
        
        .host-title {{
            font-size: 1.5rem;
            font-weight: 600;
            color: #2d3748;
        }}
        
        .host-badge {{
            background: #667eea;
            color: white;
            padding: 0.5rem 1rem;
            border-radius: 20px;
            font-size: 0.875rem;
            font-weight: 600;
        }}
        
        .detail-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 1.5rem;
        }}
        
        .detail-section {{
            background: white;
            padding: 1rem;
            border-radius: 8px;
            border: 1px solid #dee2e6;
        }}
        
        .detail-section h4 {{
            font-size: 1rem;
            margin-bottom: 0.75rem;
            color: #495057;
        }}
        
        .detail-list {{
            list-style: none;
        }}
        
        .detail-item {{
            padding: 0.5rem 0;
            border-bottom: 1px solid #e9ecef;
            font-family: 'Courier New', monospace;
            font-size: 0.875rem;
        }}
        
        .detail-item:last-child {{
            border-bottom: none;
        }}
        
        .vuln-item {{
            padding: 1rem;
            margin-bottom: 0.75rem;
            border-radius: 8px;
            border-left: 4px solid;
        }}
        
        .vuln-item.critical {{
            background: #fee;
            border-color: #dc3545;
        }}
        
        .vuln-item.high {{
            background: #fff3cd;
            border-color: #ffc107;
        }}
        
        .vuln-item.medium {{
            background: #fff8e1;
            border-color: #ff9800;
        }}
        
        .vuln-item.low {{
            background: #e8f5e9;
            border-color: #4caf50;
        }}
        
        .vuln-severity {{
            font-weight: 700;
            font-size: 0.875rem;
            margin-bottom: 0.5rem;
        }}
        
        .vuln-description {{
            font-size: 0.875rem;
            color: #495057;
            margin-bottom: 0.25rem;
        }}
        
        .vuln-recommendation {{
            font-size: 0.75rem;
            color: #6c757d;
            font-style: italic;
        }}
        
        .footer {{
            padding: 2rem;
            text-align: center;
            background: #f8f9fa;
            color: #6c757d;
            font-size: 0.875rem;
        }}
        
        @media print {{
            body {{
                padding: 0;
            }}
            .container {{
                box-shadow: none;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <h1>🔍 Network Security Assessment Report</h1>
            <p>Comprehensive vulnerability and security analysis</p>
        </div>
        
        <!-- Metadata -->
        <div class="meta">
            <div class="meta-grid">
                <div class="meta-item">
                    <span class="meta-label">Scan Date</span>
                    <span class="meta-value">{scan_results.get('scan_time', 'N/A')}</span>
                </div>
                <div class="meta-item">
                    <span class="meta-label">Target</span>
                    <span class="meta-value">{scan_results.get('target', 'Network Scan')}</span>
                </div>
                <div class="meta-item">
                    <span class="meta-label">Scan Type</span>
                    <span class="meta-value">{scan_results.get('scan_type', 'Quick').title()}</span>
                </div>
                <div class="meta-item">
                    <span class="meta-label">Generated By</span>
                    <span class="meta-value">Network Scanner v1.0</span>
                </div>
            </div>
        </div>
        
        <!-- Executive Summary -->
        <div class="section">
            <h2>📊 Executive Summary</h2>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-value">{total_hosts}</div>
                    <div class="stat-label">Hosts Scanned</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{total_ports}</div>
                    <div class="stat-label">Open Ports</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{total_services}</div>
                    <div class="stat-label">Services Detected</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{total_vulns}</div>
                    <div class="stat-label">Vulnerabilities</div>
                </div>
            </div>
            
            <h3 style="margin-top: 2rem; margin-bottom: 1rem;">Vulnerability Breakdown</h3>
            <div class="severity-grid">
                <div class="severity-card critical">
                    <div class="severity-count">{vuln_counts.get('CRITICAL', 0)}</div>
                    <div class="severity-label">Critical</div>
                </div>
                <div class="severity-card high">
                    <div class="severity-count">{vuln_counts.get('HIGH', 0)}</div>
                    <div class="severity-label">High</div>
                </div>
                <div class="severity-card medium">
                    <div class="severity-count">{vuln_counts.get('MEDIUM', 0)}</div>
                    <div class="severity-label">Medium</div>
                </div>
                <div class="severity-card low">
                    <div class="severity-count">{vuln_counts.get('LOW', 0)}</div>
                    <div class="severity-label">Low</div>
                </div>
            </div>
        </div>
        
        <!-- Detailed Findings -->
        <div class="section">
            <h2>🔍 Detailed Findings</h2>
"""
        
        # Add host details
        for i, host in enumerate(hosts, 1):
            os_info = host.get('os', {}).get('os', 'Unknown')
            
            html += f"""
            <div class="host-card">
                <div class="host-header">
                    <div>
                        <div class="host-title">{host.get('ip', 'Unknown')}</div>
                        <div style="color: #6c757d; margin-top: 0.25rem;">
                            🖥️ {host.get('hostname', 'Unknown')} | OS: {os_info}
                        </div>
                    </div>
                    <div class="host-badge">{len(host.get('ports', []))} ports open</div>
                </div>
                
                <div class="detail-grid">
                    <!-- Open Ports -->
                    <div class="detail-section">
                        <h4>🔓 Open Ports</h4>
                        <ul class="detail-list">
"""
            
            # Add ports
            for port in host.get('ports', []):
                html += f"""
                            <li class="detail-item">{port.get('port')}/tcp - {port.get('service', 'Unknown')}</li>
"""
            
            if not host.get('ports'):
                html += """
                            <li class="detail-item">No open ports</li>
"""
            
            html += """
                        </ul>
                    </div>
                    
                    <!-- Services -->
                    <div class="detail-section">
                        <h4>🎯 Services</h4>
                        <ul class="detail-list">
"""
            
            # Add services
            for service in host.get('services', []):
                version = service.get('version', '')
                html += f"""
                            <li class="detail-item">{service.get('port')}: {service.get('service')} {version}</li>
"""
            
            if not host.get('services'):
                html += """
                            <li class="detail-item">No services detected</li>
"""
            
            html += """
                        </ul>
                    </div>
                    
                    <!-- Vulnerabilities -->
                    <div class="detail-section">
                        <h4>⚠️ Vulnerabilities</h4>
"""
            
            # Add vulnerabilities
            for vuln in host.get('vulnerabilities', []):
                severity = vuln.get('severity', 'LOW').lower()
                html += f"""
                        <div class="vuln-item {severity}">
                            <div class="vuln-severity">[{vuln.get('severity', 'UNKNOWN')}] {vuln.get('type', 'Unknown')}</div>
                            <div class="vuln-description">{vuln.get('description', 'No description')}</div>
"""
                if vuln.get('recommendation'):
                    html += f"""
                            <div class="vuln-recommendation">→ {vuln.get('recommendation')}</div>
"""
                html += """
                        </div>
"""
            
            if not host.get('vulnerabilities'):
                html += """
                        <div class="vuln-item low">
                            <div class="vuln-description">✓ No vulnerabilities detected</div>
                        </div>
"""
            
            html += """
                    </div>
                </div>
            </div>
"""
        
        # Footer
        html += f"""
        </div>
        
        <!-- Footer -->
        <div class="footer">
            <p>Generated by Network Scanner | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p>This report is confidential and intended for authorized personnel only.</p>
        </div>
    </div>
</body>
</html>
"""
        
        # Write to file
        with open(filename, 'w') as f:
            f.write(html)
        
        return filename
    
    def generate_json_report(self, scan_results: Dict, filename: str = None) -> str:
        """Generate JSON report"""
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"{self.reports_dir}/scan_report_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(scan_results, f, indent=4)
        
        return filename
    
    def generate_csv_report(self, scan_results: Dict, filename: str = None) -> str:
        """Generate CSV report"""
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"{self.reports_dir}/scan_report_{timestamp}.csv"
        
        with open(filename, 'w', newline='') as f:
            writer = csv.writer(f)
            
            # Header
            writer.writerow(['Host', 'Hostname', 'OS', 'Port', 'Service', 'Version', 
                           'Vulnerability', 'Severity', 'CVE'])
            
            # Data
            for host in scan_results.get('hosts', []):
                host_ip = host.get('ip', 'Unknown')
                hostname = host.get('hostname', 'Unknown')
                os_info = host.get('os', {}).get('os', 'Unknown')
                
                # If no vulnerabilities, still show host info
                if not host.get('vulnerabilities'):
                    for service in host.get('services', []):
                        writer.writerow([
                            host_ip,
                            hostname,
                            os_info,
                            service.get('port', ''),
                            service.get('service', ''),
                            service.get('version', ''),
                            'None',
                            'N/A',
                            'N/A'
                        ])
                else:
                    for vuln in host.get('vulnerabilities', []):
                        writer.writerow([
                            host_ip,
                            hostname,
                            os_info,
                            vuln.get('port', ''),
                            vuln.get('service', ''),
                            '',
                            vuln.get('description', ''),
                            vuln.get('severity', ''),
                            vuln.get('cve', 'N/A')
                        ])
        
        return filename


def main():
    """Test report generator"""
    # Sample scan results
    scan_results = {
        'scan_time': datetime.now().isoformat(),
        'target': '192.168.1.0/24',
        'scan_type': 'quick',
        'hosts': [
            {
                'ip': '192.168.1.1',
                'hostname': 'router.local',
                'mac': '00:11:22:33:44:55',
                'vendor': 'Cisco',
                'os': {'os': 'Cisco IOS', 'confidence': 85},
                'ports': [
                    {'port': 22, 'service': 'SSH', 'state': 'open'},
                    {'port': 80, 'service': 'HTTP', 'state': 'open'}
                ],
                'services': [
                    {'port': 22, 'service': 'SSH', 'version': 'OpenSSH 7.4'},
                    {'port': 80, 'service': 'HTTP', 'version': 'Apache 2.4'}
                ],
                'vulnerabilities': [
                    {
                        'type': 'Known Vulnerability',
                        'severity': 'MEDIUM',
                        'cve': 'CVE-2018-15473',
                        'service': 'SSH',
                        'description': 'Username enumeration vulnerability',
                        'recommendation': 'Upgrade OpenSSH to 7.8 or later'
                    }
                ]
            }
        ]
    }
    
    generator = ReportGenerator()
    
    print("=" * 70)
    print("REPORT GENERATOR TEST")
    print("=" * 70)
    
    # Generate reports
    print("\n[*] Generating HTML report...")
    html_file = generator.generate_html_report(scan_results)
    print(f"    [+] Saved to: {html_file}")
    
    print("\n[*] Generating JSON report...")
    json_file = generator.generate_json_report(scan_results)
    print(f"    [+] Saved to: {json_file}")
    
    print("\n[*] Generating CSV report...")
    csv_file = generator.generate_csv_report(scan_results)
    print(f"    [+] Saved to: {csv_file}")
    
    print("\n" + "=" * 70)
    print("Reports generated successfully!")
    print("=" * 70)


if __name__ == "__main__":
    main()