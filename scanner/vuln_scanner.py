#!/usr/bin/env python3
"""
Vulnerability Scanner Module
Author: Olaoluwa Aminu-Taiwo
Description: Detects common vulnerabilities and security misconfigurations
"""

import socket
import ssl
import requests
from typing import List, Dict, Optional
import json
from datetime import datetime
import re

class VulnerabilityScanner:
    """Scan for common vulnerabilities and misconfigurations"""
    
    # Common default credentials
    DEFAULT_CREDENTIALS = [
        ('admin', 'admin'),
        ('admin', 'password'),
        ('root', 'root'),
        ('root', 'toor'),
        ('administrator', 'administrator'),
        ('user', 'user'),
        ('guest', 'guest'),
        ('test', 'test'),
    ]
    
    # Known vulnerable service versions
    VULNERABLE_VERSIONS = {
        'OpenSSH': {
            '7.4': ['CVE-2018-15473', 'CVE-2016-10009'],
            '7.2': ['CVE-2016-10012', 'CVE-2016-10010'],
            '6.6': ['CVE-2015-5600', 'CVE-2015-6563'],
        },
        'Apache': {
            '2.4.49': ['CVE-2021-41773', 'CVE-2021-42013'],
            '2.4.29': ['CVE-2017-15715', 'CVE-2017-15710'],
            '2.2.34': ['CVE-2017-7679', 'CVE-2017-9788'],
        },
        'nginx': {
            '1.10.3': ['CVE-2017-7529'],
            '1.9.5': ['CVE-2016-0742', 'CVE-2016-0746'],
        },
        'MySQL': {
            '5.7.10': ['CVE-2016-0639', 'CVE-2016-0640'],
            '5.6.28': ['CVE-2016-0546', 'CVE-2016-0610'],
        }
    }
    
    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout
        self.vulnerabilities = []
    
    def scan_service(self, host: str, port: int, service: str, 
                     version: str = '') -> List[Dict]:
        """
        Scan a service for vulnerabilities
        
        Args:
            host: Target IP
            port: Port number
            service: Service name
            version: Service version
        
        Returns:
            List of vulnerabilities found
        """
        vulns = []
        
        # Check for known vulnerable versions
        version_vulns = self._check_vulnerable_version(service, version)
        vulns.extend(version_vulns)
        
        # Service-specific checks
        if service == 'SSH':
            ssh_vulns = self._check_ssh_vulns(host, port)
            vulns.extend(ssh_vulns)
        
        elif service in ['HTTP', 'HTTPS']:
            http_vulns = self._check_http_vulns(host, port, service == 'HTTPS')
            vulns.extend(http_vulns)
        
        elif service == 'FTP':
            ftp_vulns = self._check_ftp_vulns(host, port)
            vulns.extend(ftp_vulns)
        
        elif service == 'SMB':
            smb_vulns = self._check_smb_vulns(host, port)
            vulns.extend(smb_vulns)
        
        # SSL/TLS checks for encrypted services
        if port in [443, 8443, 22, 993, 995, 465]:
            ssl_vulns = self._check_ssl_vulns(host, port)
            vulns.extend(ssl_vulns)
        
        return vulns
    
    def _check_vulnerable_version(self, service: str, version: str) -> List[Dict]:
        """Check if service version has known CVEs"""
        vulns = []
        
        # Extract version number
        version_match = re.search(r'(\d+\.\d+\.?\d*)', version)
        if not version_match:
            return vulns
        
        version_num = version_match.group(1)
        
        # Check against known vulnerabilities
        if service in self.VULNERABLE_VERSIONS:
            if version_num in self.VULNERABLE_VERSIONS[service]:
                cves = self.VULNERABLE_VERSIONS[service][version_num]
                
                for cve in cves:
                    vulns.append({
                        'type': 'Known Vulnerability',
                        'severity': 'HIGH',
                        'cve': cve,
                        'service': service,
                        'version': version,
                        'description': f'{service} {version} is vulnerable to {cve}',
                        'recommendation': f'Upgrade {service} to latest version'
                    })
        
        return vulns
    
    def _check_ssh_vulns(self, host: str, port: int) -> List[Dict]:
        """Check SSH-specific vulnerabilities"""
        vulns = []
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((host, port))
            
            # Get SSH banner
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            # Check for weak encryption
            if 'SSH-1' in banner:
                vulns.append({
                    'type': 'Weak Protocol',
                    'severity': 'HIGH',
                    'cve': 'N/A',
                    'service': 'SSH',
                    'description': 'SSH Protocol 1.0 is enabled (vulnerable)',
                    'recommendation': 'Disable SSH Protocol 1.0, use only SSH-2'
                })
            
            # Check for username enumeration (CVE-2018-15473)
            if 'OpenSSH_7.4' in banner or 'OpenSSH_7.7' in banner:
                vulns.append({
                    'type': 'Information Disclosure',
                    'severity': 'MEDIUM',
                    'cve': 'CVE-2018-15473',
                    'service': 'SSH',
                    'description': 'Username enumeration vulnerability',
                    'recommendation': 'Upgrade OpenSSH to version 7.8 or later'
                })
        
        except Exception as e:
            pass
        
        return vulns
    
    def _check_http_vulns(self, host: str, port: int, use_ssl: bool = False) -> List[Dict]:
        """Check HTTP/HTTPS vulnerabilities"""
        vulns = []
        
        try:
            protocol = 'https' if use_ssl else 'http'
            url = f"{protocol}://{host}:{port}/"
            
            response = requests.get(
                url,
                timeout=self.timeout,
                verify=False,
                allow_redirects=False
            )
            
            headers = response.headers
            
            # Missing security headers
            security_headers = {
                'X-Frame-Options': 'Clickjacking protection missing',
                'X-Content-Type-Options': 'MIME-sniffing protection missing',
                'Strict-Transport-Security': 'HSTS not enabled',
                'Content-Security-Policy': 'CSP not configured',
                'X-XSS-Protection': 'XSS protection header missing'
            }
            
            for header, description in security_headers.items():
                if header not in headers:
                    vulns.append({
                        'type': 'Missing Security Header',
                        'severity': 'MEDIUM',
                        'cve': 'N/A',
                        'service': 'HTTP',
                        'description': description,
                        'recommendation': f'Add {header} header to server configuration'
                    })
            
            # Check for directory listing
            dir_response = requests.get(
                f"{protocol}://{host}:{port}/",
                timeout=self.timeout,
                verify=False
            )
            
            if 'Index of /' in dir_response.text or 'Directory listing' in dir_response.text:
                vulns.append({
                    'type': 'Information Disclosure',
                    'severity': 'MEDIUM',
                    'cve': 'N/A',
                    'service': 'HTTP',
                    'description': 'Directory listing is enabled',
                    'recommendation': 'Disable directory indexing'
                })
            
            # Check for common files
            common_files = [
                '/.git/config',
                '/.env',
                '/backup.sql',
                '/phpinfo.php',
                '/admin',
                '/wp-admin',
                '/.htaccess'
            ]
            
            for file_path in common_files:
                try:
                    test_url = f"{protocol}://{host}:{port}{file_path}"
                    test_response = requests.get(
                        test_url,
                        timeout=2,
                        verify=False,
                        allow_redirects=False
                    )
                    
                    if test_response.status_code == 200:
                        vulns.append({
                            'type': 'Information Disclosure',
                            'severity': 'HIGH' if '.git' in file_path or '.env' in file_path else 'MEDIUM',
                            'cve': 'N/A',
                            'service': 'HTTP',
                            'description': f'Sensitive file exposed: {file_path}',
                            'recommendation': f'Remove or restrict access to {file_path}'
                        })
                except:
                    continue
            
            # Check HTTP methods
            options_response = requests.options(
                url,
                timeout=self.timeout,
                verify=False
            )
            
            allowed_methods = options_response.headers.get('Allow', '')
            dangerous_methods = ['PUT', 'DELETE', 'TRACE']
            
            for method in dangerous_methods:
                if method in allowed_methods:
                    vulns.append({
                        'type': 'Dangerous HTTP Method',
                        'severity': 'MEDIUM',
                        'cve': 'N/A',
                        'service': 'HTTP',
                        'description': f'Dangerous HTTP method enabled: {method}',
                        'recommendation': f'Disable {method} method'
                    })
        
        except Exception as e:
            pass
        
        return vulns
    
    def _check_ftp_vulns(self, host: str, port: int) -> List[Dict]:
        """Check FTP vulnerabilities"""
        vulns = []
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((host, port))
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            
            # Check for anonymous login
            sock.send(b'USER anonymous\r\n')
            response = sock.recv(1024).decode('utf-8', errors='ignore')
            
            if '230' in response or '331' in response:
                sock.send(b'PASS anonymous@\r\n')
                pass_response = sock.recv(1024).decode('utf-8', errors='ignore')
                
                if '230' in pass_response:
                    vulns.append({
                        'type': 'Weak Authentication',
                        'severity': 'HIGH',
                        'cve': 'N/A',
                        'service': 'FTP',
                        'description': 'Anonymous FTP login enabled',
                        'recommendation': 'Disable anonymous FTP access'
                    })
            
            sock.close()
        
        except Exception as e:
            pass
        
        return vulns
    
    def _check_smb_vulns(self, host: str, port: int) -> List[Dict]:
        """Check SMB vulnerabilities"""
        vulns = []
        
        # Check for EternalBlue (MS17-010)
        # This is a simplified check - full implementation would use exploit frameworks
        vulns.append({
            'type': 'Potential Vulnerability',
            'severity': 'CRITICAL',
            'cve': 'CVE-2017-0144',
            'service': 'SMB',
            'description': 'SMB service may be vulnerable to EternalBlue (requires detailed testing)',
            'recommendation': 'Apply MS17-010 patch, disable SMBv1'
        })
        
        return vulns
    
    def _check_ssl_vulns(self, host: str, port: int) -> List[Dict]:
        """Check SSL/TLS vulnerabilities"""
        vulns = []
        
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Try different SSL/TLS versions
            protocols_to_test = [
                (ssl.PROTOCOL_SSLv23, 'SSLv2/SSLv3'),
                (ssl.PROTOCOL_TLSv1, 'TLSv1.0'),
                (ssl.PROTOCOL_TLSv1_1, 'TLSv1.1'),
            ]
            
            for protocol, name in protocols_to_test:
                try:
                    test_context = ssl.SSLContext(protocol)
                    test_context.check_hostname = False
                    test_context.verify_mode = ssl.CERT_NONE
                    
                    with socket.create_connection((host, port), timeout=self.timeout) as sock:
                        with test_context.wrap_socket(sock) as ssock:
                            vulns.append({
                                'type': 'Weak Encryption',
                                'severity': 'HIGH',
                                'cve': 'N/A',
                                'service': 'SSL/TLS',
                                'description': f'Outdated protocol supported: {name}',
                                'recommendation': f'Disable {name}, use TLS 1.2 or higher'
                            })
                except:
                    # Protocol not supported (good)
                    pass
            
            # Check certificate
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check expiration
                    not_after = cert.get('notAfter')
                    if not_after:
                        # Parse date and check if expired
                        from datetime import datetime
                        expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                        
                        if expiry_date < datetime.now():
                            vulns.append({
                                'type': 'Certificate Issue',
                                'severity': 'HIGH',
                                'cve': 'N/A',
                                'service': 'SSL/TLS',
                                'description': 'SSL certificate has expired',
                                'recommendation': 'Renew SSL certificate immediately'
                            })
        
        except Exception as e:
            pass
        
        return vulns
    
    def generate_report(self, vulnerabilities: List[Dict]) -> Dict:
        """Generate vulnerability report with risk scoring"""
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'MEDIUM')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Calculate risk score (0-100)
        risk_score = (
            severity_counts['CRITICAL'] * 25 +
            severity_counts['HIGH'] * 15 +
            severity_counts['MEDIUM'] * 5 +
            severity_counts['LOW'] * 1
        )
        risk_score = min(risk_score, 100)
        
        return {
            'total_vulnerabilities': len(vulnerabilities),
            'severity_breakdown': severity_counts,
            'risk_score': risk_score,
            'risk_level': self._get_risk_level(risk_score),
            'vulnerabilities': vulnerabilities
        }
    
    def _get_risk_level(self, score: int) -> str:
        """Get risk level from score"""
        if score >= 75:
            return 'CRITICAL'
        elif score >= 50:
            return 'HIGH'
        elif score >= 25:
            return 'MEDIUM'
        else:
            return 'LOW'


def main():
    """Test vulnerability scanner"""
    print("=" * 70)
    print("VULNERABILITY SCANNER TEST")
    print("=" * 70)
    
    scanner = VulnerabilityScanner()
    
    # Test cases
    test_targets = [
        ('scanme.nmap.org', 22, 'SSH', 'OpenSSH 7.4'),
        ('scanme.nmap.org', 80, 'HTTP', 'Apache 2.4'),
        ('google.com', 443, 'HTTPS', 'gws'),
    ]
    
    all_vulns = []
    
    for host, port, service, version in test_targets:
        print(f"\n[*] Scanning {host}:{port} ({service} {version})")
        
        vulns = scanner.scan_service(host, port, service, version)
        all_vulns.extend(vulns)
        
        if vulns:
            print(f"    [!] Found {len(vulns)} vulnerabilities:")
            for vuln in vulns:
                print(f"        - [{vuln['severity']}] {vuln['description']}")
        else:
            print("    [+] No vulnerabilities found")
    
    # Generate report
    print("\n" + "=" * 70)
    print("VULNERABILITY REPORT")
    print("=" * 70)
    
    report = scanner.generate_report(all_vulns)
    
    print(f"\nTotal Vulnerabilities: {report['total_vulnerabilities']}")
    print(f"Risk Score: {report['risk_score']}/100")
    print(f"Risk Level: {report['risk_level']}")
    
    print("\nSeverity Breakdown:")
    for severity, count in report['severity_breakdown'].items():
        if count > 0:
            print(f"  {severity}: {count}")
    
    print("\n" + "=" * 70)


if __name__ == "__main__":
    main()