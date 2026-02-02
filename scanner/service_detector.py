#!/usr/bin/env python3
"""
Service Detection Module
Author: Olaoluwa Aminu Taiwo
Description: Identifies services and versions running on open ports
"""

import socket
import ssl
import re
from typing import Dict, Optional, Tuple
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Disable SSL warnings for security testing
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class ServiceDetector:
    """Detect services and versions on open ports"""
    
    # Service signatures for banner matching
    SERVICE_SIGNATURES = {
        'SSH': [
            (r'SSH-(\d+\.\d+)-OpenSSH[_-](\S+)', 'OpenSSH {}'),
            (r'SSH-(\d+\.\d+)-(\S+)', '{} {}'),
        ],
        'FTP': [
            (r'220.*FTP.*', 'FTP Server'),
            (r'220 (\S+) FTP', '{} FTP'),
            (r'220.*FileZilla Server (\S+)', 'FileZilla {}'),
            (r'220.*ProFTPD (\S+)', 'ProFTPD {}'),
        ],
        'SMTP': [
            (r'220 (\S+) ESMTP', '{} SMTP'),
            (r'220.*Postfix', 'Postfix SMTP'),
            (r'220.*Sendmail (\S+)', 'Sendmail {}'),
        ],
        'HTTP': [
            (r'Server: Apache/(\S+)', 'Apache {}'),
            (r'Server: nginx/(\S+)', 'nginx {}'),
            (r'Server: Microsoft-IIS/(\S+)', 'IIS {}'),
        ],
        'MySQL': [
            (r'mysql_native_password', 'MySQL Server'),
            (r'\x00(\d+\.\d+\.\d+)', 'MySQL {}'),
        ],
        'PostgreSQL': [
            (r'FATAL.*database', 'PostgreSQL'),
        ],
        'Redis': [
            (r'-ERR.*Redis', 'Redis Server'),
        ]
    }
    
    def __init__(self, timeout: float = 3.0):
        self.timeout = timeout
    
    def detect_service(self, host: str, port: int) -> Dict:
        """
        Detect service running on a port
        
        Args:
            host: Target IP address
            port: Port number
        
        Returns:
            Dictionary with service details
        """
        result = {
            'port': port,
            'service': 'unknown',
            'version': '',
            'banner': '',
            'cpe': '',
            'protocol': 'tcp'
        }
        
        # Try banner grabbing
        banner = self._grab_banner(host, port)
        if banner:
            result['banner'] = banner
            service_info = self._identify_service(banner)
            result.update(service_info)
        
        # Try HTTP/HTTPS detection
        if port in [80, 8080, 8000, 8888]:
            http_info = self._detect_http(host, port, use_ssl=False)
            if http_info:
                result.update(http_info)
        
        elif port in [443, 8443]:
            http_info = self._detect_http(host, port, use_ssl=True)
            if http_info:
                result.update(http_info)
        
        # Try specific protocol detection
        if result['service'] == 'unknown':
            protocol_info = self._detect_protocol(host, port)
            if protocol_info:
                result.update(protocol_info)
        
        return result
    
    def _grab_banner(self, host: str, port: int) -> str:
        """Grab service banner"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((host, port))
            
            # Different probes for different services
            probes = [
                b'',  # Some services send banner automatically
                b'\r\n\r\n',
                b'GET / HTTP/1.0\r\n\r\n',
                b'HELP\r\n',
            ]
            
            banner = ''
            for probe in probes:
                try:
                    if probe:
                        sock.send(probe)
                    data = sock.recv(1024)
                    if data:
                        banner = data.decode('utf-8', errors='ignore').strip()
                        break
                except:
                    continue
            
            sock.close()
            return banner
            
        except Exception as e:
            return ''
    
    def _identify_service(self, banner: str) -> Dict:
        """Identify service from banner"""
        for service_name, signatures in self.SERVICE_SIGNATURES.items():
            for pattern, template in signatures:
                match = re.search(pattern, banner, re.IGNORECASE)
                if match:
                    if '{}' in template:
                        groups = match.groups()
                        version = template.format(*groups)
                    else:
                        version = template
                    
                    return {
                        'service': service_name,
                        'version': version
                    }
        
        return {'service': 'unknown', 'version': ''}
    
    def _detect_http(self, host: str, port: int, use_ssl: bool = False) -> Optional[Dict]:
        """Detect HTTP/HTTPS service and get headers"""
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
            
            result = {
                'service': 'HTTPS' if use_ssl else 'HTTP',
                'http_status': response.status_code,
                'http_title': self._extract_title(response.text),
                'server': headers.get('Server', ''),
                'technologies': []
            }
            
            # Detect web technologies
            techs = self._detect_web_technologies(headers, response.text)
            result['technologies'] = techs
            
            # Update version from Server header
            if result['server']:
                result['version'] = result['server']
            
            return result
            
        except Exception as e:
            return None
    
    def _extract_title(self, html: str) -> str:
        """Extract title from HTML"""
        match = re.search(r'<title>(.*?)</title>', html, re.IGNORECASE | re.DOTALL)
        if match:
            return match.group(1).strip()[:100]
        return ''
    
    def _detect_web_technologies(self, headers: dict, html: str) -> list:
        """Detect web technologies from headers and HTML"""
        technologies = []
        
        # Check headers
        tech_patterns = {
            'X-Powered-By': lambda v: v,
            'X-AspNet-Version': lambda v: f'ASP.NET {v}',
            'X-Generator': lambda v: v,
        }
        
        for header, parser in tech_patterns.items():
            if header in headers:
                tech = parser(headers[header])
                if tech:
                    technologies.append(tech)
        
        # Check HTML patterns
        html_patterns = {
            r'content="WordPress\s+([\d.]+)"': 'WordPress {}',
            r'Powered by Drupal': 'Drupal',
            r'content="Joomla!': 'Joomla',
            r'ng-version="([\d.]+)"': 'Angular {}',
            r'react@([\d.]+)': 'React {}',
            r'jquery/([\d.]+)': 'jQuery {}',
        }
        
        for pattern, template in html_patterns.items():
            match = re.search(pattern, html, re.IGNORECASE)
            if match:
                if '{}' in template:
                    tech = template.format(match.group(1))
                else:
                    tech = template
                technologies.append(tech)
        
        return technologies
    
    def _detect_protocol(self, host: str, port: int) -> Optional[Dict]:
        """Detect protocol by sending specific probes"""
        # MySQL probe
        if port == 3306:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                sock.connect((host, port))
                data = sock.recv(128)
                sock.close()
                
                if b'mysql' in data.lower():
                    return {'service': 'MySQL', 'version': 'MySQL Server'}
            except:
                pass
        
        # PostgreSQL probe
        elif port == 5432:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                sock.connect((host, port))
                # PostgreSQL startup message
                startup = b'\x00\x00\x00\x08\x04\xd2\x16\x2f'
                sock.send(startup)
                data = sock.recv(128)
                sock.close()
                
                if data:
                    return {'service': 'PostgreSQL', 'version': 'PostgreSQL'}
            except:
                pass
        
        # Redis probe
        elif port == 6379:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                sock.connect((host, port))
                sock.send(b'PING\r\n')
                data = sock.recv(128).decode('utf-8', errors='ignore')
                sock.close()
                
                if 'PONG' in data:
                    return {'service': 'Redis', 'version': 'Redis Server'}
            except:
                pass
        
        return None
    
    def detect_ssl_certificate(self, host: str, port: int) -> Optional[Dict]:
        """Get SSL certificate information"""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    
                    return {
                        'subject': dict(x[0] for x in cert.get('subject', [])),
                        'issuer': dict(x[0] for x in cert.get('issuer', [])),
                        'version': cert.get('version'),
                        'serial_number': cert.get('serialNumber'),
                        'not_before': cert.get('notBefore'),
                        'not_after': cert.get('notAfter'),
                    }
        except:
            return None


def main():
    """Test service detector"""
    print("=" * 70)
    print("SERVICE DETECTION TEST")
    print("=" * 70)
    
    detector = ServiceDetector()
    
    # Test targets
    test_cases = [
        ('scanme.nmap.org', 22),
        ('scanme.nmap.org', 80),
        ('google.com', 443),
    ]
    
    for host, port in test_cases:
        print(f"\n[*] Detecting service on {host}:{port}")
        
        try:
            result = detector.detect_service(host, port)
            
            print(f"    Service: {result['service']}")
            print(f"    Version: {result['version']}")
            
            if result.get('banner'):
                banner = result['banner'][:80]
                print(f"    Banner: {banner}...")
            
            if result.get('server'):
                print(f"    Server: {result['server']}")
            
            if result.get('http_title'):
                print(f"    Title: {result['http_title']}")
            
            if result.get('technologies'):
                print(f"    Technologies: {', '.join(result['technologies'])}")
            
            # Check SSL if HTTPS port
            if port == 443:
                cert_info = detector.detect_ssl_certificate(host, port)
                if cert_info:
                    print(f"    SSL Subject: {cert_info['subject'].get('commonName', 'N/A')}")
                    print(f"    SSL Issuer: {cert_info['issuer'].get('commonName', 'N/A')}")
        
        except Exception as e:
            print(f"    Error: {e}")
    
    print("\n" + "=" * 70)


if __name__ == "__main__":
    main()