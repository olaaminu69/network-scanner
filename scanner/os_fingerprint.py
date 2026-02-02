#!/usr/bin/env python3
"""
OS Fingerprinting Module
Author: Olaoluwa Aminu Taiwo
Description: Identify target operating system using TCP/IP stack analysis
"""

import socket
import random
from scapy.all import IP, TCP, ICMP, sr1, sr
from typing import Dict, Optional

class OSFingerprint:
    """Operating System fingerprinting using TCP/IP stack analysis"""
    
    # OS signatures based on TTL and Window Size
    OS_SIGNATURES = {
        (64, 5840): 'Linux 2.4/2.6',
        (64, 5720): 'Google Linux',
        (64, 65535): 'FreeBSD',
        (128, 65535): 'Windows XP/7/8/10',
        (128, 8192): 'Windows Vista/7',
        (255, 4128): 'Cisco IOS',
        (255, 65535): 'Solaris',
    }
    
    def __init__(self, timeout: int = 2):
        self.timeout = timeout
    
    def fingerprint(self, host: str) -> Dict:
        """
        Perform OS fingerprinting on target
        
        Args:
            host: Target IP address
        
        Returns:
            Dictionary with OS detection results
        """
        result = {
            'os': 'Unknown',
            'confidence': 0,
            'ttl': None,
            'window_size': None,
            'details': {}
        }
        
        # Method 1: TTL and Window Size analysis
        ttl_result = self._analyze_ttl(host)
        if ttl_result:
            result.update(ttl_result)
        
        # Method 2: TCP options analysis
        tcp_options = self._analyze_tcp_options(host)
        if tcp_options:
            result['details']['tcp_options'] = tcp_options
        
        # Method 3: ICMP analysis
        icmp_result = self._analyze_icmp(host)
        if icmp_result:
            result['details']['icmp'] = icmp_result
        
        return result
    
    def _analyze_ttl(self, host: str) -> Optional[Dict]:
        """Analyze TTL and Window Size"""
        try:
            # Send SYN packet
            src_port = random.randint(1024, 65535)
            dst_port = 80  # Try common HTTP port
            
            ip = IP(dst=host)
            syn = TCP(sport=src_port, dport=dst_port, flags='S', seq=1000)
            
            # Send packet and get response
            response = sr1(ip/syn, timeout=self.timeout, verbose=0)
            
            if response and response.haslayer(TCP):
                ttl = response.ttl
                window = response[TCP].window
                
                # Guess OS from signature
                os_guess = self._guess_os_from_signature(ttl, window)
                
                return {
                    'os': os_guess['os'],
                    'confidence': os_guess['confidence'],
                    'ttl': ttl,
                    'window_size': window
                }
        
        except Exception as e:
            return None
    
    def _guess_os_from_signature(self, ttl: int, window: int) -> Dict:
        """Guess OS from TTL and window size"""
        # Exact match
        if (ttl, window) in self.OS_SIGNATURES:
            return {
                'os': self.OS_SIGNATURES[(ttl, window)],
                'confidence': 95
            }
        
        # TTL-based guessing
        if ttl <= 64:
            base_os = 'Linux/Unix'
            confidence = 70
        elif ttl <= 128:
            base_os = 'Windows'
            confidence = 70
        elif ttl <= 255:
            base_os = 'Cisco/Solaris'
            confidence = 60
        else:
            return {'os': 'Unknown', 'confidence': 0}
        
        # Refine based on window size
        if window == 65535:
            if ttl <= 64:
                return {'os': 'FreeBSD/OpenBSD', 'confidence': 80}
            else:
                return {'os': 'Windows (Recent)', 'confidence': 80}
        elif window == 5840:
            return {'os': 'Linux 2.4/2.6', 'confidence': 85}
        elif window == 8192:
            return {'os': 'Windows Vista/7/8', 'confidence': 85}
        
        return {'os': base_os, 'confidence': confidence}
    
    def _analyze_tcp_options(self, host: str) -> Optional[str]:
        """Analyze TCP options"""
        try:
            src_port = random.randint(1024, 65535)
            dst_port = 80
            
            ip = IP(dst=host)
            syn = TCP(sport=src_port, dport=dst_port, flags='S')
            
            response = sr1(ip/syn, timeout=self.timeout, verbose=0)
            
            if response and response.haslayer(TCP):
                options = response[TCP].options
                return str(options)
        
        except:
            return None
    
    def _analyze_icmp(self, host: str) -> Optional[Dict]:
        """Analyze ICMP response"""
        try:
            # Send ICMP echo request
            packet = IP(dst=host)/ICMP()
            response = sr1(packet, timeout=self.timeout, verbose=0)
            
            if response and response.haslayer(ICMP):
                return {
                    'type': response[ICMP].type,
                    'code': response[ICMP].code,
                    'ttl': response.ttl
                }
        
        except:
            return None
    
    def simple_fingerprint(self, host: str) -> str:
        """Simple OS detection based on common port responses"""
        # Check common Windows ports
        windows_ports = [135, 139, 445, 3389]
        windows_score = sum(1 for port in windows_ports if self._is_port_open(host, port))
        
        # Check common Linux ports
        linux_ports = [22, 111, 2049]
        linux_score = sum(1 for port in linux_ports if self._is_port_open(host, port))
        
        if windows_score > linux_score:
            return "Likely Windows"
        elif linux_score > windows_score:
            return "Likely Linux/Unix"
        else:
            return "Unknown"
    
    def _is_port_open(self, host: str, port: int) -> bool:
        """Quick check if port is open"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except:
            return False


def main():
    """Test OS fingerprinting"""
    print("=" * 70)
    print("OS FINGERPRINTING TEST")
    print("=" * 70)
    
    fingerprinter = OSFingerprint()
    
    target = input("\nEnter target IP or hostname: ").strip()
    
    try:
        target_ip = socket.gethostbyname(target)
    except:
        print("Error: Could not resolve hostname")
        return
    
    print(f"\n[*] Fingerprinting {target_ip}...")
    
    # Method 1: Advanced fingerprinting (requires root)
    try:
        result = fingerprinter.fingerprint(target_ip)
        
        print(f"\n[+] OS Detection Results:")
        print(f"    Operating System: {result['os']}")
        print(f"    Confidence: {result['confidence']}%")
        
        if result['ttl']:
            print(f"    TTL: {result['ttl']}")
        if result['window_size']:
            print(f"    Window Size: {result['window_size']}")
        
        if result['details']:
            print(f"\n[+] Additional Details:")
            for key, value in result['details'].items():
                print(f"    {key}: {value}")
    
    except PermissionError:
        print("\n[!] Advanced fingerprinting requires root privileges")
        print("[*] Falling back to simple detection...")
        
        # Method 2: Simple fingerprinting (no root required)
        simple_result = fingerprinter.simple_fingerprint(target_ip)
        print(f"\n[+] Simple OS Detection: {simple_result}")
    
    print("\n" + "=" * 70)


if __name__ == "__main__":
    main()