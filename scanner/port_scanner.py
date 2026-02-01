#!/usr/bin/env python3
"""
Advanced Port Scanner Module
Author: Olaoluwa Aminu-Taiwo
Description: Multi-threaded port scanning with service detecting
"""

import socket
import concurrent.futures
from typing import List, Dict, Tuple
import time
from datetime import datetime

class PortScanner:
    """Advanced mlti-threaded port scanner"""

    # Common ports and services
    COMMON_PORTS = {
        21: 'FTP',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        53: 'DNS',
        80: 'HTTP',
        110: 'POP3',
        143: 'IMAP',
        443: 'HTTPS',
        445: 'SMB',
        3306: 'MySQL',
        3389: 'RDP',
        5432: 'PostgreSQL',
        5900: 'VNC',
        8080: 'HTTP-Proxy',
        8443: 'HTTPS-Alt',
        27017: 'MonogoDB',
        6379: 'Redis'
    }

    def __init__(self, timeout: float = 1.0, max_workers: int = 100):
        self.timeout = timeout
        self.max_workers = max_workers

    def scan_port(self, host: str, pot: int) -> Dict:
        """
        Scan a single port

        Args:
            host: Target IP address
            port: port number to scan

        Returns:
            Dict with port info if open, None if closed
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((host, port))

            if result == 0:
                service = self.COMMON_PORTS.get(port, 'Unknown')
                banner =self._grab_banner(sock, host,port)

                port_info = {
                    'port': port,
                    'state':'open',
                    'service': service,
                    'baner': banner
                }

                sock.close()
                return port_info

            sock.close()
            return None
        
        except socket.timeout:
            return None
        except socket.error:
            return None
        except Exception as e:
            return None

    def _grab_banner(self, sock: socket.socket, host: str, port: int) -> str:
        """Attempt to grab service banner"""
        try:
            sock.settimeout(2)

            # Try to grab banner
            if port in [80, 8080, 8443]:
                sock.send(b'GET /HTTP/1.0\r\n\r\n')
            elif port == 22:
                pass    # SSH sends banner automatically
            else:
                sock.send(b'\r\n')

            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            return banner[:100] if banner else ''

        except:
            return ''

    def scan_ports(self, host: str, ports: List[int] = None,
                    progress_callback=None) -> List[Dict]:

        """
        Scan multiple ports on a host

        Args:
            host: Target Ip address
            ports: List of ports to scan (None for common ports)
            progress_callback: Function to call for progress updates

        Returns:
            List of open ports with details
        """
        if ports is None:
            ports = list(self.COMMON_PORTS.keys())

        open_ports = []
        total_ports = len(ports)
        scanned = 0

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_port = {executor.submit(self.scan_port, host, port): port
                                for port in ports}

            for future in concurrent.futures.as_completed(future_to_port):
                result = future.result()
                scanned += 1

                if result:
                    open_ports.append(result)

                if progress_callback:
                    progress_callback(scanned, total_ports)

        return sorted(open_ports, key=lambda x: x['port'])

    def scan_range(self, host: str, start_port: int, end_port: int,
                    progress_callback=None) -> List[Dict]:
        """
        Scan a range of ports

        Args:
            host: Target IP address
            start_port: Starting port number
            end_port: Ending port number
            progress_callback: Function for progress updates

        Returns:
            List of open ports
        """
        ports = range(start_port, end_port + 1)
        return self.scan_ports(host, list(ports), progress_callback)

    def quick_scan(self, host: str) -> List[Dict]:
        """Scan only the most common 20 ports"""
        common_20 = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
                     3306, 3389, 5432, 5900, 8080, 8443, 1433, 1521,
                     27017, 6379]
        return self.scan_ports(host, common_20)

    def full_scan(self, host: str, progress_callback=None) -> List[Dict]:
        """Scan all 65535 ports (SLOW -use with caution)"""
        return self.scan_range(host, 1, 65535, progress_callback)

def main():
    """Test port scanner"""
    print("=" * 70)
    print("PORT SCANNER TEST")
    print("=" * 70)

    scanner = PortScanner()

    # Get target
    target = input("\nEnter target IP or hostname: ").strip()

    # Resolve hostname
    try:
        target_ip = socket.gethostbyname(target)
        print(f"Resolved to: {target_ip}")
    except:
        print("Error: Could not resolve hostname")
        return

    print("\nScan options:")
    print("1. Quick scan (20 most common ports)")
    print("2. Common ports (18 ports)")
    print("3. Custom range")

    choice = input("\nSelect option (1-3): ").strip()

    print(f"\n[*] Scanning {target_ip}...")
    start_time = time.time()

    def progress(current, total):
        percent = (current / total) * 100
        print(f"\r[*] Progress: {current}/{total} ({percent:.1f}%)", end='')

    if choice == '1':
        results = scanner.quick_scan(target_ip)
    elif choice == '2':
        results = scanner.scan_ports(target_ip, progress_callback=progress)
    elif choice == '3':
        start = int(input("Start port: "))
        end = int(input("End port: "))
        results = scanner.scan_range(target_ip, start, end, progress_callback=progress)
    else:
        print("Invalid choice")
        return
    elapsed = time.time() - start_time

    print(f"\n\n[+] Scan completed in {elapsed:.2f} seconds")
    print(f"[+] Found {len(results)} open ports\n")

    if results:
        print("=" * 70)
        print(f"{'Port':<8} {'State':<10} {'Service':<15} {'Banner'}")
        print("=" * 70)

        for port_info in results:
            banner = port_info['banner'][:40] + '...' if len(port_info['banner']) > 40 else port_info['banner']
            print(f"{port_info['port']:<8} {port_info['state']:<10} "
                  f"{port_info['service']:<15} {banner}")

        print("=" * 70)
    else:
        print("No open ports found")

if __name__ == "__main__":
    main()