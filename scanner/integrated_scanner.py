#!/usr/bin/env python3
"""
Integrated Scanner
Combines network discovery, port scanning, service detection, and OS fingerprinting
"""

from network_discovery import NetworkDiscovery
from port_scanner import PortScanner
from service_detector import ServiceDetector
from os_fingerprint import OSFingerprint
import time
from typing import List, Dict

class IntegratedScanner:
    """Complete network scanning solution"""
    
    def __init__(self):
        self.discovery = NetworkDiscovery()
        self.port_scanner = PortScanner()
        self.service_detector = ServiceDetector()
        self.os_fingerprint = OSFingerprint()
    
    def scan_host(self, host: str, port_range: str = 'common') -> Dict:
        """
        Perform complete scan on a single host
        
        Args:
            host: Target IP address
            port_range: 'common', 'quick', or 'full'
        
        Returns:
            Complete scan results
        """
        print(f"\n[*] Scanning {host}...")
        start_time = time.time()
        
        results = {
            'host': host,
            'scan_time': '',
            'open_ports': [],
            'os': {},
            'services': []
        }
        
        # Port scan
        print("  [+] Port scanning...")
        if port_range == 'quick':
            open_ports = self.port_scanner.quick_scan(host)
        elif port_range == 'common':
            open_ports = self.port_scanner.scan_ports(host)
        else:
            open_ports = self.port_scanner.full_scan(host)
        
        results['open_ports'] = open_ports
        
        # Service detection on open ports
        print(f"  [+] Detecting services on {len(open_ports)} ports...")
        for port_info in open_ports:
            service_info = self.service_detector.detect_service(
                host, port_info['port']
            )
            results['services'].append(service_info)
        
        # OS fingerprinting
        print("  [+] OS fingerprinting...")
        try:
            os_info = self.os_fingerprint.fingerprint(host)
            results['os'] = os_info
        except PermissionError:
            results['os'] = {
                'os': self.os_fingerprint.simple_fingerprint(host),
                'method': 'simple'
            }
        
        elapsed = time.time() - start_time
        results['scan_time'] = f"{elapsed:.2f} seconds"
        
        return results
    
    def scan_network(self, network_range: str = None) -> List[Dict]:
        """
        Scan entire network
        
        Args:
            network_range: CIDR notation (e.g., 192.168.1.0/24)
        
        Returns:
            List of scan results for all hosts
        """
        # Discover hosts
        print("[*] Discovering hosts...")
        hosts = self.discovery.arp_scan(network_range)
        
        print(f"\n[+] Found {len(hosts)} active hosts")
        
        # Scan each host
        all_results = []
        for i, host_info in enumerate(hosts, 1):
            print(f"\n[{i}/{len(hosts)}] Scanning {host_info['ip']}...")
            
            results = self.scan_host(host_info['ip'], 'quick')
            results['hostname'] = host_info['hostname']
            results['mac'] = host_info['mac']
            results['vendor'] = host_info['vendor']
            
            all_results.append(results)
        
        return all_results


def main():
    """Test integrated scanner"""
    scanner = IntegratedScanner()
    
    print("=" * 70)
    print("INTEGRATED NETWORK SCANNER")
    print("=" * 70)
    
    print("\nOptions:")
    print("1. Scan single host")
    print("2. Scan entire network")
    
    choice = input("\nSelect option (1-2): ").strip()
    
    if choice == '1':
        host = input("Enter target IP or hostname: ").strip()
        
        print("\nScan depth:")
        print("1. Quick (20 ports)")
        print("2. Common (18 ports)")
        print("3. Full (all 65535 ports)")
        
        depth = input("Select (1-3): ").strip()
        port_range = {'1': 'quick', '2': 'common', '3': 'full'}.get(depth, 'quick')
        
        results = scanner.scan_host(host, port_range)
        
        # Display results
        print("\n" + "=" * 70)
        print("SCAN RESULTS")
        print("=" * 70)
        print(f"Host: {results['host']}")
        print(f"Scan Time: {results['scan_time']}")
        print(f"OS: {results['os'].get('os', 'Unknown')}")
        print(f"\nOpen Ports: {len(results['open_ports'])}")
        
        if results['services']:
            print("\n" + "-" * 70)
            print(f"{'Port':<8} {'Service':<15} {'Version'}")
            print("-" * 70)
            for service in results['services']:
                print(f"{service['port']:<8} {service['service']:<15} {service.get('version', '')}")
        
        print("=" * 70)
    
    elif choice == '2':
        network = input("Enter network range (or press Enter for auto): ").strip()
        if not network:
            network = None
        
        results = scanner.scan_network(network)
        
        print("\n" + "=" * 70)
        print("NETWORK SCAN RESULTS")
        print("=" * 70)
        
        for host_result in results:
            print(f"\n{host_result['ip']} ({host_result['hostname']})")
            print(f"  MAC: {host_result['mac']} ({host_result['vendor']})")
            print(f"  OS: {host_result['os'].get('os', 'Unknown')}")
            print(f"  Open Ports: {len(host_result['open_ports'])}")
            
            if host_result['services']:
                for service in host_result['services'][:3]:  # Show first 3
                    print(f"    - {service['port']}: {service['service']}")
        
        print("\n" + "=" * 70)


if __name__ == "__main__":
    main()