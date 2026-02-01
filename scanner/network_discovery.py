#!/usr/bin/env python3
"""
Network Discovery Module
Author: Olaoluwa Aminu Taiwo
Description: Discovers active hosts on the network
"""

import socket
import struct
import ipaddress
from scapy.all import ARP, Ether, srp
import netifaces
from typing import List, Dict
import concurrent.futures
import time

class NetworkDiscovery:
    """Discover active hosts on the network"""
    
    def __init__(self):
        self.timeout = 2
        self.max_workers = 100
    
    def get_local_ip(self) -> str:
        """Get local IP address"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            return local_ip
        except:
            return "127.0.0.1"
    
    def get_network_range(self) -> str:
        """Get network range from local IP"""
        try:
            local_ip = self.get_local_ip()
            
            # Get network interface
            gateways = netifaces.gateways()
            default_gateway = gateways['default'][netifaces.AF_INET]
            interface = default_gateway[1]
            
            # Get network address
            addrs = netifaces.ifaddresses(interface)
            ip_info = addrs[netifaces.AF_INET][0]
            
            ip = ip_info['addr']
            netmask = ip_info['netmask']
            
            # Calculate network
            network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
            return str(network)
        except:
            # Fallback
            return "192.168.1.0/24"
    
    def arp_scan(self, network_range: str = None) -> List[Dict]:
        """
        Perform ARP scan to discover hosts
        
        Args:
            network_range: Network range in CIDR notation (e.g., 192.168.1.0/24)
        
        Returns:
            List of discovered hosts with IP and MAC addresses
        """
        if not network_range:
            network_range = self.get_network_range()
        
        print(f"Scanning network: {network_range}")
        
        # Create ARP request
        arp = ARP(pdst=network_range)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp
        
        # Send packet and receive response
        result = srp(packet, timeout=3, verbose=0)[0]
        
        # Parse results
        hosts = []
        for sent, received in result:
            hosts.append({
                'ip': received.psrc,
                'mac': received.hwsrc,
                'hostname': self._get_hostname(received.psrc),
                'vendor': self._get_vendor(received.hwsrc)
            })
        
        return hosts
    
    def ping_sweep(self, network_range: str = None) -> List[str]:
        """
        Perform ping sweep to find active hosts
        
        Args:
            network_range: Network range in CIDR notation
        
        Returns:
            List of active IP addresses
        """
        if not network_range:
            network_range = self.get_network_range()
        
        network = ipaddress.IPv4Network(network_range, strict=False)
        active_hosts = []
        
        print(f"Ping sweep on: {network_range}")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(self._ping_host, str(ip)): ip for ip in network.hosts()}
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    active_hosts.append(result)
                    print(f"  [+] Found: {result}")
        
        return active_hosts
    
    def _ping_host(self, ip: str) -> str:
        """Check if host responds to ping"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip, 80))
            sock.close()
            
            if result == 0:
                return ip
        except:
            pass
        
        return None
    
    def _get_hostname(self, ip: str) -> str:
        """Get hostname from IP address"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except:
            return "Unknown"
    
    def _get_vendor(self, mac: str) -> str:
        """Get vendor from MAC address (first 3 octets)"""
        oui_db = {
            '00:50:56': 'VMware',
            '08:00:27': 'VirtualBox',
            '52:54:00': 'QEMU/KVM',
            '00:1c:42': 'Parallels',
            'dc:a6:32': 'Raspberry Pi'
        }
        
        prefix = mac[:8].lower()
        return oui_db.get(prefix, 'Unknown')


def main():
    """Test network discovery"""
    print("=" * 70)
    print("NETWORK DISCOVERY TEST")
    print("=" * 70)
    
    discovery = NetworkDiscovery()
    
    # Get local info
    local_ip = discovery.get_local_ip()
    network_range = discovery.get_network_range()
    
    print(f"\nLocal IP: {local_ip}")
    print(f"Network Range: {network_range}")
    
    # Perform ARP scan
    print("\n[*] Performing ARP scan...")
    start_time = time.time()
    
    hosts = discovery.arp_scan()
    
    elapsed = time.time() - start_time
    
    print(f"\n[+] Found {len(hosts)} active hosts in {elapsed:.2f} seconds")
    print("\n" + "=" * 70)
    print(f"{'IP Address':<16} {'MAC Address':<18} {'Hostname':<25} {'Vendor'}")
    print("=" * 70)
    
    for host in hosts:
        print(f"{host['ip']:<16} {host['mac']:<18} {host['hostname']:<25} {host['vendor']}")
    
    print("=" * 70)


if __name__ == "__main__":
    main()