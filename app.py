#!/usr/bin/env python3
"""
Network Scanner Web Dashboard
Author: Olaoluwa Aminu-Taiwo
Description: Web interface for network scanning and vulnerability assessment
"""

from flask import Flask, render_template, request, jsonify, send_file
import sys
import os

# Add scanner directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'scanner'))

from scanner.network_discovery import NetworkDiscovery
from scanner.port_scanner import PortScanner
from scanner.service_detector import ServiceDetector
from scanner.os_fingerprint import OSFingerprint
from scanner.vuln_scanner import VulnerabilityScanner
from scanner.cve_lookup import CVELookup

import threading
import time
from datetime import datetime
import json

app = Flask(__name__)

# Initialize scanners
discovery = NetworkDiscovery()
port_scanner = PortScanner()
service_detector = ServiceDetector()
os_fingerprint = OSFingerprint()
vuln_scanner = VulnerabilityScanner()
cve_lookup = CVELookup()

# Global variables for scan state
scan_progress = {
    'status': 'idle',
    'current_step': '',
    'progress': 0,
    'total': 0,
    'results': None
}


@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('index.html')


@app.route('/api/network-info', methods=['GET'])
def get_network_info():
    """Get local network information"""
    try:
        local_ip = discovery.get_local_ip()
        network_range = discovery.get_network_range()
        
        return jsonify({
            'success': True,
            'local_ip': local_ip,
            'network_range': network_range
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/scan/start', methods=['POST'])
def start_scan():
    """Start network scan"""
    global scan_progress
    
    if scan_progress['status'] == 'running':
        return jsonify({
            'success': False,
            'error': 'Scan already in progress'
        }), 400
    
    data = request.get_json()
    scan_type = data.get('scan_type', 'quick')
    target = data.get('target', '')
    
    # Start scan in background thread
    scan_thread = threading.Thread(
        target=perform_scan,
        args=(target, scan_type)
    )
    scan_thread.daemon = True
    scan_thread.start()
    
    return jsonify({
        'success': True,
        'message': 'Scan started'
    })


@app.route('/api/scan/progress', methods=['GET'])
def get_scan_progress():
    """Get current scan progress"""
    return jsonify(scan_progress)


@app.route('/api/scan/results', methods=['GET'])
def get_scan_results():
    """Get scan results"""
    if scan_progress['results']:
        return jsonify({
            'success': True,
            'results': scan_progress['results']
        })
    else:
        return jsonify({
            'success': False,
            'error': 'No results available'
        }), 404


@app.route('/api/host/scan', methods=['POST'])
def scan_single_host():
    """Scan a single host"""
    data = request.get_json()
    host = data.get('host', '')
    port_range = data.get('port_range', 'common')
    
    if not host:
        return jsonify({
            'success': False,
            'error': 'Host is required'
        }), 400
    
    try:
        results = {
            'host': host,
            'scan_time': datetime.now().isoformat(),
            'ports': [],
            'services': [],
            'vulnerabilities': [],
            'os': {}
        }
        
        # Port scan
        if port_range == 'quick':
            open_ports = port_scanner.quick_scan(host)
        elif port_range == 'common':
            open_ports = port_scanner.scan_ports(host)
        else:
            open_ports = port_scanner.scan_ports(host)
        
        results['ports'] = open_ports
        
        # Service detection
        for port_info in open_ports:
            service_info = service_detector.detect_service(host, port_info['port'])
            results['services'].append(service_info)
            
            # Vulnerability scan
            vulns = vuln_scanner.scan_service(
                host,
                port_info['port'],
                service_info['service'],
                service_info.get('version', '')
            )
            results['vulnerabilities'].extend(vulns)
        
        # OS fingerprinting
        try:
            os_info = os_fingerprint.fingerprint(host)
            results['os'] = os_info
        except:
            results['os'] = {
                'os': os_fingerprint.simple_fingerprint(host),
                'method': 'simple'
            }
        
        return jsonify({
            'success': True,
            'results': results
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/cve/<cve_id>', methods=['GET'])
def lookup_cve(cve_id):
    """Look up CVE details"""
    try:
        cve_data = cve_lookup.lookup_cve(cve_id)
        
        if cve_data:
            return jsonify({
                'success': True,
                'cve': cve_data
            })
        else:
            return jsonify({
                'success': False,
                'error': 'CVE not found'
            }), 404
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


def perform_scan(target, scan_type):
    """Perform network scan (runs in background thread)"""
    global scan_progress
    
    scan_progress['status'] = 'running'
    scan_progress['progress'] = 0
    scan_progress['results'] = None
    
    try:
        results = {
            'scan_time': datetime.now().isoformat(),
            'target': target,
            'scan_type': scan_type,
            'hosts': []
        }
        
        # Step 1: Network discovery
        scan_progress['current_step'] = 'Discovering hosts...'
        scan_progress['progress'] = 10
        
        if target:
            hosts = [{'ip': target, 'hostname': 'Manual Target', 'mac': 'N/A', 'vendor': 'N/A'}]
        else:
            hosts = discovery.arp_scan()
        
        scan_progress['total'] = len(hosts)
        
        # Step 2: Scan each host
        for i, host_info in enumerate(hosts):
            scan_progress['current_step'] = f"Scanning {host_info['ip']}..."
            scan_progress['progress'] = 20 + int((i / len(hosts)) * 70)
            
            host_results = {
                'ip': host_info['ip'],
                'hostname': host_info.get('hostname', 'Unknown'),
                'mac': host_info.get('mac', 'N/A'),
                'vendor': host_info.get('vendor', 'N/A'),
                'ports': [],
                'services': [],
                'vulnerabilities': [],
                'os': {}
            }
            
            # Port scan
            if scan_type == 'quick':
                open_ports = port_scanner.quick_scan(host_info['ip'])
            else:
                open_ports = port_scanner.scan_ports(host_info['ip'])
            
            host_results['ports'] = open_ports
            
            # Service detection and vulnerability scanning
            for port_info in open_ports:
                service_info = service_detector.detect_service(
                    host_info['ip'],
                    port_info['port']
                )
                host_results['services'].append(service_info)
                
                # Vulnerability scan
                vulns = vuln_scanner.scan_service(
                    host_info['ip'],
                    port_info['port'],
                    service_info['service'],
                    service_info.get('version', '')
                )
                host_results['vulnerabilities'].extend(vulns)
            
            # OS fingerprinting
            try:
                os_info = os_fingerprint.fingerprint(host_info['ip'])
                host_results['os'] = os_info
            except:
                host_results['os'] = {
                    'os': os_fingerprint.simple_fingerprint(host_info['ip']),
                    'method': 'simple'
                }
            
            results['hosts'].append(host_results)
        
        scan_progress['current_step'] = 'Scan complete!'
        scan_progress['progress'] = 100
        scan_progress['status'] = 'complete'
        scan_progress['results'] = results
        
    except Exception as e:
        scan_progress['status'] = 'error'
        scan_progress['current_step'] = f'Error: {str(e)}'
        print(f"Scan error: {e}")


@app.route('/api/export/<format>', methods=['POST'])
def export_report(format):
    """Export scan results"""
    from scanner.report_generator import ReportGenerator
    
    data = request.get_json()
    results = data.get('results')
    
    if not results:
        return jsonify({
            'success': False,
            'error': 'No results to export'
        }), 400
    
    try:
        generator = ReportGenerator()
        
        if format == 'html':
            filename = generator.generate_html_report(results)
        elif format == 'json':
            filename = generator.generate_json_report(results)
        elif format == 'csv':
            filename = generator.generate_csv_report(results)
        else:
            return jsonify({
                'success': False,
                'error': 'Invalid format'
            }), 400
        
        return send_file(
            filename,
            as_attachment=True,
            download_name=os.path.basename(filename)
        )
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


if __name__ == '__main__':
    print("=" * 70)
    print("NETWORK SCANNER WEB DASHBOARD")
    print("=" * 70)
    print("\nStarting server...")
    print("Access dashboard at: http://localhost:5000")
    print("\nPress CTRL+C to stop")
    print("=" * 70)
    
    app.run(debug=True, host='0.0.0.0', port=5000, threaded=True)