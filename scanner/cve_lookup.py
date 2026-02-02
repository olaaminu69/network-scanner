#!/usr/bin/env python3
"""
CVE Lookup Module
Author: Olaoluwa Aminu-Taiwo
Description: Look up CVE details from online databases
"""

import requests
import json
from typing import Dict, Optional, List
import time

class CVELookup:
    """Look up CVE information from NVD database"""
    
    # Updated NVD API v2.0
    NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.cache = {}
    
    def lookup_cve(self, cve_id: str) -> Optional[Dict]:
        """
        Look up CVE details
        
        Args:
            cve_id: CVE identifier (e.g., CVE-2021-44228)
        
        Returns:
            Dictionary with CVE details
        """
        # Check cache first
        if cve_id in self.cache:
            return self.cache[cve_id]
        
        try:
            # Use CVE ID parameter for v2 API
            params = {'cveId': cve_id}
            headers = {'User-Agent': 'NetworkScanner/1.0'}
            
            if self.api_key:
                headers['apiKey'] = self.api_key
            
            response = requests.get(
                self.NVD_API_URL,
                params=params,
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                
                if 'vulnerabilities' in data and len(data['vulnerabilities']) > 0:
                    cve_item = data['vulnerabilities'][0]['cve']
                    
                    cve_data = self._parse_cve_data_v2(cve_item)
                    self.cache[cve_id] = cve_data
                    
                    return cve_data
                else:
                    print(f"    No data found for {cve_id}")
            else:
                print(f"    API returned status code: {response.status_code}")
            
            # Rate limiting
            time.sleep(0.6)  # NVD API rate limit
            
        except Exception as e:
            print(f"    Error: {e}")
        
        return None
    
    def _parse_cve_data_v2(self, cve: dict) -> Dict:
        """Parse CVE data from NVD API v2 response"""
        # Get CVSS metrics
        metrics = cve.get('metrics', {})
        cvss_v3 = metrics.get('cvssMetricV31', [{}])[0] if 'cvssMetricV31' in metrics else {}
        cvss_v2 = metrics.get('cvssMetricV2', [{}])[0] if 'cvssMetricV2' in metrics else {}
        
        # Extract scores
        if cvss_v3:
            cvss_data = cvss_v3.get('cvssData', {})
            base_score = cvss_data.get('baseScore', 0)
            severity = cvss_data.get('baseSeverity', 'UNKNOWN')
        elif cvss_v2:
            cvss_data = cvss_v2.get('cvssData', {})
            base_score = cvss_data.get('baseScore', 0)
            severity = self._score_to_severity(base_score)
        else:
            base_score = 0
            severity = 'UNKNOWN'
        
        # Get description
        descriptions = cve.get('descriptions', [])
        description = ''
        for desc in descriptions:
            if desc.get('lang') == 'en':
                description = desc.get('value', '')
                break
        
        # Get references
        references = []
        ref_data = cve.get('references', [])
        for ref in ref_data[:5]:  # Limit to 5 references
            references.append({
                'url': ref.get('url', ''),
                'source': ref.get('source', '')
            })
        
        return {
            'cve_id': cve.get('id', ''),
            'description': description[:500],  # Limit description length
            'cvss_score': base_score,
            'severity': severity,
            'published_date': cve.get('published', ''),
            'last_modified': cve.get('lastModified', ''),
            'references': references
        }
    
    def _score_to_severity(self, score: float) -> str:
        """Convert CVSS score to severity"""
        if score >= 9.0:
            return 'CRITICAL'
        elif score >= 7.0:
            return 'HIGH'
        elif score >= 4.0:
            return 'MEDIUM'
        elif score > 0:
            return 'LOW'
        else:
            return 'UNKNOWN'
    
    def lookup_multiple(self, cve_ids: List[str]) -> Dict[str, Dict]:
        """Look up multiple CVEs"""
        results = {}
        
        for cve_id in cve_ids:
            print(f"Looking up {cve_id}...")
            result = self.lookup_cve(cve_id)
            if result:
                results[cve_id] = result
            time.sleep(0.6)  # Rate limiting
        
        return results
    
    def search_by_keyword(self, keyword: str, max_results: int = 5) -> List[Dict]:
        """
        Search CVEs by keyword
        
        Args:
            keyword: Search keyword
            max_results: Maximum number of results
        
        Returns:
            List of CVE dictionaries
        """
        try:
            params = {
                'keywordSearch': keyword,
                'resultsPerPage': max_results
            }
            headers = {'User-Agent': 'NetworkScanner/1.0'}
            
            if self.api_key:
                headers['apiKey'] = self.api_key
            
            response = requests.get(
                self.NVD_API_URL,
                params=params,
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                results = []
                
                if 'vulnerabilities' in data:
                    for vuln in data['vulnerabilities']:
                        cve_data = self._parse_cve_data_v2(vuln['cve'])
                        results.append(cve_data)
                
                return results
        
        except Exception as e:
            print(f"Search error: {e}")
        
        return []


def main():
    """Test CVE lookup"""
    print("=" * 70)
    print("CVE LOOKUP TEST")
    print("=" * 70)
    
    lookup = CVELookup()
    
    # Test CVEs
    test_cves = [
        'CVE-2021-44228',  # Log4Shell
        'CVE-2017-0144',   # EternalBlue
        'CVE-2014-0160',   # Heartbleed
    ]
    
    for cve_id in test_cves:
        print(f"\n[*] Looking up {cve_id}...")
        
        result = lookup.lookup_cve(cve_id)
        
        if result:
            print(f"    CVE ID: {result['cve_id']}")
            print(f"    Severity: {result['severity']} (CVSS: {result['cvss_score']})")
            print(f"    Description: {result['description'][:150]}...")
            print(f"    Published: {result['published_date'][:10]}")
            
            if result['references']:
                print(f"    References:")
                for ref in result['references'][:2]:
                    print(f"      - {ref['url']}")
        else:
            print(f"    [!] Could not retrieve CVE data")
        
        time.sleep(1)  # Rate limiting
    
    # Test keyword search
    print(f"\n{'=' * 70}")
    print("KEYWORD SEARCH TEST")
    print("=" * 70)
    
    print("\n[*] Searching for 'apache' vulnerabilities...")
    results = lookup.search_by_keyword('apache', max_results=3)
    
    if results:
        print(f"    Found {len(results)} results:")
        for i, result in enumerate(results, 1):
            print(f"\n    {i}. {result['cve_id']} - {result['severity']}")
            print(f"       {result['description'][:100]}...")
    else:
        print("    No results found")
    
    print("\n" + "=" * 70)


if __name__ == "__main__":
    main()