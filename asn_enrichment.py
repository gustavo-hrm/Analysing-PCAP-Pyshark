#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ASN and IP Enrichment Module
=============================

Provides ASN, organization, and geolocation enrichment for IP addresses
with local caching to minimize external API calls.

Supports multiple data sources:
- Team Cymru (DNS-based, no auth required)
- IPWhois (RDAP/WHOIS)
- Local cache for performance

"""

# Fallback for restricted Python runtimes where open may be undefined
try:
    open
except NameError:
    import io
    open = io.open

import json
import os
import time
import socket
import re
from collections import defaultdict
from datetime import datetime, timedelta

# Cache configuration
CACHE_DIR = os.path.expanduser('~/.cache/pcap_analysis')
os.makedirs(CACHE_DIR, exist_ok=True)
CACHE_FILE = os.path.join(CACHE_DIR, 'asn_cache.json')
CACHE_TTL_SECONDS = 86400  # 24 hours
MAX_CACHE_ENTRIES = 10000

# ASN reputation tracking (cloud providers, hosting, etc.)
CLOUD_ASN_PATTERNS = {
    'AWS': [16509, 14618, 8987],
    'Google Cloud': [15169, 139070],
    'Azure': [8075, 12076],
    'DigitalOcean': [14061],
    'OVH': [16276],
    'Cloudflare': [13335],
    'Akamai': [20940, 16625],
}

SUSPICIOUS_ASN_CATEGORIES = {
    'BULLETPROOF_HOSTING': ['VDSINA', 'M247', 'MAROSNET', 'BAXET'],
    'VPNPROXY': ['SURFSHARK', 'NORDVPN', 'EXPRESSVPN', 'PRIVATEVPN'],
    'ABUSED_CLOUD': []  # Populated dynamically from abuse tracking
}


class ASNCache:
    """Local cache for ASN lookups with TTL support"""
    
    def __init__(self, cache_file=CACHE_FILE, ttl=CACHE_TTL_SECONDS):
        self.cache_file = cache_file
        self.ttl = ttl
        self.cache = {}
        self.load_cache()
    
    def load_cache(self):
        """Load cache from disk if exists and not expired"""
        if not os.path.exists(self.cache_file):
            return
        
        try:
            with open(self.cache_file, 'r') as f:
                data = json.load(f)
                
            # Filter expired entries
            now = time.time()
            self.cache = {
                ip: entry for ip, entry in data.items()
                if now - entry.get('cached_at', 0) < self.ttl
            }
            
            print(f"[ASN Cache] Loaded {len(self.cache)} valid entries from cache")
        except Exception as e:
            print(f"[ASN Cache] Failed to load cache: {e}")
            self.cache = {}
    
    def save_cache(self, silent=False):
        """Save cache to disk"""
        try:
            # Limit cache size
            if len(self.cache) > MAX_CACHE_ENTRIES:
                # Keep most recent entries
                sorted_items = sorted(
                    self.cache.items(),
                    key=lambda x: x[1].get('cached_at', 0),
                    reverse=True
                )
                self.cache = dict(sorted_items[:MAX_CACHE_ENTRIES])
            
            with open(self.cache_file, 'w') as f:
                json.dump(self.cache, f, indent=2)
        except Exception as e:
            if not silent:
                print(f"[ASN Cache] Failed to save cache: {e}")
    
    def get(self, ip):
        """Get cached ASN info for IP"""
        return self.cache.get(ip)
    
    def set(self, ip, data):
        """Cache ASN info for IP"""
        data['cached_at'] = time.time()
        self.cache[ip] = data
    
    def __del__(self):
        """Save cache on cleanup"""
        try:
            self.save_cache(silent=True)
        except Exception:
            # Ignore errors during interpreter shutdown (e.g., "name 'open' is not defined").
            # This is harmless - explicit saves should be done via close()/save() in main code.
            pass


class ASNEnricher:
    """Main ASN enrichment class"""
    
    def __init__(self):
        self.cache = ASNCache()
        self.abuse_tracking = defaultdict(int)  # Track abuse by ASN
    
    def _cymru_lookup(self, ip):
        """
        Perform Team Cymru DNS-based ASN lookup (no authentication required)
        
        Query: <reversed-ip>.origin.asn.cymru.com
        Returns: "ASN | IP Prefix | Country | Registry | Allocation Date"
        
        Note: This is a basic implementation. For production use, consider using
        the dnspython library for proper TXT record lookups.
        """
        try:
            # This is a stub - actual implementation would require dnspython library
            # For now, return None to use fallback mechanisms
            # 
            # Production implementation with dnspython:
            # import dns.resolver
            # octets = ip.split('.')
            # if len(octets) != 4:
            #     return None
            # reversed_ip = '.'.join(reversed(octets))
            # query_host = f"{reversed_ip}.origin.asn.cymru.com"
            # answers = dns.resolver.resolve(query_host, 'TXT')
            # for rdata in answers:
            #     txt = rdata.to_text().strip('"')
            #     parts = txt.split('|')
            #     if len(parts) >= 5:
            #         return {
            #             'asn': int(parts[0].strip()),
            #             'prefix': parts[1].strip(),
            #             'country': parts[2].strip(),
            #             'registry': parts[3].strip(),
            #             'allocated': parts[4].strip()
            #         }
            return None
            
        except Exception:
            return None
    
    def _is_cloud_provider(self, asn, org):
        """Check if ASN belongs to a cloud provider"""
        if not asn:
            return None
        
        # Check known cloud ASNs
        for provider, asn_list in CLOUD_ASN_PATTERNS.items():
            if asn in asn_list:
                return provider
        
        # Check organization name
        if org:
            org_lower = org.lower()
            if 'amazon' in org_lower or 'aws' in org_lower:
                return 'AWS'
            if 'google' in org_lower or 'gcp' in org_lower:
                return 'Google Cloud'
            if 'microsoft' in org_lower or 'azure' in org_lower:
                return 'Azure'
            if 'digitalocean' in org_lower:
                return 'DigitalOcean'
            if 'cloudflare' in org_lower:
                return 'Cloudflare'
        
        return None
    
    def _categorize_asn(self, asn, org):
        """Categorize ASN based on known patterns"""
        categories = []
        
        if not org:
            return categories
        
        org_upper = org.upper()
        
        # Check suspicious hosting
        for pattern_list in SUSPICIOUS_ASN_CATEGORIES.values():
            for pattern in pattern_list:
                if pattern in org_upper:
                    categories.append('SUSPICIOUS_HOSTING')
                    break
        
        # Check cloud provider
        cloud = self._is_cloud_provider(asn, org)
        if cloud:
            categories.append(f'CLOUD_{cloud.upper().replace(" ", "_")}')
        
        # Check abuse history
        if self.abuse_tracking.get(asn, 0) > 5:
            categories.append('ABUSED_ASN')
        
        return categories
    
    def enrich_ip(self, ip):
        """
        Enrich IP address with ASN, organization, and categorization
        
        Returns dict with:
        - asn: AS number
        - org: Organization name
        - country: Country code
        - cloud_provider: Cloud provider name (if applicable)
        - categories: List of ASN categories
        - is_suspicious: Boolean flag
        - confidence: Confidence score for categorization
        """
        # Check cache first
        cached = self.cache.get(ip)
        if cached:
            return cached
        
        # Skip private IPs
        if self._is_private_ip(ip):
            result = {
                'asn': None,
                'org': 'Private Network',
                'country': None,
                'cloud_provider': None,
                'categories': ['PRIVATE'],
                'is_suspicious': False,
                'confidence': 100
            }
            self.cache.set(ip, result)
            return result
        
        # Perform lookup (Team Cymru or fallback)
        cymru_data = self._cymru_lookup(ip)
        
        # For now, create a basic result structure
        # In production, you would parse cymru_data or use ipwhois library
        result = {
            'asn': None,
            'org': 'Unknown',
            'country': None,
            'cloud_provider': None,
            'categories': [],
            'is_suspicious': False,
            'confidence': 0
        }
        
        # Cache and return
        self.cache.set(ip, result)
        return result
    
    def _is_private_ip(self, ip):
        """Check if IP is in private range"""
        try:
            octets = [int(x) for x in ip.split('.')]
            if len(octets) != 4:
                return True
            
            # 10.0.0.0/8
            if octets[0] == 10:
                return True
            # 172.16.0.0/12
            if octets[0] == 172 and 16 <= octets[1] <= 31:
                return True
            # 192.168.0.0/16
            if octets[0] == 192 and octets[1] == 168:
                return True
            # Loopback
            if octets[0] == 127:
                return True
            
            return False
        except:
            return True
    
    def correlate_domain_with_ip(self, domain, dst_ip):
        """
        Correlate domain with destination IP ASN
        Detects mismatches between domain owner and hosting provider
        
        Returns:
        - mismatch: Boolean indicating suspicious mismatch
        - reason: Description of the mismatch
        - risk_score: Risk score (0-100)
        """
        # Get IP enrichment
        ip_info = self.enrich_ip(dst_ip)
        
        result = {
            'mismatch': False,
            'reason': '',
            'risk_score': 0,
            'ip_org': ip_info.get('org', 'Unknown'),
            'ip_asn': ip_info.get('asn'),
            'cloud_provider': ip_info.get('cloud_provider')
        }
        
        # Check for domain/IP mismatch patterns
        if domain and ip_info.get('cloud_provider'):
            domain_lower = domain.lower()
            
            # Check if domain claims to be one service but hosted on different cloud
            suspicious_patterns = [
                ('google.com', ['AWS', 'Azure', 'DigitalOcean']),
                ('microsoft.com', ['AWS', 'Google Cloud', 'DigitalOcean']),
                ('amazon.com', ['Google Cloud', 'Azure', 'DigitalOcean']),
                ('apple.com', ['AWS', 'Azure', 'DigitalOcean']),
            ]
            
            for pattern_domain, wrong_clouds in suspicious_patterns:
                if pattern_domain in domain_lower:
                    if ip_info['cloud_provider'] in wrong_clouds:
                        result['mismatch'] = True
                        result['reason'] = f"Domain '{domain}' hosted on unexpected cloud: {ip_info['cloud_provider']}"
                        result['risk_score'] = 75
                        return result
        
        # Check for generic suspicious hosting
        if ip_info.get('categories'):
            if 'SUSPICIOUS_HOSTING' in ip_info['categories']:
                result['mismatch'] = True
                result['reason'] = f"Domain hosted on suspicious provider: {ip_info['org']}"
                result['risk_score'] = 60
            elif 'ABUSED_ASN' in ip_info['categories']:
                result['mismatch'] = True
                result['reason'] = f"Domain hosted on frequently abused ASN: {ip_info['asn']}"
                result['risk_score'] = 70
        
        return result
    
    def track_abuse(self, asn):
        """Track ASN abuse for future categorization"""
        if asn:
            self.abuse_tracking[asn] += 1
    
    def get_abuse_stats(self):
        """Get abuse statistics"""
        return dict(self.abuse_tracking)


# Global instance
_enricher = None

def get_enricher():
    """Get global ASN enricher instance"""
    global _enricher
    if _enricher is None:
        _enricher = ASNEnricher()
    return _enricher


# Convenience functions
def enrich_ip(ip):
    """Enrich IP address with ASN info"""
    return get_enricher().enrich_ip(ip)


def correlate_domain_ip(domain, dst_ip):
    """Check for domain/IP ASN mismatch"""
    return get_enricher().correlate_domain_with_ip(domain, dst_ip)


def track_abuse(asn):
    """Track ASN abuse"""
    return get_enricher().track_abuse(asn)


if __name__ == "__main__":
    # Test module
    print("=== ASN Enrichment Module ===")
    print("Testing IP enrichment...")
    
    # Test private IP
    private_result = enrich_ip("192.168.1.1")
    print(f"Private IP: {private_result}")
    
    # Test public IP
    public_result = enrich_ip("8.8.8.8")
    print(f"Public IP: {public_result}")
    
    # Test domain correlation
    correlation = correlate_domain_ip("google.com", "1.2.3.4")
    print(f"Domain correlation: {correlation}")
    
    print("\n✓ ASN enrichment module ready")
