#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Threat Intelligence Integration Module
=======================================

Provides integration with threat intelligence feeds and APIs:
- VirusTotal (optional, requires API key)
- AbuseIPDB (optional, requires API key)
- GreyNoise (optional, requires API key)
- Local IOC lists

Implements caching and rate limiting to minimize API calls.
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
import hashlib
import urllib.request
import urllib.error
from collections import defaultdict

# Cache configuration
CACHE_DIR = os.path.expanduser('~/.cache/pcap_analysis')
os.makedirs(CACHE_DIR, exist_ok=True)
CACHE_FILE = os.path.join(CACHE_DIR, 'threat_intel_cache.json')
CACHE_TTL_SECONDS = 3600  # 1 hour for threat intel (more dynamic)
MAX_CACHE_ENTRIES = 5000

# Rate limiting (requests per minute)
RATE_LIMITS = {
    'virustotal': 4,  # Free tier: 4 requests/min
    'abuseipdb': 1000,  # Free tier: 1000/day
    'greynoise': 50,  # Free tier varies
}

# API endpoint configuration (placeholder - users provide their own keys)
API_ENDPOINTS = {
    'virustotal': 'https://www.virustotal.com/vtapi/v2/ip-address/report',
    'abuseipdb': 'https://api.abuseipdb.com/api/v2/check',
    'greynoise': 'https://api.greynoise.io/v3/community/',
}


class ThreatIntelCache:
    """Cache for threat intelligence lookups"""
    
    def __init__(self, cache_file=CACHE_FILE, ttl=CACHE_TTL_SECONDS):
        self.cache_file = cache_file
        self.ttl = ttl
        self.cache = {}
        self.load_cache()
    
    def load_cache(self):
        """Load cache from disk"""
        if not os.path.exists(self.cache_file):
            return
        
        try:
            with open(self.cache_file, 'r') as f:
                data = json.load(f)
            
            # Filter expired entries
            now = time.time()
            self.cache = {
                key: entry for key, entry in data.items()
                if now - entry.get('cached_at', 0) < self.ttl
            }
            
            print(f"[Threat Intel] Loaded {len(self.cache)} valid entries from cache")
        except Exception as e:
            print(f"[Threat Intel] Failed to load cache: {e}")
            self.cache = {}
    
    def save_cache(self, silent=False):
        """Save cache to disk
        
        Args:
            silent: If True, suppress error messages (used by __del__ during shutdown)
        """
        try:
            # Limit cache size
            if len(self.cache) > MAX_CACHE_ENTRIES:
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
                print(f"[Threat Intel] Failed to save cache: {e}")
    
    def get(self, key):
        """Get cached threat intel"""
        return self.cache.get(key)
    
    def set(self, key, data):
        """Cache threat intel data"""
        data['cached_at'] = time.time()
        self.cache[key] = data
    
    def __del__(self):
        """Save cache on cleanup"""
        try:
            self.save_cache(silent=True)
        except Exception:
            # Ignore errors during interpreter shutdown (e.g., "name 'open' is not defined").
            # This is harmless - explicit saves should be done via close()/save() in main code.
            pass


class RateLimiter:
    """Simple rate limiter for API calls"""
    
    def __init__(self):
        self.call_times = defaultdict(list)
    
    def can_call(self, service, limit_per_min):
        """Check if we can make an API call within rate limit"""
        now = time.time()
        cutoff = now - 60  # 1 minute ago
        
        # Remove old calls
        self.call_times[service] = [
            t for t in self.call_times[service] if t > cutoff
        ]
        
        # Check if under limit
        return len(self.call_times[service]) < limit_per_min
    
    def record_call(self, service):
        """Record an API call"""
        self.call_times[service].append(time.time())


class ThreatIntelligence:
    """Main threat intelligence integration class"""
    
    def __init__(self):
        self.cache = ThreatIntelCache()
        self.rate_limiter = RateLimiter()
        self.api_keys = self._load_api_keys()
        self.local_iocs = self._load_local_iocs()
    
    def _load_api_keys(self):
        """Load API keys from environment variables or config file"""
        keys = {
            'virustotal': os.environ.get('VT_API_KEY', ''),
            'abuseipdb': os.environ.get('ABUSEIPDB_API_KEY', ''),
            'greynoise': os.environ.get('GREYNOISE_API_KEY', ''),
        }
        
        # Try loading from config file
        config_file = os.path.expanduser('~/.threat_intel_config.json')
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    config = json.load(f)
                    keys.update(config.get('api_keys', {}))
            except:
                pass
        
        return keys
    
    def _load_local_iocs(self):
        """Load local IOC lists (malicious IPs, domains, etc.)"""
        iocs = {
            'malicious_ips': set(),
            'malicious_domains': set(),
            'c2_indicators': set(),
        }
        
        # Try loading from local file in cache directory
        ioc_file = os.path.join(CACHE_DIR, 'local_iocs.json')
        if os.path.exists(ioc_file):
            try:
                with open(ioc_file, 'r') as f:
                    data = json.load(f)
                    iocs['malicious_ips'] = set(data.get('ips', []))
                    iocs['malicious_domains'] = set(data.get('domains', []))
                    iocs['c2_indicators'] = set(data.get('c2', []))
            except:
                pass
        
        return iocs
    
    def check_ip(self, ip):
        """
        Check IP against threat intelligence sources
        
        Returns:
        - is_malicious: Boolean
        - sources: List of sources that flagged this IP
        - threat_score: Score 0-100
        - categories: List of threat categories
        - last_seen: Timestamp of last malicious activity
        - confidence: Confidence in assessment (0-100)
        """
        # Generate cache key
        cache_key = f"ip:{ip}"
        
        # Check cache first
        cached = self.cache.get(cache_key)
        if cached:
            return cached
        
        result = {
            'is_malicious': False,
            'sources': [],
            'threat_score': 0,
            'categories': [],
            'last_seen': None,
            'confidence': 0,
            'details': {}
        }
        
        # Check local IOC list first (fast)
        if ip in self.local_iocs['malicious_ips']:
            result['is_malicious'] = True
            result['sources'].append('local_iocs')
            result['threat_score'] = 80
            result['categories'].append('Known Malicious IP')
            result['confidence'] = 95
        
        # Check external APIs if available (with rate limiting)
        # VirusTotal
        if self.api_keys.get('virustotal') and self.rate_limiter.can_call('virustotal', RATE_LIMITS['virustotal']):
            vt_result = self._check_virustotal_ip(ip)
            if vt_result and vt_result.get('detected'):
                self.rate_limiter.record_call('virustotal')  # Record successful call
                result['is_malicious'] = True
                result['sources'].append('VirusTotal')
                result['threat_score'] = max(result['threat_score'], vt_result.get('score', 70))
                result['categories'].extend(vt_result.get('categories', []))
                result['details']['virustotal'] = vt_result
        
        # AbuseIPDB
        if self.api_keys.get('abuseipdb') and self.rate_limiter.can_call('abuseipdb', RATE_LIMITS['abuseipdb']):
            abuse_result = self._check_abuseipdb(ip)
            if abuse_result and abuse_result.get('abuse_score', 0) > 50:
                self.rate_limiter.record_call('abuseipdb')  # Record successful call
                result['is_malicious'] = True
                result['sources'].append('AbuseIPDB')
                result['threat_score'] = max(result['threat_score'], abuse_result.get('abuse_score', 0))
                result['categories'].append('Reported Abuse')
                result['details']['abuseipdb'] = abuse_result
        
        # GreyNoise
        if self.api_keys.get('greynoise') and self.rate_limiter.can_call('greynoise', RATE_LIMITS['greynoise']):
            gn_result = self._check_greynoise(ip)
            if gn_result and gn_result.get('classification') == 'malicious':
                self.rate_limiter.record_call('greynoise')  # Record successful call
                result['is_malicious'] = True
                result['sources'].append('GreyNoise')
                result['threat_score'] = max(result['threat_score'], 75)
                result['categories'].append('Active Scanner/Attacker')
                result['details']['greynoise'] = gn_result
        
        # Calculate confidence based on number of sources
        if result['sources']:
            result['confidence'] = min(100, 50 + len(result['sources']) * 25)
        
        # Cache result
        self.cache.set(cache_key, result)
        
        return result
    
    def check_domain(self, domain):
        """
        Check domain against threat intelligence sources
        
        Returns similar structure to check_ip()
        """
        cache_key = f"domain:{domain}"
        
        # Check cache
        cached = self.cache.get(cache_key)
        if cached:
            return cached
        
        result = {
            'is_malicious': False,
            'sources': [],
            'threat_score': 0,
            'categories': [],
            'confidence': 0,
            'details': {}
        }
        
        # Check local IOC list
        if domain in self.local_iocs['malicious_domains']:
            result['is_malicious'] = True
            result['sources'].append('local_iocs')
            result['threat_score'] = 80
            result['categories'].append('Known Malicious Domain')
            result['confidence'] = 95
        
        # Check for C2 patterns
        if domain in self.local_iocs['c2_indicators']:
            result['is_malicious'] = True
            result['sources'].append('c2_signatures')
            result['threat_score'] = 90
            result['categories'].append('C2 Infrastructure')
            result['confidence'] = 90
        
        # External API checks would go here (similar to IP checks)
        
        # Calculate confidence
        if result['sources']:
            result['confidence'] = min(100, 50 + len(result['sources']) * 25)
        
        # Cache result
        self.cache.set(cache_key, result)
        
        return result
    
    def _check_virustotal_ip(self, ip):
        """
        Check IP against VirusTotal API.
        
        Args:
            ip: IP address to check
            
        Returns:
            dict with detection status, score, categories, AS owner, country
            or None on error
        """
        api_key = self.api_keys.get('virustotal')
        if not api_key:
            return None
        
        try:
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
            req = urllib.request.Request(
                url,
                headers={
                    'x-apikey': api_key,
                    'Accept': 'application/json'
                }
            )
            
            with urllib.request.urlopen(req, timeout=10) as response:
                data = json.loads(response.read().decode('utf-8', errors='replace'))
            
            attributes = data.get('data', {}).get('attributes', {})
            stats = attributes.get('last_analysis_stats', {})
            
            malicious_count = stats.get('malicious', 0)
            suspicious_count = stats.get('suspicious', 0)
            
            # Calculate score (0-100)
            total = max(1, sum(stats.values()))
            score = int((malicious_count + suspicious_count * 0.5) / total * 100)
            
            return {
                'detected': malicious_count > 0 or suspicious_count > 0,
                'score': score,
                'malicious_count': malicious_count,
                'suspicious_count': suspicious_count,
                'categories': list(attributes.get('categories', {}).values()),
                'as_owner': attributes.get('as_owner', 'Unknown'),
                'country': attributes.get('country', 'Unknown'),
            }
            
        except urllib.error.HTTPError as e:
            print(f"[ThreatIntel] VirusTotal API error for {ip}: HTTP {e.code}")
            return None
        except urllib.error.URLError as e:
            print(f"[ThreatIntel] VirusTotal connection error for {ip}: {e.reason}")
            return None
        except Exception as e:
            print(f"[ThreatIntel] VirusTotal error for {ip}: {e}")
            return None
    
    def _check_abuseipdb(self, ip):
        """
        Check IP against AbuseIPDB API.
        
        Args:
            ip: IP address to check
            
        Returns:
            dict with abuse confidence score, total reports, country, ISP, isTor
            or None on error
        """
        api_key = self.api_keys.get('abuseipdb')
        if not api_key:
            return None
        
        try:
            url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90"
            req = urllib.request.Request(
                url,
                headers={
                    'Key': api_key,
                    'Accept': 'application/json'
                }
            )
            
            with urllib.request.urlopen(req, timeout=10) as response:
                data = json.loads(response.read().decode('utf-8', errors='replace'))
            
            result_data = data.get('data', {})
            abuse_score = result_data.get('abuseConfidenceScore', 0)
            
            return {
                'detected': abuse_score > 50,
                'abuse_score': abuse_score,
                'total_reports': result_data.get('totalReports', 0),
                'country': result_data.get('countryCode', 'Unknown'),
                'isp': result_data.get('isp', 'Unknown'),
                'is_tor': result_data.get('isTor', False),
                'is_public': result_data.get('isPublic', True),
                'last_reported': result_data.get('lastReportedAt'),
            }
            
        except urllib.error.HTTPError as e:
            print(f"[ThreatIntel] AbuseIPDB API error for {ip}: HTTP {e.code}")
            return None
        except urllib.error.URLError as e:
            print(f"[ThreatIntel] AbuseIPDB connection error for {ip}: {e.reason}")
            return None
        except Exception as e:
            print(f"[ThreatIntel] AbuseIPDB error for {ip}: {e}")
            return None
    
    def _check_greynoise(self, ip):
        """
        Check IP against GreyNoise Community API.
        
        Args:
            ip: IP address to check
            
        Returns:
            dict with noise, riot, classification, name, last_seen
            or None on error
        """
        api_key = self.api_keys.get('greynoise')
        if not api_key:
            return None
        
        try:
            url = f"https://api.greynoise.io/v3/community/{ip}"
            req = urllib.request.Request(
                url,
                headers={
                    'key': api_key,
                    'Accept': 'application/json'
                }
            )
            
            with urllib.request.urlopen(req, timeout=10) as response:
                data = json.loads(response.read().decode('utf-8', errors='replace'))
            
            classification = data.get('classification', 'unknown')
            
            return {
                'detected': classification == 'malicious',
                'noise': data.get('noise', False),
                'riot': data.get('riot', False),
                'classification': classification,
                'name': data.get('name', 'Unknown'),
                'last_seen': data.get('last_seen'),
                'message': data.get('message', ''),
            }
            
        except urllib.error.HTTPError as e:
            # GreyNoise returns 404 for IPs not in their database
            if e.code == 404:
                return {
                    'detected': False,
                    'noise': False,
                    'riot': False,
                    'classification': 'unknown',
                    'name': 'Not in GreyNoise database',
                    'last_seen': None,
                    'message': 'IP not found',
                }
            print(f"[ThreatIntel] GreyNoise API error for {ip}: HTTP {e.code}")
            return None
        except urllib.error.URLError as e:
            print(f"[ThreatIntel] GreyNoise connection error for {ip}: {e.reason}")
            return None
        except Exception as e:
            print(f"[ThreatIntel] GreyNoise error for {ip}: {e}")
            return None
    
    def bulk_check_ips(self, ip_list):
        """
        Bulk check multiple IPs (more efficient)
        
        Returns dict of {ip: result}
        """
        results = {}
        for ip in ip_list:
            results[ip] = self.check_ip(ip)
            # Small delay to respect rate limits
            time.sleep(0.1)
        return results
    
    def add_local_ioc(self, ioc_type, value):
        """Add IOC to local list"""
        if ioc_type == 'ip':
            self.local_iocs['malicious_ips'].add(value)
        elif ioc_type == 'domain':
            self.local_iocs['malicious_domains'].add(value)
        elif ioc_type == 'c2':
            self.local_iocs['c2_indicators'].add(value)
    
    def save_local_iocs(self):
        """Save local IOCs to disk"""
        ioc_file = os.path.join(CACHE_DIR, 'local_iocs.json')
        try:
            data = {
                'ips': list(self.local_iocs['malicious_ips']),
                'domains': list(self.local_iocs['malicious_domains']),
                'c2': list(self.local_iocs['c2_indicators']),
            }
            with open(ioc_file, 'w') as f:
                json.dump(data, f, indent=2)
            # Set secure permissions (owner read/write only)
            os.chmod(ioc_file, 0o600)
        except Exception as e:
            print(f"[Threat Intel] Failed to save IOCs: {e}")


# Global instance
_threat_intel = None

def get_threat_intel():
    """Get global threat intelligence instance"""
    global _threat_intel
    if _threat_intel is None:
        _threat_intel = ThreatIntelligence()
    return _threat_intel


# Convenience functions
def check_ip(ip):
    """Check if IP is malicious"""
    return get_threat_intel().check_ip(ip)


def check_domain(domain):
    """Check if domain is malicious"""
    return get_threat_intel().check_domain(domain)


def add_ioc(ioc_type, value):
    """Add IOC to local list"""
    return get_threat_intel().add_local_ioc(ioc_type, value)


if __name__ == "__main__":
    # Test module
    print("=== Threat Intelligence Module ===")
    print("Testing IP check...")
    
    # Test with example IP
    result = check_ip("8.8.8.8")
    print(f"IP check result: {result}")
    
    # Test with example domain
    domain_result = check_domain("example.com")
    print(f"Domain check result: {domain_result}")
    
    # Test adding local IOC
    add_ioc('ip', '1.2.3.4')
    test_result = check_ip('1.2.3.4')
    print(f"Local IOC test: {test_result}")
    
    print("\n✓ Threat intelligence module ready")
    print("Note: Configure API keys in environment variables or ~/.threat_intel_config.json")
    print("  VT_API_KEY - VirusTotal API key")
    print("  ABUSEIPDB_API_KEY - AbuseIPDB API key")
    print("  GREYNOISE_API_KEY - GreyNoise API key")
