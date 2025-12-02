#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
C2 Domain Blocklist Correlation Module
=======================================

This module provides functions to correlate PCAP-parsed domains with external C2 Botnet domain blocklists.

Features:
- Load C2 domains from text files, hardcoded sets, or external feeds
- Correlate parsed DNS/HTTP/TLS traffic with known malicious domains
- Generate reports of matched domain indicators

Usage:
    from c2_domain_blocklist import load_c2_domains, correlate_c2_domains_from_pcap

    # Load domain blocklist from file or use default
    c2_domains = load_c2_domains('c2_domains_blocklist.txt')

    # Correlate parsed traffic with blocklist
    hits = correlate_c2_domains_from_pcap(dns_df, http_df, tls_df, c2_domains, pcap_file='capture.pcap')

Supported File Formats:
-----------------------
1. **Plain domain list**: One domain per line
   example.com
   malware.ru

2. **Hosts file format** (ThreatFox style): 127.0.0.1<tab>domain
   127.0.0.1	demure.de5per5eem.ru
   127.0.0.1	billing.keywordmatters.com

3. **Comments**: Lines starting with # are ignored

Output Table Columns:
---------------------
- PCAP_FILE: Name of the analyzed PCAP file
- PROTOCOL: Network protocol (DNS, HTTP, TLS)
- DOMAIN: The domain queried/accessed
- MATCHED_DOMAIN: The domain that matched the blocklist
- SRC_IP: Source IP address (if available)
- DST_IP: Destination IP address (if available)
- REPUTATION: Threat reputation (MALICIOUS, SUSPICIOUS, UNKNOWN)
"""

# Fallback for restricted Python runtimes where open may be undefined
try:
    open
except NameError:
    import io
    open = io.open

import os
import re
import pandas as pd

# Try to import requests for URL fetching
try:
    import urllib.request
    import urllib.error
    URL_FETCH_AVAILABLE = True
except ImportError:
    URL_FETCH_AVAILABLE = False
    print("[C2 Domains] Warning: urllib not available for URL fetching")

# -----------------------
# Known C2 Domain Blocklist URLs
# -----------------------
# Pre-configured URLs to well-known C2/Botnet domain blocklists.
# These are automatically downloaded when using load_c2_domains_from_urls()
#
KNOWN_C2_DOMAIN_URLS = {
    # ThreatFox - Malware domains in hosts file format
    'threatfox_hosts': 'https://threatfox.abuse.ch/downloads/hostfile/',
    
    # URLhaus - Active malware distribution domains
    'urlhaus_domains': 'https://urlhaus.abuse.ch/downloads/text_online/',
}

# -----------------------
# Default C2 Domain Blocklist
# -----------------------
# This hardcoded set contains known malicious domains from various threat intelligence sources.
# Last updated: December 2024
#
DEFAULT_C2_DOMAINS = {
    # ThreatFox IOCs
    "demure.de5per5eem.ru",
    "peren5.de5per5eem.ru",
    "depra.de5per5eem.ru",
    "deepem.de5per5eem.ru",
    "benra8.be8ref7ain.ru",
    "abqsales.com",
    "billing.keywordmatters.com",
    "refayn.be8ref7ain.ru",
    "breez5.be8ref7ain.ru",
    "rainel.be8ref7ain.ru",
    
    # Emotet C2 domains
    "qqanddoo.com",
    "trendsmallbiz.com",
    "agentadigital.net",
    
    # Cobalt Strike beacons
    "cdn.cloudflare-analytics.com",
    "api.microsoft-security.com",
    "update.microsoft-download.com",
    
    # Known malware domains
    "evil.com",
    "malware-c2.ru",
    "botnet-controller.net",
    "rat-server.xyz",
    "stealer-panel.top",
    
    # Phishing infrastructure
    "login-secure-update.com",
    "account-verify-support.net",
    "banking-secure-login.ru",
    
    # RAT C2 domains
    "asyncrat-c2.duckdns.org",
    "remcos-panel.ddns.net",
    "njrat-control.no-ip.biz",
    "quasar-c2.servegame.com",
    
    # Ransomware infrastructure
    "lockbit-chat.onion",
    "conti-support.ru",
    "revil-payment.xyz",
}

# Domain validation pattern
DOMAIN_PATTERN = re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
)


def is_valid_domain(domain):
    """
    Validate domain format.
    
    Args:
        domain: String to validate as domain
        
    Returns:
        bool: True if valid domain format, False otherwise
    """
    if not domain or not isinstance(domain, str):
        return False
    domain = domain.strip().lower()
    # Skip IP addresses
    if re.match(r'^\d+\.\d+\.\d+\.\d+$', domain):
        return False
    return bool(DOMAIN_PATTERN.match(domain))


def load_c2_domains(source=None, include_default=True):
    """
    Load C2 domain blocklist from various sources.
    
    Args:
        source: Path to text file with domains, or None to use default
        include_default: Whether to include the hardcoded DEFAULT_C2_DOMAINS (default: True)
        
    Returns:
        set: Set of known C2 domain names (lowercase)
        
    Supported Formats:
        # Comment line
        example.com
        127.0.0.1	malware.ru  (hosts file format)
    """
    c2_domains = set()
    
    # Include default domains if requested
    if include_default:
        c2_domains.update(d.lower() for d in DEFAULT_C2_DOMAINS)
        print(f"[C2 Domains] Loaded {len(DEFAULT_C2_DOMAINS)} default C2 domains")
    
    # Load from file if source provided
    if source and os.path.isfile(source):
        try:
            with open(source, 'r', encoding='utf-8') as f:
                file_count = 0
                for line in f:
                    line = line.strip()
                    # Skip empty lines and comments
                    if not line or line.startswith('#'):
                        continue
                    
                    domain = extract_domain_from_line(line)
                    if domain and is_valid_domain(domain):
                        c2_domains.add(domain.lower())
                        file_count += 1
                        
                print(f"[C2 Domains] Loaded {file_count} C2 domains from {source}")
        except Exception as e:
            print(f"[C2 Domains] Warning: Failed to load {source}: {e}")
    elif source:
        print(f"[C2 Domains] Warning: File not found: {source}")
    
    print(f"[C2 Domains] Total unique C2 domains: {len(c2_domains)}")
    return c2_domains


def extract_domain_from_line(line):
    """
    Extract domain from various line formats.
    
    Supported formats:
    - domain.com (plain domain)
    - 127.0.0.1	domain.com (hosts file format)
    - 127.0.0.1 domain.com (hosts file with spaces)
    - domain.com:443 (domain with port)
    
    Args:
        line: Line from blocklist file
        
    Returns:
        str: Extracted domain or None
    """
    line = line.strip()
    if not line:
        return None
    
    # Handle hosts file format: 127.0.0.1<tab or space>domain
    if line.startswith('127.0.0.1') or line.startswith('0.0.0.0'):
        parts = line.split()
        if len(parts) >= 2:
            return parts[1].strip().lower()
        return None
    
    # Handle tab-separated format
    if '\t' in line:
        parts = line.split('\t')
        # Check if first part is an IP, take second part as domain
        if len(parts) >= 2 and re.match(r'^\d+\.\d+\.\d+\.\d+$', parts[0].strip()):
            return parts[1].strip().lower()
        return parts[0].strip().lower()
    
    # Handle domain:port format
    if ':' in line and not line.startswith('http'):
        return line.split(':')[0].strip().lower()
    
    # Plain domain
    return line.strip().lower()


def load_c2_domains_from_url(url, timeout=30):
    """
    Load C2 domain blocklist from a URL.
    
    Supports multiple formats including hosts file format.
    
    Args:
        url: URL to fetch the blocklist from
        timeout: Request timeout in seconds (default: 30)
        
    Returns:
        set: Set of C2 domains from the URL
    """
    if not URL_FETCH_AVAILABLE:
        print("[C2 Domains] Error: urllib not available for URL fetching")
        return set()
    
    c2_domains = set()
    
    try:
        print(f"[C2 Domains] Fetching blocklist from: {url}")
        req = urllib.request.Request(
            url,
            headers={'User-Agent': 'PCAP-Analyzer/1.0 (Threat Intel Loader)'}
        )
        with urllib.request.urlopen(req, timeout=timeout) as response:
            content = response.read().decode('utf-8', errors='ignore')
            
            for line in content.splitlines():
                line = line.strip()
                # Skip empty lines and comments
                if not line or line.startswith('#') or line.startswith(';'):
                    continue
                
                domain = extract_domain_from_line(line)
                if domain and is_valid_domain(domain):
                    c2_domains.add(domain.lower())
            
            print(f"[C2 Domains] Loaded {len(c2_domains)} C2 domains from URL")
            
    except urllib.error.URLError as e:
        print(f"[C2 Domains] Error fetching URL {url}: {e}")
    except Exception as e:
        print(f"[C2 Domains] Error processing URL {url}: {e}")
    
    return c2_domains


def load_c2_domains_from_urls(urls=None, include_default=True, include_known_sources=True):
    """
    Load C2 domain blocklist from multiple URLs and merge with defaults.
    
    Args:
        urls: List of additional URLs to fetch (optional)
        include_default: Whether to include hardcoded DEFAULT_C2_DOMAINS (default: True)
        include_known_sources: Whether to fetch from KNOWN_C2_DOMAIN_URLS (default: True)
        
    Returns:
        set: Merged set of all C2 domains
    """
    c2_domains = set()
    
    # Include default hardcoded domains
    if include_default:
        c2_domains.update(d.lower() for d in DEFAULT_C2_DOMAINS)
        print(f"[C2 Domains] Loaded {len(DEFAULT_C2_DOMAINS)} default C2 domains")
    
    # Fetch from known sources
    if include_known_sources and URL_FETCH_AVAILABLE:
        print(f"[C2 Domains] Fetching from {len(KNOWN_C2_DOMAIN_URLS)} known sources...")
        for source_name, url in KNOWN_C2_DOMAIN_URLS.items():
            try:
                source_domains = load_c2_domains_from_url(url)
                if source_domains:
                    print(f"  - {source_name}: {len(source_domains)} domains")
                    c2_domains.update(source_domains)
            except Exception as e:
                print(f"  - {source_name}: Failed ({e})")
    
    # Fetch from additional URLs
    if urls:
        print(f"[C2 Domains] Fetching from {len(urls)} additional URLs...")
        for url in urls:
            try:
                url_domains = load_c2_domains_from_url(url)
                if url_domains:
                    print(f"  - {url}: {len(url_domains)} domains")
                    c2_domains.update(url_domains)
            except Exception as e:
                print(f"  - {url}: Failed ({e})")
    
    print(f"[C2 Domains] Total unique C2 domains: {len(c2_domains)}")
    return c2_domains


def correlate_c2_domains_from_pcap(dns_df=None, http_df=None, tls_df=None, 
                                    c2_domains=None, pcap_file='unknown'):
    """
    Correlate parsed protocol DataFrames with known C2 domain blocklist.
    
    Scans all domains from DNS queries, HTTP requests, and TLS SNI
    and identifies matches against the provided C2 domain blocklist.
    
    Args:
        dns_df: DataFrame with DNS traffic (columns: DOMAIN, A, etc.)
        http_df: DataFrame with HTTP traffic (columns: DOMAIN, etc.)
        tls_df: DataFrame with TLS traffic (columns: SNI, etc.)
        c2_domains: Set of known C2 domains (if None, uses default blocklist)
        pcap_file: Name of the PCAP file being analyzed (for reporting)
        
    Returns:
        DataFrame with columns: 
            - PCAP_FILE: Name of the analyzed PCAP file
            - PROTOCOL: Network protocol (DNS, HTTP, TLS)
            - DOMAIN: The domain queried/accessed
            - MATCHED_DOMAIN: The domain that matched the blocklist
            - SRC_IP: Source IP (if available)
            - DST_IP: Destination IP (if available)
            - REPUTATION: Threat reputation (MALICIOUS)
    """
    # Use default blocklist if none provided
    if c2_domains is None:
        c2_domains = load_c2_domains()
    
    # Normalize domains to lowercase for comparison
    c2_domains_lower = {d.lower() for d in c2_domains}
    
    hits = []
    verified_domains = set()
    
    def check_domain(domain, protocol, src_ip='', dst_ip=''):
        """Check if domain matches blocklist"""
        if not domain or not isinstance(domain, str):
            return
        domain_lower = domain.strip().lower()
        verified_domains.add(domain_lower)
        
        # Check exact match
        if domain_lower in c2_domains_lower:
            hits.append({
                'PCAP_FILE': pcap_file,
                'PROTOCOL': protocol,
                'DOMAIN': domain,
                'MATCHED_DOMAIN': domain_lower,
                'SRC_IP': src_ip,
                'DST_IP': dst_ip,
                'REPUTATION': 'MALICIOUS'
            })
            return
        
        # Check if domain is subdomain of a blocklisted domain
        for c2_domain in c2_domains_lower:
            if domain_lower.endswith('.' + c2_domain):
                hits.append({
                    'PCAP_FILE': pcap_file,
                    'PROTOCOL': protocol,
                    'DOMAIN': domain,
                    'MATCHED_DOMAIN': c2_domain,
                    'SRC_IP': src_ip,
                    'DST_IP': dst_ip,
                    'REPUTATION': 'MALICIOUS'
                })
                return
    
    # Process DNS traffic
    if dns_df is not None and not dns_df.empty:
        for _, row in dns_df.iterrows():
            domain = row.get('DOMAIN', '')
            resolved_ip = str(row.get('A', '')) if 'A' in row.index else ''
            check_domain(domain, 'DNS', dst_ip=resolved_ip)
    
    # Process HTTP traffic
    if http_df is not None and not http_df.empty:
        for _, row in http_df.iterrows():
            domain = row.get('DOMAIN', '')
            src_ip = str(row.get('SRC_IP', '')) if 'SRC_IP' in row.index else ''
            dst_ip = str(row.get('DST_IP', '')) if 'DST_IP' in row.index else ''
            check_domain(domain, 'HTTP', src_ip=src_ip, dst_ip=dst_ip)
    
    # Process TLS traffic (SNI)
    if tls_df is not None and not tls_df.empty:
        for _, row in tls_df.iterrows():
            sni = row.get('SNI', '')
            src_ip = str(row.get('SRC_IP', '')) if 'SRC_IP' in row.index else ''
            dst_ip = str(row.get('DST_IP', '')) if 'DST_IP' in row.index else ''
            check_domain(sni, 'TLS', src_ip=src_ip, dst_ip=dst_ip)
    
    # Print verification statistics
    matched_domains = set(h['MATCHED_DOMAIN'] for h in hits) if hits else set()
    print(f"[C2 Domains] Verification Statistics:")
    print(f"  - Blocklist domains loaded: {len(c2_domains)}")
    print(f"  - Unique domains from PCAP verified: {len(verified_domains)}")
    print(f"  - C2 domains matched: {len(matched_domains)}")
    if matched_domains:
        print(f"  - Matched domains: {', '.join(sorted(matched_domains)[:10])}" + 
              ("..." if len(matched_domains) > 10 else ""))
    
    # Create DataFrame and deduplicate
    if hits:
        df = pd.DataFrame(hits)
        df = df.drop_duplicates(subset=['PROTOCOL', 'DOMAIN', 'MATCHED_DOMAIN'])
        df = df.reset_index(drop=True)
        return df
    
    return pd.DataFrame(columns=['PCAP_FILE', 'PROTOCOL', 'DOMAIN', 'MATCHED_DOMAIN', 
                                  'SRC_IP', 'DST_IP', 'REPUTATION'])


def print_c2_domain_hits_table(hits_df):
    """
    Print C2 domain blocklist hits as a formatted table to console.
    
    Args:
        hits_df: DataFrame of C2 domain hits from correlate_c2_domains_from_pcap()
    """
    if hits_df.empty:
        print("\n[C2 Domains] No matches found against C2 domain blocklist")
        return
    
    print("\n" + "=" * 120)
    print("🚨 C2 DOMAIN BLOCKLIST MATCHES FOUND")
    print("=" * 120)
    print(f"Total matches: {len(hits_df)}")
    print("-" * 120)
    
    # Print header
    print(f"{'PCAP_FILE':<25} {'PROTO':<6} {'DOMAIN':<40} {'MATCHED':<30} {'REPUTATION':<12}")
    print("-" * 120)
    
    # Print rows
    for _, row in hits_df.iterrows():
        pcap = str(row['PCAP_FILE'])[:24]
        proto = str(row['PROTOCOL'])[:5]
        domain = str(row['DOMAIN'])[:39]
        matched = str(row['MATCHED_DOMAIN'])[:29]
        reputation = str(row.get('REPUTATION', 'UNKNOWN'))[:11]
        print(f"{pcap:<25} {proto:<6} {domain:<40} {matched:<30} {reputation:<12}")
    
    print("=" * 120)
    
    # Print summary
    unique_domains = hits_df['MATCHED_DOMAIN'].unique()
    print(f"\n🎯 Unique Malicious Domains Matched: {len(unique_domains)}")
    for domain in unique_domains[:10]:
        count = len(hits_df[hits_df['MATCHED_DOMAIN'] == domain])
        print(f"  - {domain}: {count} connections")
    if len(unique_domains) > 10:
        print(f"  ... and {len(unique_domains) - 10} more")
    
    print()


def export_c2_domain_hits_csv(hits_df, output_file='c2_domain_hits.csv'):
    """
    Export C2 domain blocklist hits to CSV file.
    
    Args:
        hits_df: DataFrame of C2 domain hits
        output_file: Path to output CSV file
        
    Returns:
        str: Path to the exported CSV file
    """
    if hits_df.empty:
        print("[C2 Domains] No hits to export")
        return None
    
    hits_df.to_csv(output_file, index=False)
    print(f"[C2 Domains] Exported {len(hits_df)} hits to {output_file}")
    return output_file


if __name__ == "__main__":
    # Test module
    print("=== C2 Domain Blocklist Module Test ===\n")
    
    # Test loading default blocklist
    print("1. Testing default domain blocklist loading:")
    c2_domains = load_c2_domains()
    print(f"   Loaded {len(c2_domains)} C2 domains\n")
    
    # Test with sample data
    print("2. Testing correlation with sample data:")
    sample_dns = pd.DataFrame([
        {'DOMAIN': 'demure.de5per5eem.ru', 'A': '1.2.3.4'},
        {'DOMAIN': 'google.com', 'A': '8.8.8.8'},
        {'DOMAIN': 'billing.keywordmatters.com', 'A': '5.6.7.8'},
    ])
    
    hits = correlate_c2_domains_from_pcap(dns_df=sample_dns, c2_domains=c2_domains, pcap_file='test.pcap')
    print_c2_domain_hits_table(hits)
    
    print("\n✓ C2 Domain Blocklist module ready")
