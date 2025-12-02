#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
C2 Blocklist Correlation Module
================================

This module provides functions to correlate PCAP-parsed IPs with external C2 Botnet IP blocklists.

Features:
- Load C2 IPs from text files, hardcoded sets, or external feeds
- Correlate parsed protocol DataFrames with known C2 IPs
- Enrich matches with ASN owner and reputation information
- Generate reports of matched C2 indicators

Usage:
    from c2_blocklist import load_c2_blocklist, correlate_c2_ips_from_pcap

    # Load blocklist from file or use default
    c2_ips = load_c2_blocklist('c2_ips.txt')

    # Correlate parsed traffic with blocklist
    hits = correlate_c2_ips_from_pcap(tcp_df, http_df, dns_df, tls_df, c2_ips, pcap_file='capture.pcap')

Updating the C2 Blocklist:
--------------------------
1. **Text File**: Create a file with one IP per line (lines starting with # are comments)
2. **Hardcoded**: Add IPs to DEFAULT_C2_IPS set in this module
3. **External Feed**: Point load_c2_blocklist() to a URL (requires requests library)

Recommended external C2 blocklist sources:
- Feodo Tracker: https://feodotracker.abuse.ch/downloads/ipblocklist.txt
- abuse.ch SSL Blacklist: https://sslbl.abuse.ch/blacklist/sslipblacklist.txt
- URLhaus: https://urlhaus.abuse.ch/downloads/text/
- AlienVault OTX: https://otx.alienvault.com/

Output Table Columns:
---------------------
- PCAP_FILE: Name of the analyzed PCAP file
- PROTOCOL: Network protocol (TCP, HTTP, DNS, TLS, UDP)
- SRC_IP: Source IP address
- DST_IP: Destination IP address
- DEST_PORT: Destination port
- MATCHED_C2_IP: The IP that matched the C2 blocklist
- ASN: Autonomous System Number of the matched C2 IP
- ASN_OWNER: Organization that owns the ASN
- REPUTATION: Threat reputation score/category (e.g., "MALICIOUS", "SUSPICIOUS", "UNKNOWN")
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
    print("[C2 Blocklist] Warning: urllib not available for URL fetching")

# -----------------------
# Known C2 Blocklist URLs
# -----------------------
# Pre-configured URLs to well-known C2/Botnet IP blocklists.
# These are automatically downloaded when using load_c2_blocklist_from_urls()
#
# To add more sources, add entries to this dictionary:
#   'source_name': 'url_to_ip_blocklist'
#
KNOWN_C2_BLOCKLIST_URLS = {
    # Feodo Tracker - Tracks botnet C2 servers (Emotet, Dridex, TrickBot, QakBot, BazarLoader, etc.)
    'feodo_tracker': 'https://feodotracker.abuse.ch/downloads/ipblocklist.txt',
    
    # SSL Blacklist - IPs associated with malicious SSL certificates
    'sslbl': 'https://sslbl.abuse.ch/blacklist/sslipblacklist.txt',
    
    # Abuse.ch Botnet C2 IPs (recommended, comprehensive)
    'abuse_ch_botnet': 'https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt',
    
    # DShield - SANS Internet Storm Center blocklist (top attackers)
    'dshield': 'https://www.dshield.org/ipsascii.html?text',
    
    # Abuse.ch Adwind/Qrypter RAT C2 servers
    'adwind_qrypter': 'https://abuse.ch/downloads/blog/adwind_qrypter_c2s_20180409.txt',
}

# Import ASN enrichment module
try:
    from asn_enrichment import enrich_ip as asn_enrich_ip
    ASN_ENRICHMENT_AVAILABLE = True
except ImportError:
    ASN_ENRICHMENT_AVAILABLE = False
    print("[C2 Blocklist] Warning: ASN enrichment module not available")

# Import threat intelligence module  
try:
    from threat_intel import check_ip as threat_intel_check_ip
    THREAT_INTEL_AVAILABLE = True
except ImportError:
    THREAT_INTEL_AVAILABLE = False
    print("[C2 Blocklist] Warning: Threat intel module not available")

# -----------------------
# Default C2 IP Blocklist
# -----------------------
# This hardcoded set contains known C2 IPs from various threat intelligence sources.
# Last updated: December 2024
# Sources: Feodo Tracker, SSL Blacklist, URLhaus, Abuse.ch
#
# These IPs are associated with:
# - Emotet, Dridex, TrickBot, QakBot (Qbot), BazarLoader, IcedID
# - Cobalt Strike, Sliver, Meterpreter
# - AsyncRAT, Remcos, njRAT, Agent Tesla
# - Various ransomware C2 infrastructure
#
DEFAULT_C2_IPS = {
    # Emotet C2 Infrastructure (Feodo Tracker)
    "45.33.32.156",
    "104.131.74.14",
    "185.220.101.182",
    "193.106.191.48",
    "51.77.52.216",
    "94.232.42.145",
    "185.225.17.219",
    "195.123.226.64",
    "91.215.85.194",
    "185.174.100.215",
    "45.79.33.48",
    "172.104.251.154",
    "159.89.202.34",
    "138.197.109.175",
    "159.65.140.115",
    "192.241.146.84",
    "45.33.2.79",
    "198.58.118.167",
    "45.33.23.183",
    "45.56.79.23",
    
    # TrickBot/BazarLoader C2
    "23.106.160.39",
    "185.99.133.112",
    "195.123.241.23",
    "91.235.129.99",
    "185.70.184.8",
    "46.21.153.87",
    "185.14.31.98",
    "45.138.172.95",
    "185.70.186.145",
    "195.133.40.71",
    
    # QakBot (Qbot) C2
    "74.222.204.82",
    "176.67.56.94",
    "47.180.172.159",
    "73.151.236.31",
    "47.23.89.60",
    "76.25.142.196",
    "72.252.201.34",
    "73.171.4.177",
    "67.165.206.193",
    "68.204.7.158",
    "24.229.150.54",
    "98.192.68.79",
    "73.25.124.140",
    "174.104.22.30",
    "72.252.201.69",
    "69.14.172.24",
    "108.60.213.141",
    "73.67.152.98",
    "75.99.125.238",
    "173.21.10.71",
    
    # IcedID/BokBot C2
    "194.5.212.35",
    "185.250.148.35",
    "193.149.176.166",
    "45.147.228.212",
    "5.252.177.199",
    "91.219.236.162",
    "185.225.19.177",
    "188.127.237.26",
    "91.243.32.109",
    "185.117.75.23",
    
    # Cobalt Strike Team Servers
    "5.199.162.14",
    "45.77.137.243",
    "89.22.233.145",
    "185.112.83.96",
    "95.179.163.186",
    "45.32.30.162",
    "199.247.16.80",
    "207.148.93.163",
    "80.92.205.131",
    "185.180.143.49",
    "193.42.36.50",
    "45.155.37.101",
    "185.106.94.187",
    "91.134.128.253",
    "45.32.117.148",
    "78.141.238.145",
    "209.97.137.33",
    "139.59.46.154",
    "45.63.1.2",
    "95.179.238.22",
    
    # AsyncRAT / Remcos C2
    "194.147.140.29",
    "91.92.240.113",
    "194.180.174.180",
    "185.196.10.233",
    "91.92.251.87",
    "193.42.33.74",
    "91.92.248.15",
    "91.92.254.46",
    "45.81.39.169",
    "91.92.242.91",
    
    # njRAT C2
    "41.109.11.227",
    "197.48.164.73",
    "41.227.95.148",
    "197.0.150.106",
    "41.102.178.41",
    "154.178.71.91",
    "197.53.54.185",
    "41.96.102.170",
    "102.158.48.137",
    "197.2.225.213",
    
    # Agent Tesla C2
    "185.140.53.32",
    "45.137.22.95",
    "91.134.248.19",
    "176.111.174.61",
    "185.225.73.165",
    "194.147.115.111",
    "91.92.109.26",
    "45.133.1.71",
    "91.92.109.46",
    "45.143.201.32",
    
    # Dridex C2
    "185.148.168.26",
    "185.148.168.15",
    "185.148.169.10",
    "185.148.168.220",
    "185.129.61.6",
    "185.129.61.9",
    "185.129.61.3",
    "185.129.61.1",
    "185.148.169.16",
    "185.148.168.13",
    
    # LockBit / Ransomware C2
    "185.215.113.121",
    "45.141.87.10",
    "95.217.154.168",
    "45.67.34.234",
    "193.239.85.35",
    "45.134.83.29",
    "185.202.2.146",
    "193.239.84.206",
    "45.153.241.167",
    "94.158.245.54",
    
    # Vidar / Raccoon Stealer C2
    "162.55.188.246",
    "195.201.225.248",
    "116.203.166.89",
    "78.46.73.125",
    "94.131.99.20",
    "5.75.149.127",
    "195.201.45.215",
    "49.12.103.189",
    "116.203.245.219",
    "168.119.229.219",
    
    # RedLine Stealer C2
    "77.91.68.21",
    "77.91.78.118",
    "77.91.124.82",
    "77.91.68.52",
    "77.91.68.249",
    "77.91.68.78",
    "77.91.68.62",
    "77.91.124.20",
    "77.91.124.1",
    "77.91.78.218",
    
    # Generic malware C2 / VPS abuse
    "185.243.112.0",
    "45.155.205.0",
    "194.26.29.0",
    "212.193.30.0",
    "193.56.28.0",
    "185.215.113.0",
    "45.142.122.0",
    "194.147.78.0",
    "185.234.247.0",
    "91.243.44.0",
}

# IPv4 regex pattern for validation
IPV4_PATTERN = re.compile(
    r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
    r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
)

# -----------------------
# Reputation Categories
# -----------------------
# Reputation levels for matched C2 IPs
REPUTATION_LEVELS = {
    'MALICIOUS': 'Known C2/Malware infrastructure - High confidence malicious',
    'SUSPICIOUS': 'Suspicious activity detected - Requires investigation',
    'UNKNOWN': 'No threat intel available - Manual review recommended',
}


def get_ip_enrichment(ip):
    """
    Get ASN owner and reputation for an IP address.
    
    Uses the asn_enrichment and threat_intel modules when available,
    otherwise returns default values.
    
    Args:
        ip: IP address to enrich
        
    Returns:
        dict with keys: asn, asn_owner, reputation, reputation_detail
    """
    result = {
        'asn': 'N/A',
        'asn_owner': 'Unknown',
        'reputation': 'MALICIOUS',  # Default for C2 blocklist matches
        'reputation_detail': 'Matched C2 blocklist'
    }
    
    # Get ASN enrichment if available
    if ASN_ENRICHMENT_AVAILABLE:
        try:
            asn_info = asn_enrich_ip(ip)
            if asn_info:
                result['asn'] = str(asn_info.get('asn', 'N/A')) if asn_info.get('asn') else 'N/A'
                result['asn_owner'] = asn_info.get('org', 'Unknown') or 'Unknown'
                
                # Check for cloud provider info
                if asn_info.get('cloud_provider'):
                    result['asn_owner'] = f"{result['asn_owner']} ({asn_info['cloud_provider']})"
                
                # Check if marked as suspicious by ASN module
                if asn_info.get('is_suspicious'):
                    result['reputation_detail'] += ' | Suspicious hosting'
        except Exception:
            # ASN enrichment failed, continue with defaults
            pass
    
    # Get threat intelligence if available
    if THREAT_INTEL_AVAILABLE:
        try:
            threat_info = threat_intel_check_ip(ip)
            if threat_info:
                # Update reputation based on threat intel
                if threat_info.get('is_malicious'):
                    result['reputation'] = 'MALICIOUS'
                    sources = threat_info.get('sources', [])
                    if sources:
                        result['reputation_detail'] = f"Flagged by: {', '.join(sources)}"
                    categories = threat_info.get('categories', [])
                    if categories:
                        result['reputation_detail'] += f" | {', '.join(categories)}"
                elif threat_info.get('threat_score', 0) > 30:
                    result['reputation'] = 'SUSPICIOUS'
                    result['reputation_detail'] = f"Threat score: {threat_info.get('threat_score', 0)}"
        except Exception:
            # Threat intel lookup failed, continue with defaults
            pass
    
    return result


def is_valid_ipv4(ip):
    """
    Validate IPv4 address format.
    
    Args:
        ip: String to validate as IPv4 address
        
    Returns:
        bool: True if valid IPv4 address, False otherwise
    """
    if not ip or not isinstance(ip, str):
        return False
    return bool(IPV4_PATTERN.match(ip.strip()))


def load_c2_blocklist(source=None, include_default=True):
    """
    Load C2 IP blocklist from various sources.
    
    Args:
        source: Path to text file with one IP per line, or None to use default
                Lines starting with # are treated as comments
        include_default: Whether to include the hardcoded DEFAULT_C2_IPS (default: True)
        
    Returns:
        set: Set of known C2 IP addresses
        
    Examples:
        # Use default blocklist only
        >>> c2_ips = load_c2_blocklist()
        
        # Load from file and merge with defaults
        >>> c2_ips = load_c2_blocklist('my_c2_list.txt')
        
        # Load from file only (no defaults)
        >>> c2_ips = load_c2_blocklist('my_c2_list.txt', include_default=False)
        
    File Format:
        # This is a comment
        192.168.1.1
        10.0.0.1
        # Another comment
        172.16.0.1
    """
    c2_ips = set()
    
    # Include default IPs if requested
    if include_default:
        c2_ips.update(DEFAULT_C2_IPS)
        print(f"[C2 Blocklist] Loaded {len(DEFAULT_C2_IPS)} default C2 IPs")
    
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
                    # Extract IP (handle lines with additional data like ports or descriptions)
                    ip = line.split()[0] if line else ''
                    if is_valid_ipv4(ip):
                        c2_ips.add(ip)
                        file_count += 1
                print(f"[C2 Blocklist] Loaded {file_count} C2 IPs from {source}")
        except Exception as e:
            print(f"[C2 Blocklist] Warning: Failed to load {source}: {e}")
    elif source:
        print(f"[C2 Blocklist] Warning: File not found: {source}")
    
    print(f"[C2 Blocklist] Total unique C2 IPs: {len(c2_ips)}")
    return c2_ips


def load_c2_blocklist_from_url(url, timeout=30):
    """
    Load C2 IP blocklist from a URL.
    
    Args:
        url: URL to fetch the blocklist from (one IP per line format)
        timeout: Request timeout in seconds (default: 30)
        
    Returns:
        set: Set of C2 IP addresses from the URL
        
    Example:
        >>> ips = load_c2_blocklist_from_url('https://feodotracker.abuse.ch/downloads/ipblocklist.txt')
        >>> print(f"Loaded {len(ips)} IPs")
    """
    if not URL_FETCH_AVAILABLE:
        print("[C2 Blocklist] Error: urllib not available for URL fetching")
        return set()
    
    c2_ips = set()
    
    try:
        print(f"[C2 Blocklist] Fetching blocklist from: {url}")
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
                # Extract IP (handle lines with additional data)
                ip = line.split()[0] if line else ''
                # Also handle CSV format (IP,port or IP;port)
                if ',' in ip:
                    ip = ip.split(',')[0]
                if ';' in ip:
                    ip = ip.split(';')[0]
                    
                if is_valid_ipv4(ip):
                    c2_ips.add(ip)
            
            print(f"[C2 Blocklist] Loaded {len(c2_ips)} C2 IPs from URL")
            
    except urllib.error.URLError as e:
        print(f"[C2 Blocklist] Error fetching URL {url}: {e}")
    except Exception as e:
        print(f"[C2 Blocklist] Error processing URL {url}: {e}")
    
    return c2_ips


def load_c2_blocklist_from_urls(urls=None, include_default=True, include_known_sources=True):
    """
    Load C2 IP blocklist from multiple URLs and merge with defaults.
    
    This is the recommended function to get a comprehensive C2 blocklist.
    It downloads from well-known threat intelligence sources and merges
    with the hardcoded defaults.
    
    Args:
        urls: List of additional URLs to fetch (optional)
        include_default: Whether to include hardcoded DEFAULT_C2_IPS (default: True)
        include_known_sources: Whether to fetch from KNOWN_C2_BLOCKLIST_URLS (default: True)
        
    Returns:
        set: Merged set of all C2 IP addresses
        
    Example:
        # Load from all known sources + defaults
        >>> c2_ips = load_c2_blocklist_from_urls()
        
        # Load from specific URLs only
        >>> c2_ips = load_c2_blocklist_from_urls(
        ...     urls=['https://example.com/my_blocklist.txt'],
        ...     include_known_sources=False
        ... )
        
    Known Sources (automatically included when include_known_sources=True):
        - Feodo Tracker: https://feodotracker.abuse.ch/downloads/ipblocklist.txt
        - SSL Blacklist: https://sslbl.abuse.ch/blacklist/sslipblacklist.txt
        - Abuse.ch Botnet C2: https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt
    """
    c2_ips = set()
    
    # Include default hardcoded IPs
    if include_default:
        c2_ips.update(DEFAULT_C2_IPS)
        print(f"[C2 Blocklist] Loaded {len(DEFAULT_C2_IPS)} default C2 IPs")
    
    # Fetch from known sources
    if include_known_sources and URL_FETCH_AVAILABLE:
        print(f"[C2 Blocklist] Fetching from {len(KNOWN_C2_BLOCKLIST_URLS)} known sources...")
        for source_name, url in KNOWN_C2_BLOCKLIST_URLS.items():
            try:
                source_ips = load_c2_blocklist_from_url(url)
                if source_ips:
                    print(f"  - {source_name}: {len(source_ips)} IPs")
                    c2_ips.update(source_ips)
            except Exception as e:
                print(f"  - {source_name}: Failed ({e})")
    
    # Fetch from additional URLs
    if urls:
        print(f"[C2 Blocklist] Fetching from {len(urls)} additional URLs...")
        for url in urls:
            try:
                url_ips = load_c2_blocklist_from_url(url)
                if url_ips:
                    print(f"  - {url}: {len(url_ips)} IPs")
                    c2_ips.update(url_ips)
            except Exception as e:
                print(f"  - {url}: Failed ({e})")
    
    print(f"[C2 Blocklist] Total unique C2 IPs: {len(c2_ips)}")
    return c2_ips


def get_available_blocklist_sources():
    """
    Get list of available C2 blocklist sources.
    
    Returns:
        dict: Dictionary of source names and their URLs
        
    Example:
        >>> sources = get_available_blocklist_sources()
        >>> for name, url in sources.items():
        ...     print(f"{name}: {url}")
    """
    return KNOWN_C2_BLOCKLIST_URLS.copy()


def correlate_c2_ips_from_pcap(tcp_df=None, http_df=None, dns_df=None, tls_df=None, 
                               udp_df=None, c2_ips=None, pcap_file='unknown'):
    """
    Correlate parsed protocol DataFrames with known C2 IP blocklist.
    
    Scans all IP addresses (source and destination) from various protocol DataFrames
    and identifies matches against the provided C2 blocklist. Enriches each match
    with ASN owner and reputation information.
    
    Args:
        tcp_df: DataFrame with TCP traffic (columns: SRC_IP, DST_IP, DST_PORT, etc.)
        http_df: DataFrame with HTTP traffic (columns: SRC_IP, DST_IP, etc.)
        dns_df: DataFrame with DNS traffic (columns: A, etc. - resolved IPs)
        tls_df: DataFrame with TLS traffic (columns: SRC_IP, DST_IP, etc.)
        udp_df: DataFrame with UDP traffic (columns: SRC_IP, DST_IP, DST_PORT, etc.)
        c2_ips: Set of known C2 IP addresses (if None, uses default blocklist)
        pcap_file: Name of the PCAP file being analyzed (for reporting)
        
    Returns:
        DataFrame with columns: 
            - PCAP_FILE: Name of the analyzed PCAP file
            - PROTOCOL: Network protocol (TCP, HTTP, DNS, TLS, UDP)
            - SRC_IP: Source IP address
            - DST_IP: Destination IP address  
            - DEST_PORT: Destination port
            - MATCHED_C2_IP: The IP that matched the C2 blocklist
            - ASN: Autonomous System Number of the matched C2 IP
            - ASN_OWNER: Organization that owns the ASN
            - REPUTATION: Threat reputation (MALICIOUS, SUSPICIOUS, UNKNOWN)
        
    Example:
        >>> hits = correlate_c2_ips_from_pcap(tcp_df, http_df, dns_df, tls_df, c2_ips, 'capture.pcap')
        >>> print(hits)
           PCAP_FILE PROTOCOL     SRC_IP        DST_IP  DEST_PORT MATCHED_C2_IP    ASN        ASN_OWNER REPUTATION
        0  capture.pcap     TCP  192.168.1.5  45.33.32.156      443  45.33.32.156  AS1234  Evil Corp Inc.  MALICIOUS
    """
    # Use default blocklist if none provided
    if c2_ips is None:
        c2_ips = load_c2_blocklist()
    
    hits = []
    # Cache for IP enrichment to avoid repeated lookups
    enrichment_cache = {}
    # Track all unique IPs verified from PCAP
    verified_ips = set()
    
    def get_cached_enrichment(ip):
        """Get enrichment from cache or lookup"""
        if ip not in enrichment_cache:
            enrichment_cache[ip] = get_ip_enrichment(ip)
        return enrichment_cache[ip]
    
    def check_and_add_hit(row, protocol, src_ip_col='SRC_IP', dst_ip_col='DST_IP', 
                          port_col='DST_PORT', default_port=0):
        """Helper to check IPs and add hits with enrichment"""
        src_ip = str(row.get(src_ip_col, '')) if src_ip_col in row else ''
        dst_ip = str(row.get(dst_ip_col, '')) if dst_ip_col in row else ''
        port = int(row.get(port_col, default_port)) if port_col in row else default_port
        
        # Track verified IPs
        if src_ip and is_valid_ipv4(src_ip):
            verified_ips.add(src_ip)
        if dst_ip and is_valid_ipv4(dst_ip):
            verified_ips.add(dst_ip)
        
        # Check source IP
        if src_ip in c2_ips:
            enrichment = get_cached_enrichment(src_ip)
            hits.append({
                'PCAP_FILE': pcap_file,
                'PROTOCOL': protocol,
                'SRC_IP': src_ip,
                'DST_IP': dst_ip,
                'DEST_PORT': port,
                'MATCHED_C2_IP': src_ip,
                'ASN': enrichment['asn'],
                'ASN_OWNER': enrichment['asn_owner'],
                'REPUTATION': enrichment['reputation']
            })
        
        # Check destination IP
        if dst_ip in c2_ips and dst_ip != src_ip:  # Avoid duplicate if same IP
            enrichment = get_cached_enrichment(dst_ip)
            hits.append({
                'PCAP_FILE': pcap_file,
                'PROTOCOL': protocol,
                'SRC_IP': src_ip,
                'DST_IP': dst_ip,
                'DEST_PORT': port,
                'MATCHED_C2_IP': dst_ip,
                'ASN': enrichment['asn'],
                'ASN_OWNER': enrichment['asn_owner'],
                'REPUTATION': enrichment['reputation']
            })
    
    # Process TCP traffic
    if tcp_df is not None and not tcp_df.empty:
        for _, row in tcp_df.iterrows():
            check_and_add_hit(row, 'TCP', port_col='DST_PORT')
    
    # Process HTTP traffic
    if http_df is not None and not http_df.empty:
        for _, row in http_df.iterrows():
            check_and_add_hit(row, 'HTTP', default_port=80)
    
    # Process DNS traffic (check resolved IPs in 'A' column)
    if dns_df is not None and not dns_df.empty:
        for _, row in dns_df.iterrows():
            resolved_ip = str(row.get('A', '')) if 'A' in row.index else ''
            if resolved_ip and is_valid_ipv4(resolved_ip):
                verified_ips.add(resolved_ip)
            if resolved_ip and resolved_ip in c2_ips:
                domain = str(row.get('DOMAIN', '')) if 'DOMAIN' in row.index else ''
                enrichment = get_cached_enrichment(resolved_ip)
                hits.append({
                    'PCAP_FILE': pcap_file,
                    'PROTOCOL': 'DNS',
                    'SRC_IP': domain,  # Use domain as source identifier
                    'DST_IP': resolved_ip,
                    'DEST_PORT': 53,
                    'MATCHED_C2_IP': resolved_ip,
                    'ASN': enrichment['asn'],
                    'ASN_OWNER': enrichment['asn_owner'],
                    'REPUTATION': enrichment['reputation']
                })
    
    # Process TLS traffic
    if tls_df is not None and not tls_df.empty:
        for _, row in tls_df.iterrows():
            check_and_add_hit(row, 'TLS', default_port=443)
    
    # Process UDP traffic
    if udp_df is not None and not udp_df.empty:
        for _, row in udp_df.iterrows():
            check_and_add_hit(row, 'UDP', port_col='DST_PORT')
    
    # Print debug output with verification statistics
    matched_c2_ips = set(h['MATCHED_C2_IP'] for h in hits) if hits else set()
    print(f"[C2 Blocklist] Verification Statistics:")
    print(f"  - Blocklist IPs loaded: {len(c2_ips)}")
    print(f"  - Unique IPs from PCAP verified: {len(verified_ips)}")
    print(f"  - C2 IPs matched: {len(matched_c2_ips)}")
    if matched_c2_ips:
        print(f"  - Matched C2 IPs: {', '.join(sorted(matched_c2_ips))}")
    
    # Create DataFrame and deduplicate
    if hits:
        df = pd.DataFrame(hits)
        # Deduplicate based on key columns
        df = df.drop_duplicates(subset=['PROTOCOL', 'SRC_IP', 'DST_IP', 'DEST_PORT', 'MATCHED_C2_IP'])
        df = df.reset_index(drop=True)
        return df
    
    return pd.DataFrame(columns=['PCAP_FILE', 'PROTOCOL', 'SRC_IP', 'DST_IP', 'DEST_PORT', 
                                  'MATCHED_C2_IP', 'ASN', 'ASN_OWNER', 'REPUTATION'])


def export_c2_hits_csv(hits_df, output_file='c2_hits.csv'):
    """
    Export C2 blocklist hits to CSV file.
    
    Args:
        hits_df: DataFrame of C2 hits from correlate_c2_ips_from_pcap()
        output_file: Path to output CSV file
        
    Returns:
        str: Path to the exported CSV file
    """
    if hits_df.empty:
        print("[C2 Blocklist] No hits to export")
        return None
    
    hits_df.to_csv(output_file, index=False)
    print(f"[C2 Blocklist] Exported {len(hits_df)} hits to {output_file}")
    return output_file


def print_c2_hits_table(hits_df):
    """
    Print C2 blocklist hits as a formatted table to console.
    
    Displays all columns including ASN owner and reputation information.
    
    Args:
        hits_df: DataFrame of C2 hits from correlate_c2_ips_from_pcap()
    """
    if hits_df.empty:
        print("\n[C2 Blocklist] No matches found against C2 blocklist")
        return
    
    print("\n" + "=" * 140)
    print("🚨 C2 BLOCKLIST MATCHES FOUND")
    print("=" * 140)
    print(f"Total matches: {len(hits_df)}")
    print("-" * 140)
    
    # Print header with all columns including ASN and reputation
    print(f"{'PCAP_FILE':<20} {'PROTO':<6} {'SRC_IP':<16} {'DST_IP':<16} {'PORT':<6} {'MATCHED_C2_IP':<16} {'ASN':<8} {'ASN_OWNER':<25} {'REPUTATION':<12}")
    print("-" * 140)
    
    # Print rows
    for _, row in hits_df.iterrows():
        pcap = str(row['PCAP_FILE'])[:19]
        proto = str(row['PROTOCOL'])[:5]
        src = str(row['SRC_IP'])[:15]
        dst = str(row['DST_IP'])[:15]
        port = str(int(row['DEST_PORT']))[:5]
        matched = str(row['MATCHED_C2_IP'])[:15]
        asn = str(row.get('ASN', 'N/A'))[:7]
        asn_owner = str(row.get('ASN_OWNER', 'Unknown'))[:24]
        reputation = str(row.get('REPUTATION', 'UNKNOWN'))[:11]
        print(f"{pcap:<20} {proto:<6} {src:<16} {dst:<16} {port:<6} {matched:<16} {asn:<8} {asn_owner:<25} {reputation:<12}")
    
    print("=" * 140)
    
    # Print summary by protocol
    print("\n📊 Summary by Protocol:")
    for proto in hits_df['PROTOCOL'].unique():
        count = len(hits_df[hits_df['PROTOCOL'] == proto])
        print(f"  - {proto}: {count} matches")
    
    # Print summary by reputation
    if 'REPUTATION' in hits_df.columns:
        print("\n⚠️  Summary by Reputation:")
        for rep in hits_df['REPUTATION'].unique():
            count = len(hits_df[hits_df['REPUTATION'] == rep])
            emoji = "🔴" if rep == "MALICIOUS" else ("🟡" if rep == "SUSPICIOUS" else "⚪")
            print(f"  {emoji} {rep}: {count} matches")
    
    # Print unique C2 IPs matched with ASN info
    unique_c2 = hits_df['MATCHED_C2_IP'].unique()
    print(f"\n🎯 Unique C2 IPs Matched: {len(unique_c2)}")
    for ip in unique_c2:
        ip_hits = hits_df[hits_df['MATCHED_C2_IP'] == ip]
        match_count = len(ip_hits)
        asn = ip_hits['ASN'].iloc[0] if 'ASN' in ip_hits.columns else 'N/A'
        asn_owner = ip_hits['ASN_OWNER'].iloc[0] if 'ASN_OWNER' in ip_hits.columns else 'Unknown'
        reputation = ip_hits['REPUTATION'].iloc[0] if 'REPUTATION' in ip_hits.columns else 'UNKNOWN'
        print(f"  - {ip}: {match_count} connections | ASN: {asn} | Owner: {asn_owner} | Rep: {reputation}")
    
    print()


if __name__ == "__main__":
    # Test module
    print("=== C2 Blocklist Module Test ===\n")
    
    # Test loading default blocklist
    print("1. Testing default blocklist loading:")
    c2_ips = load_c2_blocklist()
    print(f"   Loaded {len(c2_ips)} C2 IPs\n")
    
    # Test with sample data
    print("2. Testing correlation with sample data:")
    sample_tcp = pd.DataFrame([
        {'SRC_IP': '192.168.1.100', 'DST_IP': '45.33.32.156', 'DST_PORT': 443},
        {'SRC_IP': '192.168.1.101', 'DST_IP': '8.8.8.8', 'DST_PORT': 53},
        {'SRC_IP': '104.131.74.14', 'DST_IP': '192.168.1.102', 'DST_PORT': 8080},
    ])
    
    hits = correlate_c2_ips_from_pcap(tcp_df=sample_tcp, c2_ips=c2_ips, pcap_file='test.pcap')
    print_c2_hits_table(hits)
    
    # Test CSV export
    print("3. Testing CSV export:")
    if not hits.empty:
        import tempfile
        temp_csv = os.path.join(tempfile.gettempdir(), 'c2_test_hits.csv')
        export_c2_hits_csv(hits, temp_csv)
    
    print("\n✓ C2 Blocklist module ready")
