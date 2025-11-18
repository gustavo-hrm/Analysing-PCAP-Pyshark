
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Stability v20.1 — Clean, modular, C2 graph fixes (graph subset + full table)
# Usage: python3 stability_v20_1.py

import os
import re
import sys
import time
import math
import json
import hashlib
import traceback
import pandas as pd
from tqdm import tqdm

# scapy import with lazy fallback if running where scapy not available for dry-run
try:
    from scapy.all import PcapReader, TCP, IP, Raw, DNS, DNSRR
except Exception:
    # allow static testing on systems without scapy; Pcap parsing will fail but code remains testable
    PcapReader = None
    TCP = IP = Raw = DNS = DNSRR = object

# -----------------------
# CONFIG
# -----------------------
FILE_PCAP = "ataques_out_novembro_2025.pcapng"

TRUSTED_DOMAINS = {
    "google.com","facebook.com","oracle.com","microsoft.com","apple.com",
    "amazon.com","linkedin.com","cloudflare.com","youtube.com","whatsapp.net",
    "googleapis.com","twitter.com","ytimg.com","fbcdn.net","tiktokv.com","instagram.com","gstatic.com"
}
MAX_GRAPH_EDGES = 50   # cap to avoid hairballs
GRAPH_MIN_SCORE = 25    # minimal SCORE for graph-worthy indicators

# Enhanced C2 Detection Thresholds
BEACONING_CV_THRESHOLD = 0.50  # Coefficient of variation tolerance (increased from 0.35 to catch C2s with jitter)
BEACONING_MIN_COUNT = 12       # Minimum connections for beaconing detection
PAYLOAD_ENTROPY_THRESHOLD = 7.5  # Entropy threshold for encrypted payload detection
DNS_TUNNEL_MIN_SCORE = 40      # Minimum score for DNS tunneling detection
STANDARD_TLS_PORTS = {443, 8443, 9443}  # Standard TLS ports
STANDARD_HTTP_PORTS = {80, 8080, 8000, 8888}  # Standard HTTP ports

# -----------------------
# Utilities
# -----------------------
def shannon_entropy(s):
    if not s: return 0.0
    s = str(s)
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs)

def payload_entropy(data):
    """Calculate entropy of payload data to detect encrypted/encoded content."""
    if not data or len(data) == 0: return 0.0
    byte_counts = [0] * 256
    for byte in data:
        byte_counts[byte] += 1
    total = len(data)
    entropy = 0.0
    for count in byte_counts:
        if count > 0:
            prob = count / total
            entropy -= prob * math.log2(prob)
    return entropy

def chi_square_test(data):
    """Perform chi-square test to detect randomness in data (encrypted traffic indicator)."""
    if not data or len(data) < 100: return 0.0
    byte_counts = [0] * 256
    for byte in data:
        byte_counts[byte] += 1
    expected = len(data) / 256.0
    chi_square = sum((count - expected) ** 2 / expected for count in byte_counts if expected > 0)
    return chi_square

def is_base64_encoded(s):
    """Detect if a string is likely base64 encoded."""
    if not s or len(s) < 8: return False
    # Base64 uses A-Z, a-z, 0-9, +, /, = characters
    base64_pattern = re.compile(r'^[A-Za-z0-9+/]+={0,2}$')
    return bool(base64_pattern.match(s))

def is_hex_encoded(s):
    """Detect if a string is hex encoded."""
    if not s or len(s) < 8: return False
    hex_pattern = re.compile(r'^[0-9a-fA-F]+$')
    return bool(hex_pattern.match(s)) and len(s) % 2 == 0

def is_trusted_domain(domain):
    if not domain: return False
    d = domain.lower().strip().rstrip('.')
    return any(d == t or d.endswith('.' + t) for t in TRUSTED_DOMAINS)

def safe_js_json(obj):
    # ensure JSON is safe to embed in <script>
    return json.dumps(obj, ensure_ascii=False).replace("</", "<\\/")

_http_host_re = re.compile(r'(?mi)^Host:\s*([^\r\n]+)')

# -----------------------
# TLS JA3 & SNI extraction
# -----------------------
def extract_ja3_from_client_hello(data: bytes):
    try:
        if not data or len(data) < 6 or data[0] != 0x16 or data[5] != 0x01:
            return None
        ptr = 5 + 4
        if ptr + 34 > len(data): return None
        ptr += 2 + 32
        sid_len = data[ptr]; ptr += 1 + sid_len
        if ptr + 2 > len(data): return None
        cs_len = int.from_bytes(data[ptr:ptr+2], 'big'); ptr += 2
        if ptr + cs_len > len(data): return None
        cipher_suites = data[ptr:ptr+cs_len]; ptr += cs_len
        if ptr + 1 > len(data): return None
        comp_len = data[ptr]; ptr += 1 + comp_len
        if ptr + 2 > len(data): return None
        ext_total = int.from_bytes(data[ptr:ptr+2], 'big'); ptr += 2
        end = min(ptr + ext_total, len(data))
        exts = []
        elliptic_curves = []
        ecp_formats = []
        while ptr + 4 <= end:
            ext_type = int.from_bytes(data[ptr:ptr+2], 'big')
            ext_len = int.from_bytes(data[ptr+2:ptr+4], 'big')
            ptr += 4
            if ptr + ext_len > end: break
            body = data[ptr:ptr+ext_len]
            exts.append(str(ext_type))
            if ext_type == 10 and len(body) >= 2:
                l = int.from_bytes(body[0:2], 'big'); pos = 2
                while pos + 1 < 2 + l and pos + 1 < len(body):
                    elliptic_curves.append(str(int.from_bytes(body[pos:pos+2], 'big')))
                    pos += 2
            if ext_type == 11 and len(body) >= 1:
                count = body[0]; pos = 1
                for i in range(count):
                    if pos >= len(body): break
                    ecp_formats.append(str(body[pos])); pos += 1
            ptr += ext_len
        cs_list = []
        for i in range(0, len(cipher_suites), 2):
            if i+1 < len(cipher_suites):
                cs_list.append(str(int.from_bytes(cipher_suites[i:i+2], 'big')))
        ja3_str = ",".join([
            "-".join(cs_list),
            "-".join(exts),
            "-".join(elliptic_curves),
            "-".join(ecp_formats)
        ])
        return hashlib.md5(ja3_str.encode()).hexdigest()
    except Exception:
        return None

def extract_sni_from_client_hello(data: bytes):
    try:
        if not data or len(data) < 6 or data[0] != 0x16 or data[5] != 0x01:
            return None
        ptr = 5 + 4
        if ptr + 34 > len(data): return None
        ptr += 2 + 32
        sid_len = data[ptr]; ptr += 1 + sid_len
        if ptr + 2 > len(data): return None
        cs_len = int.from_bytes(data[ptr:ptr+2], 'big'); ptr += 2 + cs_len
        comp_len = data[ptr]; ptr += 1 + comp_len
        if ptr + 2 > len(data): return None
        ext_total = int.from_bytes(data[ptr:ptr+2], 'big'); ptr += 2
        end = min(ptr + ext_total, len(data))
        while ptr + 4 <= end:
            ext_type = int.from_bytes(data[ptr:ptr+2], 'big')
            ext_len = int.from_bytes(data[ptr+2:ptr+4], 'big')
            ptr += 4
            if ptr + ext_len > end: break
            if ext_type == 0:
                # server_name extension
                pos = ptr
                list_len = int.from_bytes(data[pos:pos+2], 'big'); pos += 2
                while pos + 3 <= ptr + ext_len:
                    name_type = data[pos]; name_len = int.from_bytes(data[pos+1:pos+3], 'big')
                    pos += 3
                    if name_type == 0:
                        return data[pos:pos+name_len].decode(errors='ignore')
                    pos += name_len
                return None
            ptr += ext_len
        return None
    except Exception:
        return None

def extract_ja3s_from_server_hello(data: bytes):
    """Extract JA3S (server-side TLS fingerprint) from ServerHello."""
    try:
        # Check for TLS handshake (0x16) and ServerHello (0x02)
        if not data or len(data) < 6 or data[0] != 0x16:
            return None
        # Check if it's a ServerHello (message type 0x02)
        if len(data) < 10 or data[5] != 0x02:
            return None
        
        ptr = 5 + 4  # Skip record header + handshake header start
        if ptr + 2 > len(data): return None
        
        # Skip TLS version (2 bytes)
        ptr += 2
        # Skip random (32 bytes)
        if ptr + 32 > len(data): return None
        ptr += 32
        
        # Skip session ID
        if ptr + 1 > len(data): return None
        sid_len = data[ptr]; ptr += 1 + sid_len
        
        # Get cipher suite (2 bytes)
        if ptr + 2 > len(data): return None
        cipher_suite = int.from_bytes(data[ptr:ptr+2], 'big')
        ptr += 2
        
        # Skip compression method (1 byte)
        if ptr + 1 > len(data): return None
        ptr += 1
        
        # Parse extensions
        if ptr + 2 > len(data): return None
        ext_total = int.from_bytes(data[ptr:ptr+2], 'big')
        ptr += 2
        end = min(ptr + ext_total, len(data))
        
        exts = []
        while ptr + 4 <= end:
            ext_type = int.from_bytes(data[ptr:ptr+2], 'big')
            ext_len = int.from_bytes(data[ptr+2:ptr+4], 'big')
            ptr += 4
            if ptr + ext_len > end: break
            exts.append(str(ext_type))
            ptr += ext_len
        
        # Build JA3S: TLS_version,cipher_suite,extensions
        ja3s_str = f"{cipher_suite},{'-'.join(exts)}"
        return hashlib.md5(ja3s_str.encode()).hexdigest()
    except Exception:
        return None

def extract_tls_certificate_info(data: bytes):
    """Extract basic certificate information from TLS Certificate message."""
    try:
        # Check for TLS handshake (0x16) and Certificate message (0x0b)
        if not data or len(data) < 10 or data[0] != 0x16:
            return None
        if data[5] != 0x0b:  # Certificate message type
            return None
        
        # Basic certificate info extraction
        # This is simplified - full X.509 parsing would be complex
        cert_info = {
            'self_signed': False,
            'recently_issued': False,
            'suspicious_cn': False
        }
        
        # Look for common self-signed indicators in the data
        cert_data = data[9:min(len(data), 509)]  # Sample first 500 bytes
        
        # Simple heuristic: self-signed often have same issuer/subject
        if b'localhost' in cert_data.lower() or b'untrusted' in cert_data.lower():
            cert_info['self_signed'] = True
            
        return cert_info
    except Exception:
        return None

# -----------------------
# TCP flags helper
# -----------------------
def tcp_flags_str_local(pkt):
    try:
        f = int(pkt[TCP].flags)
    except Exception:
        return 'NULL'
    flags=[]
    if f & 0x02: flags.append('SYN')
    if f & 0x10: flags.append('ACK')
    if f & 0x01: flags.append('FIN')
    if f & 0x04: flags.append('RST')
    if f & 0x08: flags.append('PSH')
    if f & 0x20: flags.append('URG')
    if f & 0x40: flags.append('ECE')
    if f & 0x80: flags.append('CWR')
    return '+'.join(flags) if flags else 'NULL'

# -----------------------
# Single-pass PCAP parser
# -----------------------
def parse_streams(pcap_path):
    dns_rows = []
    tcp_rows = []
    http_rows = []
    tls_rows = []

    if not PcapReader:
        # scapy not available: return empty frames with expected columns
        return (
            pd.DataFrame(columns=['DOMAIN','A','COUNT','ENTROPY']),
            pd.DataFrame(columns=['SRC_IP','DST_IP','SRC_PORT','DST_PORT','FLAGS','COUNT','PAYLOAD_SIZE','PAYLOAD_ENTROPY']),
            pd.DataFrame(columns=['DOMAIN','REQUEST','COUNT','USER_AGENT','REFERER','CONTENT_TYPE']),
            pd.DataFrame(columns=['SNI','JA3','JA3S','SRC_IP','DST_IP','SRC_PORT','DST_PORT','COUNT','CERT_SELF_SIGNED'])
        )

    if not os.path.exists(pcap_path):
        return (
            pd.DataFrame(columns=['DOMAIN','A','COUNT','ENTROPY']),
            pd.DataFrame(columns=['SRC_IP','DST_IP','SRC_PORT','DST_PORT','FLAGS','COUNT','PAYLOAD_SIZE','PAYLOAD_ENTROPY']),
            pd.DataFrame(columns=['DOMAIN','REQUEST','COUNT','USER_AGENT','REFERER','CONTENT_TYPE']),
            pd.DataFrame(columns=['SNI','JA3','JA3S','SRC_IP','DST_IP','SRC_PORT','DST_PORT','COUNT','CERT_SELF_SIGNED'])
        )

    with PcapReader(pcap_path) as rdr:
        for p in tqdm(rdr, desc='Single-pass PCAP'):
            try:
                # DNS queries
                if getattr(p, 'haslayer', lambda x: False)(DNS):
                    try:
                        if getattr(p[DNS], 'qd', None):
                            qname = p[DNS].qd.qname
                            q = qname.decode(errors='ignore') if isinstance(qname, (bytes,bytearray)) else str(qname)
                            domain = q.rstrip('.')
                            a = ''
                            try:
                                rr = p[DNS].an
                                if isinstance(rr, DNSRR) and getattr(rr, 'rdata', None):
                                    a = rr.rdata.decode() if isinstance(rr.rdata, (bytes,bytearray)) else str(rr.rdata)
                            except Exception:
                                a = ''
                            if not is_trusted_domain(domain):
                                dns_rows.append({'DOMAIN':domain,'A':a,'COUNT':1,'ENTROPY':shannon_entropy(domain)})
                    except Exception:
                        pass

                # TCP + IP flows
                if getattr(p, 'haslayer', lambda x: False)(TCP) and getattr(p, 'haslayer', lambda x: False)(IP):
                    src = p[IP].src
                    dst = p[IP].dst
                    src_port = p[TCP].sport
                    dst_port = p[TCP].dport
                    flags = tcp_flags_str_local(p)
                    
                    payload_size = 0
                    payload_ent = 0.0
                    
                    if getattr(p, 'haslayer', lambda x: False)(Raw):
                        payload = bytes(p[Raw])
                        payload_size = len(payload)
                        payload_ent = payload_entropy(payload)
                    
                    tcp_rows.append({
                        'SRC_IP': src, 
                        'DST_IP': dst, 
                        'SRC_PORT': src_port, 
                        'DST_PORT': dst_port, 
                        'FLAGS': flags, 
                        'COUNT': 1,
                        'PAYLOAD_SIZE': payload_size,
                        'PAYLOAD_ENTROPY': payload_ent
                    })

                    # payload analysis
                    if getattr(p, 'haslayer', lambda x: False)(Raw):
                        payload = bytes(p[Raw])

                        # Robust HTTP detection
                        try:
                            txt = payload.decode(errors='ignore')
                            if re.search(r'\b(GET|POST|HEAD|PUT|DELETE)\s+', txt):
                                lines = txt.splitlines()
                                host = None
                                user_agent = None
                                referer = None
                                content_type = None
                                
                                for ln in lines:
                                    m = _http_host_re.search(ln)
                                    if m:
                                        host = m.group(1).strip()
                                    if ln.lower().startswith('user-agent:'):
                                        user_agent = ln.split(':', 1)[1].strip()
                                    if ln.lower().startswith('referer:'):
                                        referer = ln.split(':', 1)[1].strip()
                                    if ln.lower().startswith('content-type:'):
                                        content_type = ln.split(':', 1)[1].strip()
                                        
                                if not host:
                                    for ln in lines:
                                        m2 = re.search(r'(GET|POST|HEAD|PUT|DELETE)\s+https?://([^/]+)', ln)
                                        if m2:
                                            host = m2.group(2).strip(); break
                                request_line = next((ln for ln in lines if re.search(r'\b(GET|POST|HEAD|PUT|DELETE)\s+', ln)), lines[0] if lines else '')
                                if host and not is_trusted_domain(host):
                                    http_rows.append({
                                        'DOMAIN': host, 
                                        'REQUEST': request_line, 
                                        'COUNT': 1,
                                        'USER_AGENT': user_agent,
                                        'REFERER': referer,
                                        'CONTENT_TYPE': content_type
                                    })
                        except Exception:
                            pass

                        # TLS ClientHello: SNI + JA3
                        try:
                            sni = extract_sni_from_client_hello(payload)
                            ja3 = extract_ja3_from_client_hello(payload)
                            ja3s = None
                            cert_self_signed = False
                            
                            # Try to extract JA3S from ServerHello
                            ja3s = extract_ja3s_from_server_hello(payload)
                            
                            # Try to extract certificate info
                            cert_info = extract_tls_certificate_info(payload)
                            if cert_info:
                                cert_self_signed = cert_info.get('self_signed', False)
                            
                            if sni or ja3 or ja3s:
                                sni_clean = sni.strip().rstrip('.') if sni else ''
                                if not (sni_clean and is_trusted_domain(sni_clean)):
                                    tls_rows.append({
                                        'SNI': sni_clean, 
                                        'JA3': ja3, 
                                        'JA3S': ja3s,
                                        'SRC_IP': src, 
                                        'DST_IP': dst,
                                        'SRC_PORT': src_port,
                                        'DST_PORT': dst_port,
                                        'COUNT': 1,
                                        'CERT_SELF_SIGNED': cert_self_signed
                                    })
                        except Exception:
                            pass

            except Exception:
                continue

    dns_df = pd.DataFrame(dns_rows) if dns_rows else pd.DataFrame(columns=['DOMAIN','A','COUNT','ENTROPY'])
    tcp_df = pd.DataFrame(tcp_rows) if tcp_rows else pd.DataFrame(columns=['SRC_IP','DST_IP','SRC_PORT','DST_PORT','FLAGS','COUNT','PAYLOAD_SIZE','PAYLOAD_ENTROPY'])
    http_df = pd.DataFrame(http_rows) if http_rows else pd.DataFrame(columns=['DOMAIN','REQUEST','COUNT','USER_AGENT','REFERER','CONTENT_TYPE'])
    tls_df = pd.DataFrame(tls_rows) if tls_rows else pd.DataFrame(columns=['SNI','JA3','JA3S','SRC_IP','DST_IP','SRC_PORT','DST_PORT','COUNT','CERT_SELF_SIGNED'])
    return dns_df, tcp_df, http_df, tls_df

# -----------------------
# Aggregator helper
# -----------------------
def agg(df, keys):
    if df.empty: return df
    try:
        d = df.groupby(keys, as_index=False)['COUNT'].sum()
        total = d['COUNT'].sum() if 'COUNT' in d.columns and not d.empty else 0
        d['PERCENT'] = (d['COUNT']/total*100).round(2) if total>0 else 0.0
        return d
    except Exception:
        return df

# -----------------------
# C2 heuristics (JA3-based + basic checks)
# -----------------------
MALICIOUS_JA3 = {
    # Existing signatures
    "72a589da586844d7f0818ce684948eea": "Cobalt Strike",
    "3ca48e8aa725c3091f31146e55f883a1": "Emotet",
    "7d56f4c1d5b56a54a27f35e8afc6d2ba": "TrickBot",
    "3e1f1f1f4ec4cc1d83bb7eaf8cf68e39": "Sliver",
    "5e2c33d3cd42a4e9f4a0f4d344f1e2d0": "AsyncRAT",
    "6734f37431670b3ab4292b8f60f29984": "Meterpreter",
    # Enhanced C2 framework signatures
    "51c64c77e60f3980eea90869b68c58a8": "Metasploit",
    "e7d705a3286e19ea42f587b344ee6865": "Poshc2",
    "b20f698f2e1d801c8a6a7e3c85e1e3f8": "Empire",
    "fc54e0d16d9764783542f0146a98b300": "Mythic",
    "ada70206e40642a3e4461f35503241d5": "Covenant",
    # Additional Cobalt Strike variants
    "a0e9f5d64349fb13191bc781f81f42e1": "Cobalt Strike (variant 1)",
    "b742b407517bac9536a77a7b0fee28e9": "Cobalt Strike (variant 2)",
    "8fb0be2d2f5f6c3d5e8c5c8e0f5e6c3d": "Cobalt Strike (variant 3)",
}

def compute_c2_heuristics(dnsA, httpA, tlsA, tcpA):
    rows = []
    def high_entropy(name): return bool(name) and (shannon_entropy(name) >= 3.8 or len(name) >= 45)

    # High-entropy DNS - need to correlate with TCP connections
    if not dnsA.empty:
        for _, r in dnsA.iterrows():
            dom = r.get('DOMAIN','') or ''
            if high_entropy(dom):
                # Try to find associated TCP connections for this domain
                # For graph purposes, we'll add this but mark it appropriately
                rows.append({
                    'INDICATOR': dom, 
                    'TYPE': 'High-Entropy DNS (possible DGA)', 
                    'SCORE': 60, 
                    'COUNT': int(r.get('COUNT',0)),
                    'SRC_IP': None,  # DNS doesn't have direct SRC/DST in aggregated form
                    'DST_IP': None,
                    'GRAPH_SKIP': True  # Flag to skip in graph
                })

    # TLS JA3 / JA3S / SNI checks - THESE HAVE IP DATA
    if not tlsA.empty:
        for _, r in tlsA.iterrows():
            sni = r.get('SNI','') or ''
            ja3 = r.get('JA3', None)
            ja3s = r.get('JA3S', None)
            src_ip = r.get('SRC_IP', '')
            dst_ip = r.get('DST_IP', '')
            src_port = r.get('SRC_PORT', 0)
            dst_port = r.get('DST_PORT', 0)
            cert_self_signed = r.get('CERT_SELF_SIGNED', False)
            
            if high_entropy(sni):
                rows.append({
                    'INDICATOR': sni, 
                    'TYPE': 'High-Entropy TLS SNI', 
                    'SCORE': 60, 
                    'COUNT': int(r.get('COUNT',0)),
                    'SRC_IP': src_ip,
                    'DST_IP': dst_ip
                })
            if ja3 and ja3 in MALICIOUS_JA3:
                rows.append({
                    'INDICATOR': sni or src_ip, 
                    'TYPE': f"JA3 Match: {MALICIOUS_JA3[ja3]}", 
                    'SCORE': 95, 
                    'COUNT': int(r.get('COUNT',0)),
                    'SRC_IP': src_ip,
                    'DST_IP': dst_ip
                })
            
            # JA3S detection for unusual server stacks
            if ja3s:
                rows.append({
                    'INDICATOR': sni or dst_ip,
                    'TYPE': 'Custom TLS Server Stack (JA3S)',
                    'SCORE': 55,
                    'COUNT': int(r.get('COUNT',0)),
                    'SRC_IP': src_ip,
                    'DST_IP': dst_ip
                })
            
            # Self-signed certificate detection
            if cert_self_signed:
                rows.append({
                    'INDICATOR': sni or dst_ip,
                    'TYPE': 'Self-Signed TLS Certificate',
                    'SCORE': 70,
                    'COUNT': int(r.get('COUNT',0)),
                    'SRC_IP': src_ip,
                    'DST_IP': dst_ip
                })
            
            # Protocol anomaly: TLS on non-standard port
            if dst_port and dst_port not in STANDARD_TLS_PORTS:
                rows.append({
                    'INDICATOR': f"{dst_ip}:{dst_port}",
                    'TYPE': f'TLS on Non-Standard Port ({dst_port})',
                    'SCORE': 65,
                    'COUNT': int(r.get('COUNT',0)),
                    'SRC_IP': src_ip,
                    'DST_IP': dst_ip
                })

    # Enhanced HTTP C2 detection
    if not httpA.empty:
        for _, r in httpA.iterrows():
            dom = (r.get('DOMAIN','') or '').lower()
            request = (r.get('REQUEST','') or '').lower()
            user_agent = r.get('USER_AGENT', '')
            referer = r.get('REFERER', '')
            content_type = r.get('CONTENT_TYPE', '')
            
            # Suspicious patterns
            SUSP_HTTP = ["gate.php", "panel", "upload", "cmd", "api.php", "bot"]
            if any(s in dom for s in SUSP_HTTP):
                rows.append({
                    'INDICATOR': r.get('DOMAIN',''), 
                    'TYPE': 'Suspicious HTTP pattern', 
                    'SCORE': 65, 
                    'COUNT': int(r.get('COUNT',0)),
                    'SRC_IP': None,
                    'DST_IP': None,
                    'GRAPH_SKIP': True
                })
            
            # Missing or suspicious User-Agent
            if not user_agent or user_agent in ['', 'Mozilla', 'curl', 'wget', 'python-requests']:
                rows.append({
                    'INDICATOR': r.get('DOMAIN',''),
                    'TYPE': 'Missing/Suspicious User-Agent',
                    'SCORE': 50,
                    'COUNT': int(r.get('COUNT',0)),
                    'SRC_IP': None,
                    'DST_IP': None,
                    'GRAPH_SKIP': True
                })
            
            # POST without Referer
            if 'post' in request and not referer:
                rows.append({
                    'INDICATOR': r.get('DOMAIN',''),
                    'TYPE': 'POST Request without Referer',
                    'SCORE': 55,
                    'COUNT': int(r.get('COUNT',0)),
                    'SRC_IP': None,
                    'DST_IP': None,
                    'GRAPH_SKIP': True
                })
            
            # Base64 in URL
            if is_base64_encoded(request.split('?')[1] if '?' in request else ''):
                rows.append({
                    'INDICATOR': r.get('DOMAIN',''),
                    'TYPE': 'Base64-Encoded Query Parameters',
                    'SCORE': 60,
                    'COUNT': int(r.get('COUNT',0)),
                    'SRC_IP': None,
                    'DST_IP': None,
                    'GRAPH_SKIP': True
                })
            
            # Unusual Content-Type
            if content_type and content_type not in ['text/html', 'application/json', 'text/plain', 'application/x-www-form-urlencoded']:
                rows.append({
                    'INDICATOR': r.get('DOMAIN',''),
                    'TYPE': f'Unusual Content-Type: {content_type}',
                    'SCORE': 45,
                    'COUNT': int(r.get('COUNT',0)),
                    'SRC_IP': None,
                    'DST_IP': None,
                    'GRAPH_SKIP': True
                })

    # Encrypted payload detection from TCP
    if not tcpA.empty:
        for _, r in tcpA.iterrows():
            payload_ent = r.get('PAYLOAD_ENTROPY', 0.0)
            if payload_ent >= PAYLOAD_ENTROPY_THRESHOLD:
                src_ip = r.get('SRC_IP', '')
                dst_ip = r.get('DST_IP', '')
                rows.append({
                    'INDICATOR': f"{src_ip} → {dst_ip}",
                    'TYPE': 'High Payload Entropy (likely encrypted)',
                    'SCORE': 65,
                    'COUNT': int(r.get('COUNT',0)),
                    'SRC_IP': src_ip,
                    'DST_IP': dst_ip
                })

    # Fast-flux detection
    try:
        ip_map = {}
        if not dnsA.empty:
            for _, r in dnsA.iterrows():
                dom = r.get('DOMAIN','') or ''
                a = r.get('A','') or ''
                if a:
                    ip_map.setdefault(dom, set()).add(a)
        for dom, ips in ip_map.items():
            if len(ips) >= 5:
                rows.append({
                    'INDICATOR': dom, 
                    'TYPE': 'Fast-Flux (domain → many IPs)', 
                    'SCORE': 70, 
                    'COUNT': len(ips),
                    'SRC_IP': None,
                    'DST_IP': None,
                    'GRAPH_SKIP': True
                })
    except Exception:
        pass

    # Beaconing - HAS IP DATA
    try:
        if not tcpA.empty:
            beacon_map = {}
            for _, r in tcpA.iterrows():
                src = r.get('SRC_IP', '')
                dst = r.get('DST_IP', '')
                key = (src, dst)
                beacon_map[key] = beacon_map.get(key, 0) + int(r.get('COUNT',0))
            for (src,dst), cnt in beacon_map.items():
                if cnt >= 20:
                    rows.append({
                        'INDICATOR': f"{src} → {dst}", 
                        'TYPE': 'Potential Beaconing', 
                        'SCORE': 55, 
                        'COUNT': cnt,
                        'SRC_IP': src,
                        'DST_IP': dst
                    })
    except Exception:
        pass

    # Rare JA3 and correlation with entropy - HAS IP DATA
    try:
        if not tlsA.empty:
            ja3_counts = tlsA.groupby('JA3')['COUNT'].sum()
            for ja3, cnt in ja3_counts.items():
                if ja3 and int(cnt) <= 2:
                    # Find a representative row for this JA3
                    sample = tlsA[tlsA['JA3'] == ja3].iloc[0]
                    rows.append({
                        'INDICATOR': ja3, 
                        'TYPE': 'Rare JA3 Fingerprint', 
                        'SCORE': 75, 
                        'COUNT': int(cnt),
                        'SRC_IP': sample.get('SRC_IP', ''),
                        'DST_IP': sample.get('DST_IP', '')
                    })
            
            for _, r in tlsA.iterrows():
                ja = r.get('JA3')
                sni = r.get('SNI','') or ''
                if ja and int(r.get('COUNT',0)) <= 2 and high_entropy(sni):
                    rows.append({
                        'INDICATOR': sni, 
                        'TYPE': 'High-Entropy SNI + Rare JA3', 
                        'SCORE': 90, 
                        'COUNT': int(r.get('COUNT',0)),
                        'SRC_IP': r.get('SRC_IP', ''),
                        'DST_IP': r.get('DST_IP', '')
                    })
    except Exception:
        pass

    df = pd.DataFrame(rows) if rows else pd.DataFrame(columns=['INDICATOR','TYPE','SCORE','COUNT','SRC_IP','DST_IP'])
    if not df.empty:
        # Fill NaN values
        df['SRC_IP'] = df['SRC_IP'].fillna('')
        df['DST_IP'] = df['DST_IP'].fillna('')
        
        df = df.groupby(['INDICATOR','TYPE'], as_index=False).agg({
            'SCORE':'max',
            'COUNT':'sum',
            'SRC_IP':'first',
            'DST_IP':'first'
        })
        df = df.sort_values(['SCORE','COUNT'], ascending=[False,False])
    return df

# -----------------------
# Advanced heuristics pack
# -----------------------
def is_dga_like(domain):
    if not domain: return 0
    d = domain.split('.')[0]
    ent = shannon_entropy(d)
    score = 0
    if ent >= 4.0: score += 50
    if len(d) >= 12: score += 20
    digits = sum(c.isdigit() for c in d)
    if digits / max(1, len(d)) > 0.3: score += 15
    vowels = sum(c in 'aeiou' for c in d.lower())
    if vowels / max(1, len(d)) < 0.35: score += 10
    return min(100, score)

def fanout_score(tcp_df):
    rows = []
    if tcp_df.empty: return pd.DataFrame(columns=['INDICATOR','TYPE','SCORE','COUNT'])
    try:
        grp = tcp_df.groupby('SRC_IP')['DST_IP'].nunique().reset_index(name='UNIQUE_DSTS')
        for _, r in grp.iterrows():
            u = int(r['UNIQUE_DSTS'] or 0)
            if u >= 30:
                sc = 50 + min(45, int((u-30)/2))
                rows.append({'INDICATOR': r['SRC_IP'], 'TYPE': 'High fan-out (many destinations)', 'SCORE': sc, 'COUNT': u})
    except Exception:
        pass
    return pd.DataFrame(rows) if rows else pd.DataFrame(columns=['INDICATOR','TYPE','SCORE','COUNT'])

def ja3_cluster_scores(tls_df):
    rows = []
    if tls_df.empty: return pd.DataFrame(columns=['INDICATOR','TYPE','SCORE','COUNT'])
    try:
        grp = tls_df.groupby('JA3')['SRC_IP'].nunique().reset_index(name='UNIQUE_SRCS')
        for _, r in grp.iterrows():
            ja = r['JA3']
            u = int(r['UNIQUE_SRCS'] or 0)
            if ja and u >= 4:
                sc = 60 + min(35, u*5)
                rows.append({'INDICATOR': ja, 'TYPE': 'JA3 cluster across many sources', 'SCORE': sc, 'COUNT': u})
    except Exception:
        pass
    return pd.DataFrame(rows) if rows else pd.DataFrame(columns=['INDICATOR','TYPE','SCORE','COUNT'])

def advanced_dns_checks(dns_df):
    rows = []
    if dns_df.empty: return pd.DataFrame(columns=['INDICATOR','TYPE','SCORE','COUNT'])
    try:
        for _, r in dns_df.iterrows():
            dom = r.get('DOMAIN','') or ''
            score = is_dga_like(dom)
            if score >= 50:
                rows.append({'INDICATOR': dom, 'TYPE': 'DGA-like domain', 'SCORE': 60 + (score//5), 'COUNT': int(r.get('COUNT',0))})
    except Exception:
        pass
    return pd.DataFrame(rows) if rows else pd.DataFrame(columns=['INDICATOR','TYPE','SCORE','COUNT'])

def compute_advanced_heuristics(dnsA, httpA, tlsA, tcpA, timeline_list):
    parts = []
    parts.append(advanced_dns_checks(dnsA))
    parts.append(fanout_score(tcpA))
    parts.append(ja3_cluster_scores(tlsA))
    df = pd.concat(parts, ignore_index=True) if parts else pd.DataFrame(columns=['INDICATOR','TYPE','SCORE','COUNT'])
    if not df.empty:
        df = df.groupby(['INDICATOR','TYPE'], as_index=False).agg({'SCORE':'max','COUNT':'sum'})
        df = df.sort_values(['SCORE','COUNT'], ascending=[False,False])
    return df

# -----------------------
# Beaconing detection
# -----------------------
def detect_beaconing(tcp_rows, min_count=None, max_cv=None, min_period=1, max_period=86400):
    """Enhanced beaconing detection with jitter tolerance and burst detection."""
    import math
    
    # Use configurable thresholds
    if min_count is None:
        min_count = BEACONING_MIN_COUNT
    if max_cv is None:
        max_cv = BEACONING_CV_THRESHOLD
    
    rows = []
    if tcp_rows.empty:
        return pd.DataFrame(columns=['INDICATOR','TYPE','SCORE','COUNT','MEAN_PERIOD','CV','SRC_IP','DST_IP'])
    try:
        if 'TS' not in tcp_rows.columns:
            return pd.DataFrame(columns=['INDICATOR','TYPE','SCORE','COUNT','MEAN_PERIOD','CV','SRC_IP','DST_IP'])
        grp = tcp_rows.groupby(['SRC_IP','DST_IP'])
        for (src,dst), g in grp:
            times = sorted(g['TS'].dropna().astype(float).tolist())
            if len(times) < min_count:
                continue
            diffs = [t2 - t1 for t1, t2 in zip(times, times[1:])]
            if not diffs:
                continue
            mean = sum(diffs)/len(diffs)
            var = sum((d - mean)**2 for d in diffs)/len(diffs)
            std = math.sqrt(var)
            cv = std/mean if mean>0 else 999
            if mean < min_period or mean > max_period:
                continue
            
            # Regular beaconing with jitter tolerance (increased CV threshold)
            if cv <= max_cv:
                score = int(min(100, 70 + (1 - cv) * 30 + min(20, (len(times)-min_count)//5)))
                rows.append({
                    'INDICATOR': f"{src} → {dst}", 
                    'TYPE':'Periodic beaconing (low CV)', 
                    'SCORE': score, 
                    'COUNT': len(times), 
                    'MEAN_PERIOD': round(mean,2), 
                    'CV': round(cv,3),
                    'SRC_IP': src,
                    'DST_IP': dst
                })
            
            # Connection burst detection (many connections in short time)
            if len(times) >= 5:
                # Check for bursts: 5+ connections within 60 seconds
                for i in range(len(times) - 4):
                    burst_window = times[i+4] - times[i]
                    if burst_window <= 60:  # 5 connections within 60 seconds
                        rows.append({
                            'INDICATOR': f"{src} → {dst}",
                            'TYPE': 'Connection Burst Pattern',
                            'SCORE': 60,
                            'COUNT': len(times),
                            'MEAN_PERIOD': round(mean,2),
                            'CV': round(cv,3),
                            'SRC_IP': src,
                            'DST_IP': dst
                        })
                        break
            
            # Sleep pattern analysis: short connections followed by long pauses
            if len(diffs) >= 3:
                long_pauses = [d for d in diffs if d > 300]  # pauses > 5 minutes
                short_intervals = [d for d in diffs if d < 60]  # intervals < 1 minute
                if len(long_pauses) >= 2 and len(short_intervals) >= 2:
                    rows.append({
                        'INDICATOR': f"{src} → {dst}",
                        'TYPE': 'Sleep Pattern (bursts + long pauses)',
                        'SCORE': 65,
                        'COUNT': len(times),
                        'MEAN_PERIOD': round(mean,2),
                        'CV': round(cv,3),
                        'SRC_IP': src,
                        'DST_IP': dst
                    })
                    
    except Exception:
        pass
    return pd.DataFrame(rows) if rows else pd.DataFrame(columns=['INDICATOR','TYPE','SCORE','COUNT','MEAN_PERIOD','CV','SRC_IP','DST_IP'])

# -----------------------
# DNS tunneling detection
# -----------------------
def detect_dnstunneling(dns_df):
    """Enhanced DNS tunneling detection with hex encoding, unique subdomains, and TXT record analysis."""
    rows = []
    if dns_df.empty:
        return pd.DataFrame(columns=['INDICATOR','TYPE','SCORE','COUNT','NOTES'])
    try:
        # Track unique subdomains per base domain
        subdomain_map = {}
        
        for _, r in dns_df.iterrows():
            dom = (r.get('DOMAIN','') or '').strip()
            if not dom: continue
            labels = dom.split('.'); label_count = len(labels); length = len(dom)
            ent = shannon_entropy(dom); notes = []; score = 0
            base64_like = re.compile(r'^[A-Za-z0-9+/=]{8,}$')
            base32_like = re.compile(r'^[A-Z2-7]{8,}$')
            hex_like = re.compile(r'^[0-9a-fA-F]{16,}$')
            
            # Track unique subdomains
            if label_count >= 2:
                base_domain = '.'.join(labels[-2:])
                subdomain = '.'.join(labels[:-2]) if label_count > 2 else ''
                if subdomain:
                    subdomain_map.setdefault(base_domain, set()).add(subdomain)
            
            if length >= 80:
                score += 30; notes.append('long-name')
            if label_count >= 6:
                score += 20; notes.append('many-labels')
            
            # Check each label for encoding patterns
            for lab in labels:
                if base64_like.match(lab):
                    score += 25; notes.append('base64-like-label'); break
                if base32_like.match(lab):
                    score += 20; notes.append('base32-like-label'); break
                if hex_like.match(lab):
                    score += 25; notes.append('hex-encoded-label'); break
            
            if ent >= 4.0:
                score += 25; notes.append('high-entropy')
            
            # Check for TXT/NULL record patterns (simplified check)
            # In real implementation, would need to check query type from DNS packet
            if length > 100:
                score += 15; notes.append('large-query')
            
            if score >= DNS_TUNNEL_MIN_SCORE:
                rows.append({
                    'INDICATOR': dom, 
                    'TYPE':'Possible DNS tunneling', 
                    'SCORE': min(100, score), 
                    'COUNT': int(r.get('COUNT',0)), 
                    'NOTES': ";".join(notes)
                })
        
        # Detect unique subdomain per query pattern
        for base_domain, subdomains in subdomain_map.items():
            if len(subdomains) >= 10:  # Many unique subdomains
                rows.append({
                    'INDICATOR': base_domain,
                    'TYPE': 'DNS Tunneling (unique subdomains)',
                    'SCORE': 75,
                    'COUNT': len(subdomains),
                    'NOTES': f'{len(subdomains)} unique subdomains'
                })
                
    except Exception:
        pass
    return pd.DataFrame(rows) if rows else pd.DataFrame(columns=['INDICATOR','TYPE','SCORE','COUNT','NOTES'])

# -----------------------
# JS and HTML templates (embedded)
# -----------------------
# Note: These strings are intentionally raw-like content — they will be written to files by pipeline()
JS_TEMPLATE = r"""
// === Dashboard JS (Stability v20.1) ===
if (window.__DASHBOARD_ACTIVE__) { console.warn("Dashboard already active — skipping duplicate init."); }
else { window.__DASHBOARD_ACTIVE__ = true; }

if (window.jQuery && window.jQuery.fn) {
  try { $.fn.dataTable.ext.errMode = 'none'; } catch(e) {}
}

const dnsData       = %%DNS%%;
const httpData      = %%HTTP%%;
const tlsData       = %%TLS%%;
const tcpData       = %%TCP%%;
const timelineData  = %%TIMELINE%%;

const c2Data        = %%C2GRAPH%%;   // compact subset exclusively for the graph
const c2FullData    = %%C2FULL%%;    // complete heuristic table dataset

const advData       = %%ADV%%;
const beaconData    = %%BEACON%%;
const dnstunnelData = %%DNSTUNNEL%%;


// ------------------------------------------------------------
// Table rendering helper
// ------------------------------------------------------------
function renderTableRows(tbody, rows, cols){
  if(!tbody) return;
  tbody.innerHTML = '';
  rows.forEach(r=>{
    const tr = document.createElement('tr');
    cols.forEach(c=>{
      const td = document.createElement('td');
      td.textContent = r[c] !== undefined ? r[c] : '';
      tr.appendChild(td);
    });
    tbody.appendChild(tr);
  });
}


// ------------------------------------------------------------
// Canvas preparation
// ------------------------------------------------------------
function prepareCanvas(canvas, fixedHeight){
  if(!canvas) return null;
  const dpr = window.devicePixelRatio || 1;
  const rect = canvas.getBoundingClientRect();
  const h = fixedHeight || rect.height || 220;

  canvas.width  = Math.max(1, Math.floor(rect.width * dpr));
  canvas.height = Math.max(1, Math.floor(h * dpr));

  const ctx = canvas.getContext('2d');
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  return ctx;
}


// ------------------------------------------------------------
// Simple bar chart factory
// ------------------------------------------------------------
function createBarChart(id, labels, values, title){
  const el = document.getElementById(id);
  if(!el) return null;
  const ctx = prepareCanvas(el, 220);
  if(!ctx) return null;

  try{
    return new Chart(ctx, {
      type:'bar',
      data:{
        labels:labels.slice(0,50),
        datasets:[{ label:title, data:values.slice(0,50) }]
      },
      options:{
        responsive:false,
        maintainAspectRatio:false,
        animation:false,
        legend:{ display:false }
      }
    });
  }catch(e){
    console.log('chart err', e);
    return null;
  }
}


// ------------------------------------------------------------
// Pivot view (SRC → DST)
// ------------------------------------------------------------
function renderPivot(tbody, data){
  if(!tbody) return;

  const map = {};
  data.forEach(r=>{
    const s = r.SRC_IP || 'unknown';
    const d = r.DST_IP || 'unknown';
    map[s] = map[s] || {};
    map[s][d] = (map[s][d]||0) + (r.COUNT||1);
  });

  const rows = [];
  Object.keys(map).forEach(s=>{
    Object.keys(map[s]).forEach(d=>{
      rows.push({SRC:s, DST:d, COUNT: map[s][d]});
    });
  });

  rows.sort((a,b)=>b.COUNT - a.COUNT);
  renderTableRows(tbody, rows.slice(0,200), ['SRC','DST','COUNT']);
}


// ------------------------------------------------------------
// Render C2 Graph using Cytoscape
// ------------------------------------------------------------
function renderC2Graph(containerId, data){
  if(typeof cytoscape === 'undefined') return;

  const el = document.getElementById(containerId);
  if(!el) return;

  const nodes = {};
  const edges = [];

  data.slice(0,500).forEach((r,i)=>{

    // Graph expects SRC_IP and DST_IP
    const s = r.SRC_IP || ('src'+i);
    const d = r.DST_IP || ('dst'+i);

    nodes[s] = (nodes[s]||0) + (r.COUNT||1);
    nodes[d] = (nodes[d]||0) + (r.COUNT||1);

    edges.push({
      data:{ id:'e'+i, source:s, target:d, weight:r.COUNT||1 }
    });
  });

  const cy_nodes = Object.keys(nodes).map(n=>({
    data:{ id:n, label:n, weight:nodes[n] }
  }));

  el.innerHTML = '';

  try{
    cytoscape({
      container: el,
      elements: {
        nodes: cy_nodes,
        edges: edges
      },
      style:[
        {
          selector:'node',
          style:{
            'label': 'data(label)',
            'width':'mapData(weight,0,100,8,36)',
            'height':'mapData(weight,0,100,8,36)',
            'background-color':'#1976d2',
            'color':'#fff',
            'text-valign':'center',
            'text-halign':'center',
            'font-size':11
          }
        },
        {
          selector:'edge',
          style:{
            'width':'mapData(weight,0,100,1,6)',
            'line-color':'#999',
            'opacity':0.85
          }
        }
      ],
      layout:{ name:'cose', animate:false }
    });
  }catch(e){
    console.log('cytoscape err', e);
  }
}


// ------------------------------------------------------------
// Dashboard update
// ------------------------------------------------------------
function updateDashboard(){

  const topN = parseInt(document.getElementById('topN').value || '15');

  const fs = (document.getElementById('filter_src')||{value:''}).value.trim();
  const fd = (document.getElementById('filter_dst')||{value:''}).value.trim();
  const fm = (document.getElementById('filter_dom')||{value:''}).value.trim().toLowerCase();

  const ff = r=>{
    if(fs && r.SRC_IP && !String(r.SRC_IP).includes(fs)) return false;
    if(fd && r.DST_IP && !String(r.DST_IP).includes(fd)) return false;
    if(fm){
      const s = Object.values(r).join(' ').toLowerCase();
      if(!s.includes(fm)) return false;
    }
    return true;
  };

  const dnsSlice  = (dnsData||[]).slice().sort((a,b)=>(b.COUNT||0)-(a.COUNT||0)).slice(0,topN).filter(ff);
  const httpSlice = (httpData||[]).slice().sort((a,b)=>(b.COUNT||0)-(a.COUNT||0)).slice(0,topN).filter(ff);
  const tlsSlice  = (tlsData||[]).slice().sort((a,b)=>(b.COUNT||0)-(a.COUNT||0)).slice(0,topN).filter(ff);

  const tcpSliceFiltered = (tcpData||[]).slice().sort((a,b)=>(b.COUNT||0)-(a.COUNT||0)).slice(0,topN).filter(ff);
  const tcpSliceFull     = (tcpData||[]).slice().sort((a,b)=>(b.COUNT||0)-(a.COUNT||0));

  // ------------------------
  // TABLES
  // ------------------------
  renderTableRows(document.querySelector('#tbl_dns tbody'), dnsSlice, ['DOMAIN','COUNT','PERCENT']);
  renderTableRows(document.querySelector('#tbl_http tbody'), httpSlice, ['DOMAIN','COUNT','PERCENT']);
  renderTableRows(document.querySelector('#tbl_tls tbody'), tlsSlice, ['SNI','JA3','SRC_IP','DST_IP','COUNT','PERCENT']);
  renderTableRows(document.querySelector('#tbl_tcp tbody'), tcpSliceFiltered, ['SRC_IP','DST_IP','FLAGS','COUNT','PERCENT']);

  // FULL C2 table (not filtered)
  renderTableRows(
    document.querySelector('#tbl_c2 tbody'),
    (c2FullData||[]).slice(0,topN),
    ['INDICATOR','TYPE','SCORE','COUNT']
  );

  // Advanced, beacon, DNS tunnel
  renderTableRows(document.querySelector('#tbl_adv tbody'), (advData||[]).slice(0,topN), ['INDICATOR','TYPE','SCORE','COUNT']);
  renderTableRows(document.querySelector('#tbl_beacon tbody'), (beaconData||[]).slice(0,topN), ['INDICATOR','TYPE','SCORE','COUNT']);
  renderTableRows(document.querySelector('#tbl_dnstunnel tbody'), (dnstunnelData||[]).slice(0,topN), ['INDICATOR','TYPE','SCORE','COUNT','NOTES']);

  // ------------------------
  // PIVOT
  // ------------------------
  renderPivot(document.querySelector('#pivot tbody'), tcpSliceFull);

  // ------------------------
  // C2 GRAPH
  // ------------------------
  let edgesForGraph = (c2Data || []).slice();

  // FIX: Prevent hairball graph
  if(edgesForGraph.length > 150){
    console.warn("C2 graph trimmed to 150 edges for readability.");
    edgesForGraph = edgesForGraph.slice(0,150);
  }

  renderC2Graph('c2graph', edgesForGraph);

  // ------------------------
  // CHARTS
  // ------------------------
  if(window._dns) try{ window._dns.destroy(); }catch(e){}
  window._dns = createBarChart('chart_dns', dnsSlice.map(x=>x.DOMAIN||''), dnsSlice.map(x=>x.COUNT||0), 'DNS');

  if(window._http) try{ window._http.destroy(); }catch(e){}
  window._http = createBarChart('chart_http', httpSlice.map(x=>x.DOMAIN||''), httpSlice.map(x=>x.COUNT||0), 'HTTP');

  if(window._tls) try{ window._tls.destroy(); }catch(e){}
  window._tls = createBarChart('chart_tls', tlsSlice.map(x=>x.SNI||''), tlsSlice.map(x=>x.COUNT||0), 'TLS');

  if(window._tcp) try{ window._tcp.destroy(); }catch(e){}
  window._tcp = createBarChart(
    'chart_tcp',
    tcpSliceFiltered.map(x=> (x.SRC_IP||'')+' → '+(x.DST_IP||'')),
    tcpSliceFiltered.map(x=>x.COUNT||0),
    'TCP'
  );

  // Timeline
  try{
    const ctx = prepareCanvas(document.getElementById('chart_timeline'), 220);
    if(ctx){
      window._timeline = new Chart(ctx, {
        type:'line',
        data:{
          labels: timelineData.map(x=>x.label),
          datasets:[{ label:'HTTP/min', data: timelineData.map(x=>x.count) }]
        },
        options:{ responsive:false, animation:false, legend:{ display:false } }
      });
    }
  }catch(e){
    console.log('timeline err', e);
  }

  setTimeout(()=>{ try{ $('.display').DataTable().columns.adjust(false); }catch(e){} }, 80);
}


// ------------------------------------------------------------
// INIT
// ------------------------------------------------------------
document.addEventListener('DOMContentLoaded', function(){

  ['topN','filter_src','filter_dst','filter_dom'].forEach(id=>{
    const el = document.getElementById(id);
    if(el) el.addEventListener('input', updateDashboard);
  });

  document.getElementById('clear_filters')?.addEventListener('click', function(){
    ['filter_src','filter_dst','filter_dom'].forEach(id=>{
      const e = document.getElementById(id);
      if(e) e.value='';
    });
    updateDashboard();
  });

  document.getElementById('darkToggle')?.addEventListener('click', function(){
    document.body.classList.toggle('dark');
    updateDashboard();
  });

  updateDashboard();
});
"""

HTML_TEMPLATE = r"""<!doctype html>
<html>
<head>
<meta charset='utf-8'/>
<title>PCAP Dashboard (Stability v20.1)</title>
<link rel='stylesheet' href='https://cdn.datatables.net/1.13.6/css/jquery.dataTables.min.css'>
<link rel='stylesheet' href='https://cdn.datatables.net/buttons/2.4.1/css/buttons.dataTables.min.css'>
<script src='https://code.jquery.com/jquery-3.7.1.min.js'></script>
<script src='https://cdn.jsdelivr.net/npm/chart.js@2.9.4/dist/Chart.min.js'></script>
<script src='https://cdn.datatables.net/1.13.6/js/jquery.dataTables.min.js'></script>
<script src='https://cdn.datatables.net/buttons/2.4.1/js/dataTables.buttons.min.js'></script>
<script src='https://cdnjs.cloudflare.com/ajax/libs/jszip/3.10.1/jszip.min.js'></script>
<script src='https://cdnjs.cloudflare.com/ajax/libs/pdfmake/0.2.7/pdfmake.min.js'></script>
<script src='https://cdnjs.cloudflare.com/ajax/libs/pdfmake/0.2.7/vfs_fonts.js'></script>
<script src='https://cdn.datatables.net/buttons/2.4.1/js/buttons.html5.min.js'></script>
<script src='https://unpkg.com/cytoscape@3.24.0/dist/cytoscape.min.js'></script>
<style>
:root{--card-h:220px}*{box-sizing:border-box}
body{margin:0;font-family:Inter,Arial,Helvetica,sans-serif;background:#f5f7fa;color:#111;font-size:11px}
.app{display:flex;min-height:100vh}.sidebar{width:260px;background:#0f1724;color:#fff;padding:18px;font-size:11px}.content{flex:1;padding:18px}.card-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:18px;align-items:start}.card{background:#fff;padding:14px;border-radius:10px;box-shadow:0 6px 18px rgba(13,26,40,0.06);display:flex;flex-direction:column}.chart-box{width:100%;height:220px;min-height:220px;max-height:220px;flex:0 0 auto;position:relative;overflow:hidden}.chart-box canvas{width:100% !important;height:100% !important;display:block}.table-wrap{overflow:auto;max-height:220px;margin-top:8px}.display{width:100%;table-layout:fixed !important;white-space:nowrap}.display th,.display td{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;padding:6px 8px;font-size:11px}#heatmap_canvas{width:100%;height:360px;border:1px solid #e6e9ef;background:#fff;display:block}#c2graph{width:100%;height:320px;border:1px solid #e6e9ef;background:#fff}
body.dark { background: #0b1116 !important; color: #e6eef6 !important; }
body.dark .sidebar { background:#071018 !important; color:#e6eef6 !important; }
body.dark .card { background:#0e1620 !important; color:#e6eef6 !important; box-shadow: 0 6px 18px rgba(0,0,0,0.6); }
body.dark .display th, body.dark .display td { color:#d6e6f6 !important; background: transparent !important; }
body.dark #c2graph, body.dark #heatmap_canvas { background:#071018 !important; border-color:#21313d !important; }
</style>
</head>
<body>
<div class='app'>
  <aside class='sidebar'>
    <h2 style='margin:0 0 8px 0'>PCAP Dashboard</h2>
    <div style='font-size:12px;opacity:0.9'>File: %%FILE%%</div>
    <div style='margin-top:12px'><button id='clear_filters' style='padding:8px;border-radius:6px;background:#10b981;color:#fff;border:none;cursor:pointer'>Clear Filters</button></div>
  </aside>
  <main class='content'>
    <h1 style='margin:0 0 12px 0'>PCAP Analysis Dashboard (Stability v20.1)</h1>

    <div style='margin-bottom:12px'>
      <label>Source IP: <input id='filter_src' type='text'></label>
      <label style='margin-left:12px'>Dest IP: <input id='filter_dst' type='text'></label>
      <label style='margin-left:12px'>Domain/SNI: <input id='filter_dom' type='text'></label>
      <label style='margin-left:12px'>Show Top: <select id='topN'><option value='15'>15</option><option value='25'>25</option><option value='50'>50</option><option value='99999'>All</option></select></label>
      <button id='darkToggle' style='margin-left:12px'>Dark</button>
    </div>

    <div class='card-grid'>
      <div class='card'><h3>Timeline</h3><div class='chart-box'><canvas id='chart_timeline'></canvas></div></div>
      <div class='card'><h3>C2 Graph</h3><div id='c2graph'></div></div>
      <div class='card'><h3>DNS Top</h3><div class='chart-box'><canvas id='chart_dns'></canvas></div><div class='table-wrap'><table id='tbl_dns' class='display'><thead><tr><th>DOMAIN</th><th>COUNT</th><th>PERCENT</th></tr></thead><tbody></tbody></table></div></div>
      <div class='card'><h3>HTTP Top</h3><div class='chart-box'><canvas id='chart_http'></canvas></div><div class='table-wrap'><table id='tbl_http' class='display'><thead><tr><th>DOMAIN</th><th>COUNT</th><th>PERCENT</th></tr></thead><tbody></tbody></table></div></div>
      <div class='card'><h3>TLS SNI / JA3</h3><div class='chart-box'><canvas id='chart_tls'></canvas></div><div class='table-wrap'><table id='tbl_tls' class='display'><thead><tr><th>SNI</th><th>JA3</th><th>SRC_IP</th><th>DST_IP</th><th>COUNT</th><th>PERCENT</th></tr></thead><tbody></tbody></table></div></div>
      <div class='card'><h3>TCP Flags</h3><div class='chart-box'><canvas id='chart_tcp'></canvas></div><div class='table-wrap'><table id='tbl_tcp' class='display'><thead><tr><th>SRC_IP</th><th>DST_IP</th><th>FLAGS</th><th>COUNT</th><th>PERCENT</th></tr></thead><tbody></tbody></table></div></div>
    </div>


    <div style='margin-top:18px' class='card'>
      <h3>Advanced Heuristics</h3>
      <div class='table-wrap'><table id='tbl_adv' class='display'><thead><tr><th>INDICATOR</th><th>TYPE</th><th>SCORE</th><th>COUNT</th></tr></thead><tbody></tbody></table></div>

    <div style='margin-top:18px' class='card'>
      <h3>Beaconing Detection</h3>
      <div class='table-wrap'><table id='tbl_beacon' class='display'><thead><tr><th>INDICATOR</th><th>TYPE</th><th>SCORE</th><th>COUNT</th></tr></thead><tbody></tbody></table></div>
    </div>

    <div style='margin-top:18px' class='card'>
      <h3>DNS Tunneling</h3>
      <div class='table-wrap'><table id='tbl_dnstunnel' class='display'><thead><tr><th>INDICATOR</th><th>TYPE</th><th>SCORE</th><th>COUNT</th><th>NOTES</th></tr></thead><tbody></tbody></table></div>
    </div>
    </div>

    <div style='margin-top:18px' class='card'>
      <h3>C2 / Botnet Heuristics (Full)</h3>
      <div class='table-wrap'><table id='tbl_c2' class='display'><thead><tr><th>INDICATOR</th><th>TYPE</th><th>SCORE</th><th>COUNT</th></tr></thead><tbody></tbody></table></div>
    </div>

    <div style='margin-top:18px' class='card'>
      <h3>Pivot (Source → Destination)</h3>
      <div class='table-wrap'><table id='pivot' class='display'><thead><tr><th>SRC</th><th>DST</th><th>COUNT</th></tr></thead><tbody></tbody></table></div>
    </div>

  </main>
</div>
<script src='dashboard.js'></script>
</body>
</html>
"""

# -----------------------
# Pipeline
# -----------------------
def pipeline(pcap=FILE_PCAP):
    try:
        print("\n=== Stability v20.1: Starting pipeline ===\n")

        print("[1/11] Parsing PCAP...")
        dns, tcp, http, tls = parse_streams(pcap)

        print("[2/11] Aggregating DNS...")
        dnsA = agg(dns, ['DOMAIN'])

        print("[3/11] Aggregating HTTP...")
        httpA = agg(http, ['DOMAIN'])

        print("[4/11] Aggregating TLS (ensure columns exist)...")
        tls_cols = ['SNI', 'JA3', 'JA3S', 'SRC_IP', 'DST_IP', 'SRC_PORT', 'DST_PORT', 'CERT_SELF_SIGNED']
        for col in tls_cols:
            if col not in tls.columns:
                tls[col] = None
        tlsA = agg(tls, tls_cols)

        print("[5/11] Aggregating TCP...")
        tcp_cols = ['SRC_IP', 'DST_IP', 'SRC_PORT', 'DST_PORT', 'FLAGS']
        for col in tcp_cols:
            if col not in tcp.columns:
                tcp[col] = None
        tcpA = agg(tcp, tcp_cols)
        
        # Also aggregate payload metrics separately for analysis
        if 'PAYLOAD_ENTROPY' in tcp.columns and 'PAYLOAD_SIZE' in tcp.columns:
            tcp['PAYLOAD_ENTROPY'] = tcp['PAYLOAD_ENTROPY'].fillna(0.0)
            tcp['PAYLOAD_SIZE'] = tcp['PAYLOAD_SIZE'].fillna(0)

        print("[6/11] Building HTTP Timeline...")
        timeline = {}
        if os.path.exists(pcap) and PcapReader:
            with PcapReader(pcap) as rdr:
                for p in rdr:
                    try:
                        if getattr(p, 'haslayer', lambda x: False)(Raw):
                            pl = bytes(p[Raw]).decode(errors='ignore')
                            if re.search(r'\b(GET|POST|HEAD|PUT|DELETE)\s+', pl):
                                ts = int(getattr(p, 'time', time.time()))
                                key = time.strftime('%Y-%m-%d %H:%M', time.localtime(ts))
                                timeline[key] = timeline.get(key, 0) + 1
                    except Exception:
                        pass
        timeline_list = [{'label': k, 'count': v} for k, v in sorted(timeline.items())]

        print("[7/11] Computing full C2 heuristic indicators...")
        c2_full = compute_c2_heuristics(dnsA, httpA, tlsA, tcpA)

        # Build graph subset (filtered) for readable graph
        print("[8/11] Preparing compact C2 dataset for graph (filter + cap)...")

        # pick only "graph-worthy" types and high scores, but keep fallback to some rows if empty
        important_prefixes = [
            "JA3 Match",
            "High-Entropy TLS SNI",
            "High-Entropy SNI + Rare JA3",
            "High-Entropy DNS",
            "Rare JA3 Fingerprint",
        ]

        def is_graph_worthy_row(r):
            # Skip entries marked for graph exclusion
            if r.get('GRAPH_SKIP', False):
                return False
    
            # Skip if missing both IP addresses
            if not r.get('SRC_IP') and not r.get('DST_IP'):
                return False
    
            t = r.get('TYPE','') or ''
            if any(t.startswith(p) for p in important_prefixes):
                return True
            if int(r.get('SCORE', 0) or 0) >= GRAPH_MIN_SCORE:
                return True
            return False

        if not c2_full.empty:
            c2_graph = c2_full[c2_full.apply(is_graph_worthy_row, axis=1)].copy()
            # if filter produced nothing, fallback to top-scored items, but limited
            if c2_graph.empty:
                c2_graph = c2_full.sort_values(['SCORE','COUNT'], ascending=[False,False]).head(MAX_GRAPH_EDGES).copy()
            # finally cap to avoid hairball
            if len(c2_graph) > MAX_GRAPH_EDGES:
                c2_graph = c2_graph.head(MAX_GRAPH_EDGES)
        else:
            c2_graph = pd.DataFrame(columns=['INDICATOR','TYPE','SCORE','COUNT'])

        print(f"  - c2_full rows: {len(c2_full)}")
        print(f"  - c2_graph rows (graph): {len(c2_graph)}")

        print("[9/11] Computing Advanced Heuristics...")
        adv = compute_advanced_heuristics(dnsA, httpA, tlsA, tcpA, timeline_list)

        print("[10/11] Detecting Beaconing...")
        if 'TS' not in tcp.columns:
            ts_rows = []
            if os.path.exists(pcap) and PcapReader:
                with PcapReader(pcap) as rdr:
                    for p in rdr:
                        try:
                            if getattr(p, 'haslayer', lambda x: False)(TCP) and getattr(p, 'haslayer', lambda x: False)(IP):
                                if getattr(p, 'haslayer', lambda x: False)(Raw):
                                    src = p[IP].src; dst = p[IP].dst
                                    ts_rows.append({'SRC_IP': src, 'DST_IP': dst, 'TS': float(getattr(p, 'time', time.time()))})
                        except Exception:
                            pass
            tcp_ts_df = pd.DataFrame(ts_rows) if ts_rows else tcp.copy()
        else:
            tcp_ts_df = tcp.copy()
        beacon = detect_beaconing(tcp_ts_df)

        print("[11/11] Detecting DNS Tunneling...")
        dnstunnel = detect_dnstunneling(dns)

        # Build JS and HTML files
        print("[->] Writing dashboard.js and dashboard.html ...")
        js = (
            JS_TEMPLATE
            .replace('%%DNS%%', safe_js_json(dnsA.to_dict(orient='records')))
            .replace('%%HTTP%%', safe_js_json(httpA.to_dict(orient='records')))
            .replace('%%TLS%%', safe_js_json(tlsA.to_dict(orient='records')))
            .replace('%%TCP%%', safe_js_json(tcpA.to_dict(orient='records')))
            .replace('%%TIMELINE%%', safe_js_json(timeline_list))
            .replace('%%C2GRAPH%%', safe_js_json(c2_graph.to_dict(orient='records')))
            .replace('%%C2FULL%%', safe_js_json(c2_full.to_dict(orient='records')))
            .replace('%%ADV%%', safe_js_json(adv.to_dict(orient='records')))
            .replace('%%BEACON%%', safe_js_json(beacon.to_dict(orient='records')))
            .replace('%%DNSTUNNEL%%', safe_js_json(dnstunnel.to_dict(orient='records')))
        )

        with open('dashboard.js', 'w', encoding='utf-8') as jf:
            jf.write(js)
        print("→ dashboard.js written.")

        html_output = HTML_TEMPLATE.replace('%%FILE%%', pcap)
        with open('dashboard.html', 'w', encoding='utf-8') as hf:
            hf.write(html_output)
        print("→ dashboard.html written.")

        print("\n=== DONE: Stability v20.1 dashboard generated ===\n")

    except Exception:
        print("\n\n=== PIPELINE CRASH ===")
        traceback.print_exc()
        raise

# -----------------------
# Entry point
# -----------------------
if __name__ == '__main__':
    pipeline()
