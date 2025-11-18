#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Stability v20.4 — Enhanced C2 Detection with HTTP Response + TCP Payload Scanning
# Usage: python3 main.py

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
    from scapy.all import PcapReader, TCP, IP, Raw, DNS, DNSRR, UDP, ICMP
except Exception:
    # allow static testing on systems without scapy; Pcap parsing will fail but code remains testable
    PcapReader = None
    TCP = IP = Raw = DNS = DNSRR = UDP = ICMP = object

# -----------------------
# CONFIG
# -----------------------
FILE_PCAP = "mac_ec2eabb16d15.pcapng"

TRUSTED_DOMAINS = {
    # Major Tech Companies
    "google.com", "googleapis.com", "gstatic.com", "googleusercontent.com", "googlevideo.com", "ggpht.com",
    "facebook.com", "fbcdn.net", "fbsbx.com", "facebook.net",
    "microsoft.com", "windows.com", "live.com", "msn.com", "office.com", "office365.com", "microsoftonline.com",
    "apple.com", "icloud.com", "apple-cloudkit.com", "cdn-apple.com", "mzstatic.com",
    "amazon.com", "amazonaws.com", "cloudfront.net", "aws.amazon.com", "awsstatic.com",
    "twitter.com", "twimg.com", "t.co",
    "linkedin.com", "licdn.com",
    "instagram.com", "cdninstagram.com",
    "youtube.com", "ytimg.com", "youtu.be",
    "whatsapp.net", "whatsapp.com",
    "tiktok.com", "tiktokv.com", "tiktokcdn.com", "byteoversea.com", "musical.ly",
    
    # CDN & Cloud Infrastructure
    "cloudflare.com", "cloudflare.net", "cf-ns.com", "cloudflareinsights.com",
    "akamai.com", "akamai.net", "akamaiedge.net", "akamaitechnologies.com", "akamaitech.net",
    "fastly.com", "fastly.net", "fastlylb.net",
    "edgecast.com", "edgecastcdn.net",
    "azureedge.net", "azure.com", "windowsazure.com",
    "incapsula.com", "imperva.com",
    "maxcdn.com", "bootstrapcdn.com", "stackpathcdn.com",
    
    # Content & Media
    "netflix.com", "nflxvideo.net", "nflxext.com", "nflximg.net", "nflxso.net",
    "spotify.com", "scdn.co", "spotifycdn.com",
    "twitch.tv", "ttvnw.net", "jtvnw.net",
    "vimeo.com", "vimeocdn.com",
    "reddit.com", "redd.it", "redditstatic.com", "redditmedia.com",
    "imgur.com", "imgur.io",
    "soundcloud.com", "sndcdn.com",
    
    # Security & Infrastructure  
    "mozilla.org", "mozilla.com", "mozilla.net", "firefox.com",
    "adobe.com", "adobecc.com", "typekit.net", "adobedtm.com",
    "symantec.com", "verisign.com", "digicert.com", "sectigo.com",
    "letsencrypt.org", "acme.org",
    "oracle.com", "oraclecloud.com",
    
    # Common Services & Collaboration
    "dropbox.com", "dropboxusercontent.com", "dropboxstatic.com",
    "zoom.us", "zoom.com", "zoomgov.com",
    "slack.com", "slack-edge.com", "slack-imgs.com",
    "github.com", "githubusercontent.com", "github.io", "githubassets.com", "githubapp.com",
    "stackoverflow.com", "stackexchange.com", "sstatic.net",
    "wordpress.com", "wp.com", "wordpress.org",
    "shopify.com", "shopifycdn.com",
    "salesforce.com", "force.com", "salesforceliveagent.com",
    
    # Analytics & Ads (legitimate)
    "doubleclick.net", "googlesyndication.com", "googleadservices.com", "googletagmanager.com",
    "analytics.google.com", "google-analytics.com",
    
    # CDN Libraries & Resources
    "jquery.com", "jsdelivr.net", "unpkg.com", "cdnjs.cloudflare.com", "cdnjs.com",
    "fontawesome.com", "fonts.googleapis.com", "fonts.gstatic.com"
}
MAX_GRAPH_EDGES = 50   # cap to avoid hairballs
GRAPH_MIN_SCORE = 25    # minimal SCORE for graph-worthy indicators

# -----------------------
# DDoS Detection Thresholds
# -----------------------
DDOS_SYN_FLOOD_THRESHOLD = 100          # SYN packets
DDOS_SYN_RATIO_THRESHOLD = 10.0         # SYN/ACK ratio
DDOS_UDP_FLOOD_THRESHOLD = 500          # UDP packets/min
DDOS_ICMP_FLOOD_THRESHOLD = 200         # ICMP packets
DDOS_PPS_THRESHOLD = 1000               # Packets per second
DDOS_HTTP_FLOOD_THRESHOLD = 100         # HTTP requests/min
DDOS_AMPLIFICATION_FACTOR = 10.0        # Amplification ratio
DDOS_MULTI_SOURCE_THRESHOLD = 10        # Sources attacking same target
DDOS_SUSTAINED_DURATION = 300           # 5 minutes in seconds
C2_TO_DDOS_CORRELATION_WINDOW = 300     # 5 minute correlation window
DDOS_UDP_FLOOD_PORTS = {53, 123, 161, 1900}  # Common UDP flood ports

# -----------------------
# Utilities
# -----------------------
def shannon_entropy(s):
    if not s: return 0.0
    s = str(s)
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs)

def is_trusted_domain(domain):
    if not domain: return False
    d = domain.lower().strip().rstrip('.')
    return any(d == t or d.endswith('.' + t) for t in TRUSTED_DOMAINS)

def is_private_ip(ip):
    """Check if IP is private (RFC1918) or invalid"""
    if not ip or ':' in ip:  # Skip IPv6 and empty
        return True
    parts = ip.split('.')
    if len(parts) != 4:
        return True
    try:
        octets = [int(p) for p in parts]
        # Validate range
        if any(o < 0 or o > 255 for o in octets):
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
        # 127.0.0.0/8 (localhost)
        if octets[0] == 127:
            return True
        # 0.0.0.0/8 and 255.0.0.0/8
        if octets[0] == 0 or octets[0] == 255:
            return True
        return False
    except:
        return True

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
# ✅ ENHANCED: Single-pass PCAP parser with TCP/HTTP PAYLOAD STORAGE
# -----------------------
def parse_streams(pcap_path):
    dns_rows = []
    tcp_rows = []
    http_rows = []
    tls_rows = []
    # New: DDoS-specific data collection
    udp_rows = []
    icmp_rows = []
    dns_detail_rows = []  # For amplification detection

    if not PcapReader:
        # scapy not available: return empty frames with expected columns
        return (
            pd.DataFrame(columns=['DOMAIN','A','COUNT','ENTROPY']),
            pd.DataFrame(columns=['SRC_IP','DST_IP','FLAGS','COUNT','TS','SIZE','SRC_PORT','DST_PORT','PAYLOAD']),
            pd.DataFrame(columns=['DOMAIN','REQUEST','COUNT','METHOD','TS','SRC_IP','DST_IP','PAYLOAD']),
            pd.DataFrame(columns=['SNI','JA3','SRC_IP','DST_IP','COUNT']),
            pd.DataFrame(columns=['SRC_IP','DST_IP','SRC_PORT','DST_PORT','TS','SIZE']),
            pd.DataFrame(columns=['SRC_IP','DST_IP','ICMP_TYPE','TS','SIZE']),
            pd.DataFrame(columns=['SRC_IP','DST_IP','QUERY_SIZE','RESPONSE_SIZE','DOMAIN','TS'])
        )

    if not os.path.exists(pcap_path):
        return (
            pd.DataFrame(columns=['DOMAIN','A','COUNT','ENTROPY']),
            pd.DataFrame(columns=['SRC_IP','DST_IP','FLAGS','COUNT','TS','SIZE','SRC_PORT','DST_PORT','PAYLOAD']),
            pd.DataFrame(columns=['DOMAIN','REQUEST','COUNT','METHOD','TS','SRC_IP','DST_IP','PAYLOAD']),
            pd.DataFrame(columns=['SNI','JA3','SRC_IP','DST_IP','COUNT']),
            pd.DataFrame(columns=['SRC_IP','DST_IP','SRC_PORT','DST_PORT','TS','SIZE']),
            pd.DataFrame(columns=['SRC_IP','DST_IP','ICMP_TYPE','TS','SIZE']),
            pd.DataFrame(columns=['SRC_IP','DST_IP','QUERY_SIZE','RESPONSE_SIZE','DOMAIN','TS'])
        )

    with PcapReader(pcap_path) as rdr:
        for p in tqdm(rdr, desc='Single-pass PCAP'):
            try:
                ts = float(getattr(p, 'time', time.time()))
                pkt_size = len(p) if hasattr(p, '__len__') else 0
                
                # DNS queries with amplification data
                if getattr(p, 'haslayer', lambda x: False)(DNS):
                    try:
                        if getattr(p[DNS], 'qd', None):
                            qname = p[DNS].qd.qname
                            q = qname.decode(errors='ignore') if isinstance(qname, (bytes,bytearray)) else str(qname)
                            domain = q.rstrip('.')
                            a = ''
                            query_size = 0
                            response_size = 0
                            
                            # Get packet size info for amplification detection
                            if getattr(p, 'haslayer', lambda x: False)(IP):
                                src_ip = p[IP].src
                                dst_ip = p[IP].dst
                                query_size = pkt_size
                                
                                # Check if this is a response (has answer)
                                try:
                                    rr = p[DNS].an
                                    if isinstance(rr, DNSRR) and getattr(rr, 'rdata', None):
                                        a = rr.rdata.decode() if isinstance(rr.rdata, (bytes,bytearray)) else str(rr.rdata)
                                        response_size = pkt_size
                                except Exception:
                                    a = ''
                                
                                # Store DNS detail for amplification analysis
                                dns_detail_rows.append({
                                    'SRC_IP': src_ip,
                                    'DST_IP': dst_ip,
                                    'QUERY_SIZE': query_size if not a else 0,
                                    'RESPONSE_SIZE': response_size,
                                    'DOMAIN': domain,
                                    'TS': ts
                                })
                            
                            if not is_trusted_domain(domain):
                                dns_rows.append({'DOMAIN':domain,'A':a,'COUNT':1,'ENTROPY':shannon_entropy(domain)})
                    except Exception:
                        pass

                # ✅ TCP + IP flows with PAYLOAD STORAGE (ENHANCED)
                if getattr(p, 'haslayer', lambda x: False)(TCP) and getattr(p, 'haslayer', lambda x: False)(IP):
                    src = p[IP].src
                    dst = p[IP].dst
                    src_port = p[TCP].sport
                    dst_port = p[TCP].dport
                    flags = tcp_flags_str_local(p)
                    
                    # ✅ NEW: Extract raw payload from ALL TCP packets
                    raw_payload = ''
                    if getattr(p, 'haslayer', lambda x: False)(Raw):
                        payload_bytes = bytes(p[Raw])
                        raw_payload = payload_bytes.decode(errors='ignore')
                    
                    tcp_rows.append({
                        'SRC_IP':src,
                        'DST_IP':dst,
                        'FLAGS':flags,
                        'COUNT':1,
                        'TS':ts,
                        'SIZE':pkt_size,
                        'SRC_PORT':src_port,
                        'DST_PORT':dst_port,
                        'PAYLOAD':raw_payload[:5000]  # ✅ NEW: Store payload
                    })

                    # HTTP + TLS payload analysis
                    if getattr(p, 'haslayer', lambda x: False)(Raw):
                        payload = bytes(p[Raw])
                        txt = payload.decode(errors='ignore')

                        # ✅ Detect HTTP REQUESTS (enhanced with payload storage)
                        http_match = re.search(r'\b(GET|POST|HEAD|PUT|DELETE)\s+', txt)
                        if http_match:
                            method = http_match.group(1)
                            lines = txt.splitlines()
                            host = None
                            for ln in lines:
                                m = _http_host_re.search(ln)
                                if m:
                                    host = m.group(1).strip(); break
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
                                    'METHOD': method,
                                    'TS': ts,
                                    'SRC_IP': src,
                                    'DST_IP': dst,
                                    'PAYLOAD': txt[:5000]  # ✅ NEW: Store HTTP request payload
                                })
                        
                        # ✅ NEW: Detect HTTP RESPONSES
                        http_response_match = re.search(r'^HTTP/\d\.\d\s+(\d{3})', txt, re.MULTILINE)
                        if http_response_match:
                            status_code = http_response_match.group(1)
                            domain = src  # Server IP sending response
                            
                            if not is_trusted_domain(domain):
                                http_rows.append({
                                    'DOMAIN': domain,
                                    'REQUEST': f'HTTP/{status_code} Response',
                                    'COUNT': 1,
                                    'METHOD': 'RESPONSE',
                                    'TS': ts,
                                    'SRC_IP': src,
                                    'DST_IP': dst,
                                    'PAYLOAD': txt[:5000]  # ✅ NEW: Store HTTP response payload
                                })

                        # TLS ClientHello: SNI + JA3
                        try:
                            sni = extract_sni_from_client_hello(payload)
                            ja3 = extract_ja3_from_client_hello(payload)
                            if sni or ja3:
                                sni_clean = sni.strip().rstrip('.') if sni else ''
                                if not (sni_clean and is_trusted_domain(sni_clean)):
                                    tls_rows.append({'SNI': sni_clean, 'JA3': ja3, 'SRC_IP': src, 'DST_IP': dst, 'COUNT': 1})
                        except Exception:
                            pass
                
                # UDP traffic for flood detection
                if getattr(p, 'haslayer', lambda x: False)(UDP) and getattr(p, 'haslayer', lambda x: False)(IP):
                    src = p[IP].src
                    dst = p[IP].dst
                    src_port = p[UDP].sport
                    dst_port = p[UDP].dport
                    udp_rows.append({
                        'SRC_IP': src,
                        'DST_IP': dst,
                        'SRC_PORT': src_port,
                        'DST_PORT': dst_port,
                        'TS': ts,
                        'SIZE': pkt_size
                    })
                
                # ICMP traffic for flood detection
                if getattr(p, 'haslayer', lambda x: False)(ICMP) and getattr(p, 'haslayer', lambda x: False)(IP):
                    src = p[IP].src
                    dst = p[IP].dst
                    icmp_type = p[ICMP].type if hasattr(p[ICMP], 'type') else 0
                    icmp_rows.append({
                        'SRC_IP': src,
                        'DST_IP': dst,
                        'ICMP_TYPE': icmp_type,
                        'TS': ts,
                        'SIZE': pkt_size
                    })

            except Exception:
                continue

    dns_df = pd.DataFrame(dns_rows) if dns_rows else pd.DataFrame(columns=['DOMAIN','A','COUNT','ENTROPY'])
    tcp_df = pd.DataFrame(tcp_rows) if tcp_rows else pd.DataFrame(columns=['SRC_IP','DST_IP','FLAGS','COUNT','TS','SIZE','SRC_PORT','DST_PORT','PAYLOAD'])
    http_df = pd.DataFrame(http_rows) if http_rows else pd.DataFrame(columns=['DOMAIN','REQUEST','COUNT','METHOD','TS','SRC_IP','DST_IP','PAYLOAD'])
    tls_df = pd.DataFrame(tls_rows) if tls_rows else pd.DataFrame(columns=['SNI','JA3','SRC_IP','DST_IP','COUNT'])
    udp_df = pd.DataFrame(udp_rows) if udp_rows else pd.DataFrame(columns=['SRC_IP','DST_IP','SRC_PORT','DST_PORT','TS','SIZE'])
    icmp_df = pd.DataFrame(icmp_rows) if icmp_rows else pd.DataFrame(columns=['SRC_IP','DST_IP','ICMP_TYPE','TS','SIZE'])
    dns_detail_df = pd.DataFrame(dns_detail_rows) if dns_detail_rows else pd.DataFrame(columns=['SRC_IP','DST_IP','QUERY_SIZE','RESPONSE_SIZE','DOMAIN','TS'])
    
    return dns_df, tcp_df, http_df, tls_df, udp_df, icmp_df, dns_detail_df

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
    "72a589da586844d7f0818ce684948eea": "Cobalt Strike",
    "3ca48e8aa725c3091f31146e55f883a1": "Emotet",
    "7d56f4c1d5b56a54a27f35e8afc6d2ba": "TrickBot",
    "3e1f1f1f4ec4cc1d83bb7eaf8cf68e39": "Sliver",
    "5e2c33d3cd42a4e9f4a0f4d344f1e2d0": "AsyncRAT",
    "6734f37431670b3ab4292b8f60f29984": "Meterpreter",
}

def compute_c2_heuristics(dnsA, httpA, tlsA, tcpA):
    rows = []
    def high_entropy(name): return bool(name) and (shannon_entropy(name) >= 3.8 or len(name) >= 45)

    # High-entropy DNS
    if not dnsA.empty:
        for _, r in dnsA.iterrows():
            dom = r.get('DOMAIN','') or ''
            if high_entropy(dom):
                rows.append({
                    'INDICATOR': dom, 
                    'TYPE': 'High-Entropy DNS (possible DGA)', 
                    'SCORE': 60, 
                    'COUNT': int(r.get('COUNT',0)),
                    'SRC_IP': None,
                    'DST_IP': None,
                    'GRAPH_SKIP': True
                })

    # TLS JA3 / SNI checks
    if not tlsA.empty:
        for _, r in tlsA.iterrows():
            sni = r.get('SNI','') or ''
            ja3 = r.get('JA3', None)
            src_ip = r.get('SRC_IP', '')
            dst_ip = r.get('DST_IP', '')
            
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

    # Beaconing
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

    # Suspicious HTTP patterns
    SUSP_HTTP = ["gate.php", "panel", "upload", "cmd", "api.php", "bot"]
    if not httpA.empty:
        for _, r in httpA.iterrows():
            dom = (r.get('DOMAIN','') or '').lower()
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

    # Rare JA3 and correlation with entropy
    try:
        if not tlsA.empty:
            ja3_counts = tlsA.groupby('JA3')['COUNT'].sum()
            for ja3, cnt in ja3_counts.items():
                if ja3 and int(cnt) <= 2:
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
def detect_beaconing(tcp_rows, min_count=12, max_cv=0.35, min_period=1, max_period=86400):
    import math
    rows = []
    if tcp_rows.empty:
        return pd.DataFrame(columns=['INDICATOR','TYPE','SCORE','COUNT','MEAN_PERIOD','CV'])
    try:
        if 'TS' not in tcp_rows.columns:
            return pd.DataFrame(columns=['INDICATOR','TYPE','SCORE','COUNT','MEAN_PERIOD','CV'])
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
            if cv <= max_cv:
                score = int(min(100, 70 + (1 - cv) * 30 + min(20, (len(times)-min_count)//5)))
                rows.append({'INDICATOR': f"{src} → {dst}", 'TYPE':'Periodic beaconing (low CV)', 'SCORE': score, 'COUNT': len(times), 'MEAN_PERIOD': round(mean,2), 'CV': round(cv,3)})
    except Exception:
        pass
    return pd.DataFrame(rows) if rows else pd.DataFrame(columns=['INDICATOR','TYPE','SCORE','COUNT','MEAN_PERIOD','CV'])

# -----------------------
# DNS tunneling detection
# -----------------------
def detect_dnstunneling(dns_df):
    rows = []
    if dns_df.empty:
        return pd.DataFrame(columns=['INDICATOR','TYPE','SCORE','COUNT','NOTES'])
    try:
        for _, r in dns_df.iterrows():
            dom = (r.get('DOMAIN','') or '').strip()
            if not dom: continue
            labels = dom.split('.'); label_count = len(labels); length = len(dom)
            ent = shannon_entropy(dom); notes = []; score = 0
            base64_like = re.compile(r'^[A-Za-z0-9+/=]{8,}$')
            base32_like = re.compile(r'^[A-Z2-7]{8,}$')
            if length >= 80:
                score += 30; notes.append('long-name')
            if label_count >= 6:
                score += 20; notes.append('many-labels')
            for lab in labels:
                if base64_like.match(lab):
                    score += 25; notes.append('base64-like-label'); break
                if base32_like.match(lab):
                    score += 20; notes.append('base32-like-label'); break
            if ent >= 4.0:
                score += 25; notes.append('high-entropy')
            if score >= 40:
                rows.append({'INDICATOR': dom, 'TYPE':'Possible DNS tunneling', 'SCORE': min(100, score), 'COUNT': int(r.get('COUNT',0)), 'NOTES': ";".join(notes)})
    except Exception:
        pass
    return pd.DataFrame(rows) if rows else pd.DataFrame(columns=['INDICATOR','TYPE','SCORE','COUNT','NOTES'])

# -----------------------
# ✅ ENHANCED: HTTP C2 Target Distribution Detection (with PAYLOAD support)
# -----------------------
def detect_http_target_distribution(http_df, tcp_df):
    """Detect HTTP C2 servers distributing target IP lists to bots"""
    rows = []
    if http_df.empty:
        return pd.DataFrame(columns=['C2_SERVER','BOT_COUNT','EXTRACTED_IPS','TARGETS_DISTRIBUTED','PAYLOAD_SAMPLE','TARGETS_ATTACKED','CORRELATION_SCORE','TIME_TO_ATTACK','SCORE'])
    
    try:
        c2_commands = {}
        ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        
        for _, row in http_df.iterrows():
            domain = row.get('DOMAIN', '') or ''
            if not domain or is_trusted_domain(domain):
                continue
            
            # ✅ FIX: Search in both REQUEST and PAYLOAD columns
            request = row.get('REQUEST', '') or ''
            payload = row.get('PAYLOAD', '') or ''  # ✅ NEW: Get full payload
            
            src_ip = row.get('SRC_IP', '') or ''
            
            # ✅ Search in both request and full payload
            search_text = request + '\n' + payload
            
            # Extract all IPs from search_text
            all_ips = ip_pattern.findall(search_text)
            
            # Filter to keep only public IPs
            public_ips = [ip for ip in all_ips if not is_private_ip(ip)]
            
            # Only consider if we found at least 1 public IP
            if len(public_ips) >= 1:
                # ✅ NEW: Debug output
                print(f"[DEBUG HTTP] Found {len(public_ips)} public IPs in HTTP payload from {domain}")
                print(f"[DEBUG HTTP] Sample IPs: {public_ips[:5]}")
                
                if domain not in c2_commands:
                    c2_commands[domain] = {
                        'bots': set(),
                        'targets': set(),
                        'payload_sample': payload[:500],  # Keep first 500 chars
                        'timestamps': []
                    }
                
                c2_commands[domain]['bots'].add(src_ip)
                c2_commands[domain]['targets'].update(public_ips)
                if 'TS' in row:
                    c2_commands[domain]['timestamps'].append(row['TS'])
        
        # Correlate with actual attacks in TCP traffic
        for c2_server, data in c2_commands.items():
            bot_count = len(data['bots'])
            all_distributed_targets = data['targets']
            payload_sample = data['payload_sample']
            
            # Check if distributed IPs were actually attacked
            targets_attacked = set()
            correlation_score = 0
            time_to_attack = 0
            
            if not tcp_df.empty and 'DST_IP' in tcp_df.columns:
                tcp_dsts = set(tcp_df['DST_IP'].dropna().unique())
                targets_attacked = all_distributed_targets.intersection(tcp_dsts)
                
                if len(all_distributed_targets) > 0:
                    correlation_score = int((len(targets_attacked) / len(all_distributed_targets)) * 100)
                
                if data['timestamps'] and 'TS' in tcp_df.columns:
                    c2_time = min(data['timestamps'])
                    attack_times = []
                    for target in targets_attacked:
                        target_attacks = tcp_df[tcp_df['DST_IP'] == target]
                        if not target_attacks.empty and 'TS' in target_attacks.columns:
                            attack_times.extend(target_attacks['TS'].dropna().tolist())
                    
                    if attack_times:
                        first_attack = min(attack_times)
                        time_to_attack = int(first_attack - c2_time) if first_attack > c2_time else 0
            
            # Calculate threat score
            score = 50  # Base score
            score += min(30, bot_count * 5)  # More bots = higher score
            score += min(20, correlation_score // 5)  # High correlation = higher score
            score = min(100, score)
            
            rows.append({
                'C2_SERVER': c2_server,
                'BOT_COUNT': bot_count,
                'EXTRACTED_IPS': len(all_distributed_targets),
                'TARGETS_DISTRIBUTED': ", ".join(sorted(list(all_distributed_targets))[:10]),
                'PAYLOAD_SAMPLE': payload_sample[:300],
                'TARGETS_ATTACKED': len(targets_attacked),
                'CORRELATION_SCORE': correlation_score,
                'TIME_TO_ATTACK': f"{time_to_attack}s" if time_to_attack > 0 else "N/A",
                'SCORE': score
            })
        
    except Exception:
        pass
    
    return pd.DataFrame(rows) if rows else pd.DataFrame(columns=['C2_SERVER','BOT_COUNT','EXTRACTED_IPS','TARGETS_DISTRIBUTED','PAYLOAD_SAMPLE','TARGETS_ATTACKED','CORRELATION_SCORE','TIME_TO_ATTACK','SCORE'])

# -----------------------
# ✅ NEW: TCP IP Distribution Detection (Generic - All Protocols)
# -----------------------
def detect_tcp_ip_distribution(tcp_df):
    """Detect IP address lists in ALL TCP payloads (HTTP and non-HTTP)"""
    rows = []
    if tcp_df.empty or 'PAYLOAD' not in tcp_df.columns:
        return pd.DataFrame(columns=['SRC_IP','DST_IP','SRC_PORT','DST_PORT','EXTRACTED_IPS','IPS_FOUND','PAYLOAD_SAMPLE','SCORE'])
    
    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    
    for _, row in tcp_df.iterrows():
        payload = row.get('PAYLOAD', '') or ''
        if not payload or len(payload) < 20:
            continue
        
        # Extract all IPs from payload
        all_ips = ip_pattern.findall(payload)
        
        # Filter to public IPs only
        public_ips = [ip for ip in all_ips if not is_private_ip(ip)]
        
        # Flag if 5+ public IPs found (likely a target list)
        if len(public_ips) >= 5:
            src_ip = row.get('SRC_IP', '')
            dst_ip = row.get('DST_IP', '')
            src_port = row.get('SRC_PORT', 0)
            dst_port = row.get('DST_PORT', 0)
            
            print(f"[DEBUG TCP] Found {len(public_ips)} public IPs in TCP payload")
            print(f"[DEBUG TCP] Connection: {src_ip}:{src_port} → {dst_ip}:{dst_port}")
            print(f"[DEBUG TCP] Sample IPs: {public_ips[:10]}")
            print(f"[DEBUG TCP] Payload preview: {payload[:200]}")
            
            score = 50 + min(45, len(public_ips))  # Score 50-95 based on IP count
            
            rows.append({
                'SRC_IP': src_ip,
                'DST_IP': dst_ip,
                'SRC_PORT': src_port,
                'DST_PORT': dst_port,
                'EXTRACTED_IPS': len(public_ips),
                'IPS_FOUND': ', '.join(public_ips[:20]),  # Show first 20
                'PAYLOAD_SAMPLE': payload[:500],
                'SCORE': score
            })
    
    return pd.DataFrame(rows) if rows else pd.DataFrame(columns=['SRC_IP','DST_IP','SRC_PORT','DST_PORT','EXTRACTED_IPS','IPS_FOUND','PAYLOAD_SAMPLE','SCORE'])
	# -----------------------
# DDoS Detection Functions
# -----------------------

def detect_syn_flood(tcp_df):
    """Detect SYN flood attacks by analyzing SYN/ACK ratios"""
    rows = []
    if tcp_df.empty or 'FLAGS' not in tcp_df.columns:
        return pd.DataFrame(columns=['INDICATOR','TYPE','SCORE','COUNT','SRC_IP','DST_IP','SYN_RATIO','PPS'])
    
    try:
        for (src, dst), group in tcp_df.groupby(['SRC_IP', 'DST_IP']):
            syn_count = len(group[group['FLAGS'].str.contains('SYN', na=False) & ~group['FLAGS'].str.contains('ACK', na=False)])
            ack_count = len(group[group['FLAGS'].str.contains('ACK', na=False)])
            total_count = len(group)
            
            syn_ratio = syn_count / max(1, ack_count)
            
            if syn_count >= DDOS_SYN_FLOOD_THRESHOLD and syn_ratio >= DDOS_SYN_RATIO_THRESHOLD:
                pps = 0
                if 'TS' in group.columns:
                    times = group['TS'].dropna()
                    if len(times) > 1:
                        duration = times.max() - times.min()
                        pps = int(total_count / max(1, duration))
                
                score = min(95, 80 + int(min(15, (syn_count - DDOS_SYN_FLOOD_THRESHOLD) / 50)))
                
                rows.append({
                    'INDICATOR': f'{src} → {dst}',
                    'TYPE': 'SYN Flood Attack',
                    'SCORE': score,
                    'COUNT': syn_count,
                    'SRC_IP': src,
                    'DST_IP': dst,
                    'SYN_RATIO': round(syn_ratio, 2),
                    'PPS': pps
                })
    except Exception:
        pass
    
    return pd.DataFrame(rows) if rows else pd.DataFrame(columns=['INDICATOR','TYPE','SCORE','COUNT','SRC_IP','DST_IP','SYN_RATIO','PPS'])


def detect_udp_flood(udp_df):
    """Detect UDP flood attacks based on packet rate per source"""
    rows = []
    if udp_df.empty:
        return pd.DataFrame(columns=['INDICATOR','TYPE','SCORE','COUNT','SRC_IP','DST_IP','PPS','TARGET_PORT'])
    
    try:
        for (src, dst), group in udp_df.groupby(['SRC_IP', 'DST_IP']):
            packet_count = len(group)
            
            pps = 0
            duration = 1
            if 'TS' in group.columns:
                times = group['TS'].dropna()
                if len(times) > 1:
                    duration = times.max() - times.min()
                    pps = int(packet_count / max(1, duration))
            
            ppm = int(pps * 60) if pps > 0 else packet_count
            
            if ppm >= DDOS_UDP_FLOOD_THRESHOLD:
                target_ports = group['DST_PORT'].mode().tolist() if 'DST_PORT' in group.columns else []
                target_port = target_ports[0] if target_ports else 0
                port_bonus = 10 if target_port in DDOS_UDP_FLOOD_PORTS else 0
                
                score = min(90, 70 + int(min(20, (ppm - DDOS_UDP_FLOOD_THRESHOLD) / 100)) + port_bonus)
                
                rows.append({
                    'INDICATOR': f'{src} → {dst}:{target_port}',
                    'TYPE': 'UDP Flood Attack',
                    'SCORE': score,
                    'COUNT': packet_count,
                    'SRC_IP': src,
                    'DST_IP': dst,
                    'PPS': pps,
                    'TARGET_PORT': target_port
                })
    except Exception:
        pass
    
    return pd.DataFrame(rows) if rows else pd.DataFrame(columns=['INDICATOR','TYPE','SCORE','COUNT','SRC_IP','DST_IP','PPS','TARGET_PORT'])


def detect_icmp_flood(icmp_df):
    """Detect ICMP flood attacks (ping floods)"""
    rows = []
    if icmp_df.empty:
        return pd.DataFrame(columns=['INDICATOR','TYPE','SCORE','COUNT','SRC_IP','DST_IP'])
    
    try:
        for src, group in icmp_df.groupby('SRC_IP'):
            packet_count = len(group)
            
            if packet_count >= DDOS_ICMP_FLOOD_THRESHOLD:
                echo_requests = len(group[group['ICMP_TYPE'] == 8]) if 'ICMP_TYPE' in group.columns else packet_count
                
                score = min(85, 65 + int(min(20, (packet_count - DDOS_ICMP_FLOOD_THRESHOLD) / 50)))
                
                dst_ip = group['DST_IP'].mode().tolist()[0] if 'DST_IP' in group.columns and not group.empty else ''
                
                rows.append({
                    'INDICATOR': f'{src} → ICMP Flood',
                    'TYPE': 'ICMP Flood Attack',
                    'SCORE': score,
                    'COUNT': packet_count,
                    'SRC_IP': src,
                    'DST_IP': dst_ip
                })
    except Exception:
        pass
    
    return pd.DataFrame(rows) if rows else pd.DataFrame(columns=['INDICATOR','TYPE','SCORE','COUNT','SRC_IP','DST_IP'])


def detect_packet_rate_anomalies(tcp_df, udp_df, icmp_df):
    """Detect abnormal packet rates across all protocols"""
    rows = []
    
    try:
        all_packets = []
        
        for df, proto in [(tcp_df, 'TCP'), (udp_df, 'UDP'), (icmp_df, 'ICMP')]:
            if df.empty or 'TS' not in df.columns:
                continue
            for src, group in df.groupby('SRC_IP'):
                times = group['TS'].dropna()
                if len(times) > 1:
                    duration = times.max() - times.min()
                    pps = len(group) / max(1, duration)
                    all_packets.append((src, pps, proto, len(group)))
        
        for src, pps, proto, count in all_packets:
            if pps >= DDOS_PPS_THRESHOLD:
                score = min(80, 60 + int(min(20, (pps - DDOS_PPS_THRESHOLD) / 500)))
                rows.append({
                    'INDICATOR': f'{src} ({proto})',
                    'TYPE': 'High Packet Rate Anomaly',
                    'SCORE': score,
                    'COUNT': count,
                    'SRC_IP': src,
                    'DST_IP': '',
                    'PPS': int(pps)
                })
    except Exception:
        pass
    
    return pd.DataFrame(rows) if rows else pd.DataFrame(columns=['INDICATOR','TYPE','SCORE','COUNT','SRC_IP','DST_IP','PPS'])


def detect_dns_amplification(dns_detail_df):
    """Detect DNS amplification attacks by analyzing query/response size ratios"""
    rows = []
    if dns_detail_df.empty:
        return pd.DataFrame(columns=['INDICATOR','TYPE','SCORE','AMPLIFICATION_FACTOR','VICTIM_IP','QUERY_COUNT','SRC_IP','DST_IP'])
    
    try:
        amplification_map = {}
        
        for _, row in dns_detail_df.iterrows():
            if row['RESPONSE_SIZE'] > 0 and row['QUERY_SIZE'] > 0:
                amp_factor = row['RESPONSE_SIZE'] / max(1, row['QUERY_SIZE'])
                if amp_factor >= DDOS_AMPLIFICATION_FACTOR:
                    victim = row['DST_IP']
                    if victim not in amplification_map:
                        amplification_map[victim] = {
                            'factors': [],
                            'queries': 0,
                            'domains': set(),
                            'sources': set()
                        }
                    amplification_map[victim]['factors'].append(amp_factor)
                    amplification_map[victim]['queries'] += 1
                    amplification_map[victim]['domains'].add(row['DOMAIN'])
                    amplification_map[victim]['sources'].add(row['SRC_IP'])
        
        for victim, data in amplification_map.items():
            if data['queries'] >= 5:
                avg_factor = sum(data['factors']) / len(data['factors'])
                score = min(95, 85 + int(min(10, (avg_factor - DDOS_AMPLIFICATION_FACTOR) / 5)))
                
                src_ip = list(data['sources'])[0] if data['sources'] else ''
                
                rows.append({
                    'INDICATOR': f'DNS Amplification → {victim}',
                    'TYPE': 'DNS Amplification Attack',
                    'SCORE': score,
                    'AMPLIFICATION_FACTOR': round(avg_factor, 2),
                    'VICTIM_IP': victim,
                    'QUERY_COUNT': data['queries'],
                    'SRC_IP': src_ip,
                    'DST_IP': victim
                })
    except Exception:
        pass
    
    return pd.DataFrame(rows) if rows else pd.DataFrame(columns=['INDICATOR','TYPE','SCORE','AMPLIFICATION_FACTOR','VICTIM_IP','QUERY_COUNT','SRC_IP','DST_IP'])


def detect_http_flood(http_df):
    """Detect HTTP flood attacks based on request rate"""
    rows = []
    if http_df.empty:
        return pd.DataFrame(columns=['INDICATOR','TYPE','SCORE','COUNT','SRC_IP','DST_IP','METHOD','REQUESTS_PER_MIN'])
    
    try:
        for src, group in http_df.groupby('SRC_IP'):
            request_count = len(group)
            
            rpm = request_count
            if 'TS' in group.columns:
                times = group['TS'].dropna()
                if len(times) > 1:
                    duration_min = (times.max() - times.min()) / 60
                    rpm = int(request_count / max(0.1, duration_min))
            
            if rpm >= DDOS_HTTP_FLOOD_THRESHOLD:
                methods = group['METHOD'].value_counts() if 'METHOD' in group.columns else {}
                primary_method = methods.index[0] if len(methods) > 0 else 'UNKNOWN'
                
                uri_diversity = len(group['REQUEST'].unique()) if 'REQUEST' in group.columns else 1
                pattern_bonus = 10 if uri_diversity < 5 else 0
                
                score = min(85, 70 + int(min(15, (rpm - DDOS_HTTP_FLOOD_THRESHOLD) / 50)) + pattern_bonus)
                
                target = group['DOMAIN'].mode().tolist()[0] if 'DOMAIN' in group.columns and not group.empty else ''
                
                rows.append({
                    'INDICATOR': f'{src} → {target}',
                    'TYPE': f'HTTP {primary_method} Flood Attack',
                    'SCORE': score,
                    'COUNT': request_count,
                    'SRC_IP': src,
                    'DST_IP': '',
                    'METHOD': primary_method,
                    'REQUESTS_PER_MIN': rpm
                })
    except Exception:
        pass
    
    return pd.DataFrame(rows) if rows else pd.DataFrame(columns=['INDICATOR','TYPE','SCORE','COUNT','SRC_IP','DST_IP','METHOD','REQUESTS_PER_MIN'])


def detect_multi_source_attack(tcp_df, udp_df):
    """Detect multi-source attacks targeting single destination"""
    rows = []
    
    try:
        all_traffic = []
        
        for df, proto in [(tcp_df, 'TCP'), (udp_df, 'UDP')]:
            if df.empty:
                continue
            for dst, group in df.groupby('DST_IP'):
                unique_sources = group['SRC_IP'].nunique() if 'SRC_IP' in group.columns else 0
                total_packets = len(group)
                all_traffic.append((dst, unique_sources, total_packets, proto))
        
        for dst, source_count, packet_count, proto in all_traffic:
            if source_count >= DDOS_MULTI_SOURCE_THRESHOLD:
                score = min(95, 80 + int(min(15, (source_count - DDOS_MULTI_SOURCE_THRESHOLD) / 5)))
                
                rows.append({
                    'INDICATOR': f'Coordinated Attack → {dst}',
                    'TYPE': f'Multi-Source DDoS ({proto})',
                    'SCORE': score,
                    'SOURCE_COUNT': source_count,
                    'TARGET_IP': dst,
                    'TOTAL_PACKETS': packet_count,
                    'SRC_IP': '',
                    'DST_IP': dst
                })
    except Exception:
        pass
    
    return pd.DataFrame(rows) if rows else pd.DataFrame(columns=['INDICATOR','TYPE','SCORE','SOURCE_COUNT','TARGET_IP','TOTAL_PACKETS','SRC_IP','DST_IP'])


def detect_botnet_signatures(tcp_df, udp_df):
    """Detect botnet signatures through payload similarity and timing"""
    rows = []
    
    try:
        if not tcp_df.empty and 'TS' in tcp_df.columns and 'SIZE' in tcp_df.columns:
            for dst, group in tcp_df.groupby('DST_IP'):
                if len(group) < 50:
                    continue
                
                size_groups = group.groupby('SIZE')['SRC_IP'].nunique()
                coordinated_sizes = size_groups[size_groups >= 5]
                
                if len(coordinated_sizes) > 0:
                    unique_sources = group['SRC_IP'].nunique()
                    
                    if unique_sources >= 5:
                        score = min(95, 85 + int(min(10, unique_sources / 3)))
                        
                        rows.append({
                            'INDICATOR': f'Botnet Pattern → {dst}',
                            'TYPE': 'Botnet Signature Detection',
                            'SCORE': score,
                            'SOURCE_COUNT': unique_sources,
                            'PATTERN': f'{len(coordinated_sizes)} coordinated packet sizes',
                            'SRC_IP': '',
                            'DST_IP': dst
                        })
    except Exception:
        pass
    
    return pd.DataFrame(rows) if rows else pd.DataFrame(columns=['INDICATOR','TYPE','SCORE','SOURCE_COUNT','PATTERN','SRC_IP','DST_IP'])


def correlate_c2_to_ddos(c2_df, ddos_df, tcp_df):
    """Correlate C2 communications with DDoS attacks based on timing and IPs"""
    rows = []
    
    try:
        if c2_df.empty or ddos_df.empty:
            return pd.DataFrame(columns=['INDICATOR','TYPE','SCORE','C2_IP','BOT_COUNT','ATTACK_TYPE','TIME_DELTA','SRC_IP','DST_IP'])
        
        c2_ips = set()
        for _, row in c2_df.iterrows():
            if row.get('SRC_IP'):
                c2_ips.add(row['SRC_IP'])
            if row.get('DST_IP'):
                c2_ips.add(row['DST_IP'])
        
        if not tcp_df.empty and 'SRC_IP' in tcp_df.columns:
            ddos_sources = set(ddos_df['SRC_IP'].dropna().unique()) if 'SRC_IP' in ddos_df.columns else set()
            tcp_sources = set(tcp_df['SRC_IP'].dropna().unique())
            
            potential_bots = c2_ips.intersection(tcp_sources)
            
            if len(potential_bots) >= 2:
                for c2_ip in c2_ips:
                    bot_count = len(potential_bots)
                    
                    attack_types = ddos_df['TYPE'].unique().tolist() if 'TYPE' in ddos_df.columns else []
                    attack_type = attack_types[0] if attack_types else 'Unknown'
                    
                    score = min(98, 90 + int(min(8, bot_count / 3)))
                    
                    rows.append({
                        'INDICATOR': f'C2: {c2_ip} → Coordinated DDoS',
                        'TYPE': 'C2-Coordinated DDoS Attack',
                        'SCORE': score,
                        'C2_IP': c2_ip,
                        'BOT_COUNT': bot_count,
                        'ATTACK_TYPE': attack_type,
                        'TIME_DELTA': 'Correlated',
                        'SRC_IP': c2_ip,
                        'DST_IP': ''
                    })
                    break
    except Exception:
        pass
    
    return pd.DataFrame(rows) if rows else pd.DataFrame(columns=['INDICATOR','TYPE','SCORE','C2_IP','BOT_COUNT','ATTACK_TYPE','TIME_DELTA','SRC_IP','DST_IP'])


def compute_ddos_heuristics(tcp_df, udp_df, icmp_df, http_df, dns_detail_df, c2_df):
    """Compute all DDoS detection heuristics"""
    parts = []
    
    # Volume-based attacks
    parts.append(detect_syn_flood(tcp_df))
    parts.append(detect_udp_flood(udp_df))
    parts.append(detect_icmp_flood(icmp_df))
    parts.append(detect_packet_rate_anomalies(tcp_df, udp_df, icmp_df))
    
    # Amplification attacks
    parts.append(detect_dns_amplification(dns_detail_df))
    
    # Application-layer attacks
    parts.append(detect_http_flood(http_df))
    
    # Distributed attacks
    parts.append(detect_multi_source_attack(tcp_df, udp_df))
    parts.append(detect_botnet_signatures(tcp_df, udp_df))
    
    # Combine all detections
    df = pd.concat(parts, ignore_index=True) if parts else pd.DataFrame(columns=['INDICATOR','TYPE','SCORE','COUNT','SRC_IP','DST_IP'])
    
    if not df.empty:
        if 'SRC_IP' not in df.columns:
            df['SRC_IP'] = ''
        if 'DST_IP' not in df.columns:
            df['DST_IP'] = ''
        
        df['SRC_IP'] = df['SRC_IP'].fillna('')
        df['DST_IP'] = df['DST_IP'].fillna('')
        
        df = df.sort_values(['SCORE', 'COUNT'], ascending=[False, False], ignore_index=True)
    
    # Add C2-DDoS correlation
    c2_ddos_corr = correlate_c2_to_ddos(c2_df, df, tcp_df)
    if not c2_ddos_corr.empty:
        df = pd.concat([c2_ddos_corr, df], ignore_index=True)
    
    return df
# -----------------------
# JS and HTML templates (embedded)
# -----------------------
JS_TEMPLATE = r"""
// === Dashboard JS (Stability v20.4 - Enhanced C2 Detection) ===
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

const c2Data        = %%C2GRAPH%%;
const c2FullData    = %%C2FULL%%;

const advData       = %%ADV%%;
const beaconData    = %%BEACON%%;
const dnstunnelData = %%DNSTUNNEL%%;

// DDoS Detection Data
const ddosData      = %%DDOS%%;
const ddosGraphData = %%DDOSGRAPH%%;

// HTTP C2 Detection Data
const httpC2Data    = %%HTTPC2%%;

// ✅ NEW: TCP IP Distribution Data
const tcpIPData     = %%TCPIP%%;


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
      td.title = td.textContent;  // Show full text on hover
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


// Store Cytoscape instances globally
let c2GraphInstance = null;
let ddosGraphInstance = null;

// Update renderC2Graph to store instance
function renderC2Graph(containerId, data){
  if(typeof cytoscape === 'undefined') return;

  const el = document.getElementById(containerId);
  if(!el) return;

  const nodes = {};
  const edges = [];
  const nodeScores = {};

  data.slice(0,500).forEach((r,i)=>{
    const s = r.SRC_IP || ('src'+i);
    const d = r.DST_IP || ('dst'+i);
    const score = r.SCORE || 0;

    nodes[s] = (nodes[s]||0) + (r.COUNT||1);
    nodes[d] = (nodes[d]||0) + (r.COUNT||1);

    nodeScores[s] = Math.max(nodeScores[s] || 0, score);
    nodeScores[d] = Math.max(nodeScores[d] || 0, score);

    edges.push({
      data:{ id:'e'+i, source:s, target:d, weight:r.COUNT||1, score: score }
    });
  });

  const cy_nodes = Object.keys(nodes).map(n=>({
    data:{ 
      id:n, 
      label: n,
      score: nodeScores[n] || 0,
      weight:nodes[n]
    }
  }));

  const getNodeColor = (score) => {
    if (score >= 90) return '#dc2626';
    if (score >= 75) return '#ea580c';
    if (score >= 60) return '#f59e0b';
    return '#3b82f6';
  };

  el.innerHTML = '';

  try{
    const cy = cytoscape({
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
            'text-valign':'center',
            'text-halign':'center',
            'font-size': 11,
            'font-weight': 'bold',
            'color':'#fff',
            'text-outline-width': 2.5,
            'text-outline-color': function(ele){ return getNodeColor(ele.data('score')); },
            'text-wrap': 'wrap',
            'text-max-width': 100,
            'width': function(ele){
              return Math.max(45, Math.min(80, 45 + ele.data('weight') * 2));
            },
            'height': function(ele){
              return Math.max(45, Math.min(80, 45 + ele.data('weight') * 2));
            },
            'background-color': function(ele){ return getNodeColor(ele.data('score')); },
            'border-width': 3,
            'border-color': '#fff',
            'border-opacity': 0.9
          }
        },
        {
          selector:'edge',
          style:{
            'width': function(ele){
              return Math.max(1.5, Math.min(6, 1.5 + (ele.data('weight') || 0) / 15));
            },
            'line-color': function(ele){ 
              const score = ele.data('score');
              if (score >= 90) return '#dc2626';
              if (score >= 75) return '#ea580c';
              if (score >= 60) return '#f59e0b';
              return '#94a3b8';
            },
            'opacity': 0.7,
            'curve-style': 'bezier',
            'target-arrow-shape': 'triangle',
            'target-arrow-color': function(ele){ 
              const score = ele.data('score');
              if (score >= 90) return '#dc2626';
              if (score >= 75) return '#ea580c';
              if (score >= 60) return '#f59e0b';
              return '#94a3b8';
            },
            'arrow-scale': 1.5
          }
        },
        {
          selector:'node:selected',
          style:{
            'border-width': 6,
            'border-color': '#10b981'
          }
        }
      ],
      layout:{ 
        name:'cose',
        animate: true,  // ✅ Enable animation for smooth layout
        animationDuration: 500,
        animationEasing: 'ease-out',
        
        // ✅ CRITICAL: Better spacing parameters
        nodeRepulsion: 25000,  // Increased from 20000
        idealEdgeLength: 180,  // Increased from 150
        edgeElasticity: 100,
        
        // ✅ Prevent top-clustering
        componentSpacing: 120,  // Increased
        nestingFactor: 1.2,
        gravity: 0.5,  // REDUCED from 1 to spread vertically
        
        // ✅ Better convergence
        numIter: 3000,  // Increased
        initialTemp: 1000,
        coolingFactor: 0.99,
        minTemp: 1.0,
        
        // ✅ Use available space
        fit: true,  // Auto-fit to container
        padding: 60,  // Increased from 50
        randomize: false,
        avoidOverlap: true,  // Prevent node overlap
        avoidOverlapPadding: 25  // Increased from 20
      },
      minZoom: 0.2,
      maxZoom: 4,
      wheelSensitivity: 0.15,
      
      // ✅ Auto-fit after layout completes
      ready: function(){
        this.fit(60);  // Increased padding from 50
        this.center();
      }
    });
    
    // ✅ Store instance
    if(containerId === 'c2graph') {
      c2GraphInstance = cy;
    } else if(containerId === 'ddosgraph') {
      ddosGraphInstance = cy;
    }
    
    // ✅ Re-fit after layout animation completes
    setTimeout(() => {
      cy.fit(60);  // Increased padding from 50
    }, 600);
    
  }catch(e){
    console.log('cytoscape err', e);
  }
}

// ✅ Graph control functions
function resetC2Graph() {
  if(c2GraphInstance) {
    c2GraphInstance.zoom(1);
    c2GraphInstance.center();
  }
}

function fitC2Graph() {
  if(c2GraphInstance) {
    c2GraphInstance.fit(null, 50);
  }
}

function resetDDoSGraph() {
  if(ddosGraphInstance) {
    ddosGraphInstance.zoom(1);
    ddosGraphInstance.center();
  }
}

function fitDDoSGraph() {
  if(ddosGraphInstance) {
    ddosGraphInstance.fit(null, 50);
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

  renderTableRows(
    document.querySelector('#tbl_c2 tbody'),
    (c2FullData||[]).slice(0,topN),
    ['INDICATOR','TYPE','SCORE','COUNT']
  );

  renderTableRows(document.querySelector('#tbl_adv tbody'), (advData||[]).slice(0,topN), ['INDICATOR','TYPE','SCORE','COUNT']);
  renderTableRows(document.querySelector('#tbl_beacon tbody'), (beaconData||[]).slice(0,topN), ['INDICATOR','TYPE','SCORE','COUNT']);
  renderTableRows(document.querySelector('#tbl_dnstunnel tbody'), (dnstunnelData||[]).slice(0,topN), ['INDICATOR','TYPE','SCORE','COUNT','NOTES']);
  
  // DDoS Detection table
  const ddosSlice = (ddosData||[]).slice().sort((a,b)=>(b.SCORE||0)-(a.SCORE||0)).slice(0,topN);
  renderTableRows(document.querySelector('#tbl_ddos tbody'), ddosSlice, ['INDICATOR','TYPE','SCORE','COUNT']);

  // HTTP C2 Detection table
  const httpC2Slice = (httpC2Data||[]).slice().sort((a,b)=>(b.SCORE||0)-(a.SCORE||0)).slice(0,topN);
  renderTableRows(document.querySelector('#tbl_http_c2 tbody'), httpC2Slice, 
    ['C2_SERVER','BOT_COUNT','EXTRACTED_IPS','TARGETS_DISTRIBUTED','PAYLOAD_SAMPLE',
     'TARGETS_ATTACKED','CORRELATION_SCORE','TIME_TO_ATTACK','SCORE']);

  // ✅ NEW: TCP IP Distribution table
  const tcpIPSlice = (tcpIPData||[]).slice().sort((a,b)=>(b.SCORE||0)-(a.SCORE||0)).slice(0,topN);
  renderTableRows(document.querySelector('#tbl_tcp_ip tbody'), tcpIPSlice, 
    ['SRC_IP','SRC_PORT','DST_IP','DST_PORT','EXTRACTED_IPS','IPS_FOUND','PAYLOAD_SAMPLE','SCORE']);

  // ------------------------
  // PIVOT
  // ------------------------
  renderPivot(document.querySelector('#pivot tbody'), tcpSliceFull);

  // ------------------------
  // C2 GRAPH
  // ------------------------
  let edgesForGraph = (c2Data || []).slice();

  if(edgesForGraph.length > 150){
    console.warn("C2 graph trimmed to 150 edges for readability.");
    edgesForGraph = edgesForGraph.slice(0,150);
  }

  renderC2Graph('c2graph', edgesForGraph);
  
  // ------------------------
  // DDoS GRAPH
  // ------------------------
  let ddosEdgesForGraph = (ddosGraphData || []).slice();
  if(ddosEdgesForGraph.length > 150){
    console.warn("DDoS graph trimmed to 150 edges for readability.");
    ddosEdgesForGraph = ddosEdgesForGraph.slice(0,150);
  }
  renderC2Graph('ddosgraph', ddosEdgesForGraph);

  // Update DDoS count indicator
  const ddosCountEl = document.getElementById('ddos_count');
  if(ddosCountEl) {
    ddosCountEl.textContent = (ddosData||[]).length;
    ddosCountEl.style.color = (ddosData||[]).length > 0 ? '#dc2626' : '#10b981';
  }

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
<title>PCAP Dashboard (Stability v20.4 - Enhanced C2 Detection)</title>
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
.app{display:flex;min-height:100vh}
.sidebar{width:240px;background:#0f1724;color:#fff;padding:18px;font-size:11px;flex-shrink:0}
.content{flex:1;padding:18px;max-width:100%}

/* ✅ NEW: 3-Column Grid Layout */
.card-grid{
  display:grid;
  grid-template-columns:repeat(3, 1fr);  /* 3 equal columns */
  gap:16px;
  margin-bottom:16px;
}

/* Responsive: 2 columns on medium screens */
@media (max-width: 1400px) {
  .card-grid{
    grid-template-columns:repeat(2, 1fr);
  }
}

/* Responsive: 1 column on small screens */
@media (max-width: 900px) {
  .card-grid{
    grid-template-columns:1fr;
  }
}

.card{
  background:#fff;
  border-radius:12px;
  padding:16px;
  box-shadow:0 2px 8px rgba(0,0,0,0.06);
  display:flex;
  flex-direction:column;
}

h3{
  margin:0 0 12px 0;
  font-size:14px;
  font-weight:600;
  color:#1f2937;
}

.table-wrap{
  overflow-x:auto;
  margin-top:12px;
  flex:1;
}

.display{
  width:100%;
  font-size:10px;
}

.chart-box{
  margin-bottom:12px;
  height:200px;
}

canvas{
  display:block;
  max-height:200px;
  width:100% !important;
}

.display td{
  max-width:180px;
  word-wrap:break-word;
  overflow-wrap:break-word;
  white-space:normal !important;
  font-size:10px;
}

.display th{
  font-size:10px;
  font-weight:600;
  background:#f9fafb !important;
  position:sticky;
  top:0;
  z-index:10;
}

.display td.nowrap{
  white-space:nowrap;
}

/* Graph containers - INCREASED SIZE */
#c2graph, #ddosgraph {
  width: 100%;
  height: 500px;  /* ✅ Increased from 380px to 500px */
  border: 1px solid #e5e7eb;
  background: #fafbfc;
  border-radius: 8px;
  position: relative;
  margin-top: 8px;
  min-height: 500px;  /* ✅ Ensure minimum height */
}

#c2graph::after, #ddosgraph::after {
  content: '🔍 Scroll to zoom • Drag to pan';
  position: absolute;
  bottom: 10px;
  right: 10px;
  font-size: 9px;
  color: #6b7280;
  background: rgba(255,255,255,0.95);
  padding: 5px 12px;
  border-radius: 6px;
  pointer-events: none;
  box-shadow: 0 1px 3px rgba(0,0,0,0.1);
  z-index: 1000;
}

/* Make graph cards taller */
.card-full {
  grid-column: 1 / -1;
  min-height: 550px;  /* ✅ Card minimum height */
}

/* Ensure card content fills available space */
.card-full .chart-box,
.card-full > div:not(.table-wrap) {
  flex: 1;
  display: flex;
  flex-direction: column;
}

/* Special styling for graph cards */
.card-full h3 {
  margin-bottom: 8px;
  padding-bottom: 8px;
  border-bottom: 2px solid #e5e7eb;
}

body.dark .card-full h3 {
  border-bottom-color: #374151;
}

/* Remove extra spacing around graphs */
.card-full {
  padding: 20px;
}

@media (min-width: 1400px) {
  #c2graph, #ddosgraph {
    height: 550px;  /* Even taller on large screens */
  }
  
  .card-full {
    min-height: 600px;
  }
}

/* Ensure graphs fill their containers */
#c2graph canvas,
#ddosgraph canvas {
  width: 100% !important;
  height: 100% !important;
}

/* Dark mode */
body.dark { 
  background: #0b1116 !important; 
  color: #e6eef6 !important; 
}

body.dark .sidebar { 
  background:#060a0f !important; 
  color:#e6eef6 !important; 
}

body.dark .card { 
  background:#0e1620 !important; 
  color:#e6eef6 !important; 
  box-shadow: 0 4px 12px rgba(0,0,0,0.4); 
}

body.dark h3 {
  color: #f3f4f6;
}

body.dark .display th { 
  background: #1a1f2e !important;
  color:#e5e7eb !important; 
}

body.dark .display td { 
  color:#d1d5db !important; 
  background: transparent !important; 
}

body.dark #c2graph, body.dark #ddosgraph { 
  background:#0a0f1a !important; 
  border-color:#1f2937 !important; 
}

body.dark #c2graph::after, body.dark #ddosgraph::after {
  background: rgba(15,23,42,0.95);
  color: #9ca3af;
}

/* Input and button styling */
input[type="text"], select {
  padding: 6px 10px;
  border: 1px solid #d1d5db;
  border-radius: 6px;
  font-size: 11px;
  background: #fff;
}

body.dark input[type="text"], body.dark select {
  background: #1a1f2e;
  border-color: #374151;
  color: #e5e7eb;
}

button {
  padding: 6px 12px;
  border: none;
  border-radius: 6px;
  font-size: 11px;
  cursor: pointer;
  transition: all 0.2s;
}

button:hover {
  opacity: 0.9;
  transform: translateY(-1px);
}

#clear_filters {
  background: #10b981;
  color: #fff;
  width: 100%;
  padding: 10px;
  font-weight: 600;
}

#darkToggle {
  background: #6366f1;
  color: #fff;
}
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
    <h1 style='margin:0 0 12px 0'>PCAP Analysis Dashboard (Stability v20.4 - Enhanced C2 Detection)</h1>

    <div style='margin-bottom:12px'>
      <label>Source IP: <input id='filter_src' type='text'></label>
      <label style='margin-left:12px'>Dest IP: <input id='filter_dst' type='text'></label>
      <label style='margin-left:12px'>Domain/SNI: <input id='filter_dom' type='text'></label>
      <label style='margin-left:12px'>Show Top: <select id='topN'><option value='15'>15</option><option value='25'>25</option><option value='50'>50</option><option value='99999'>All</option></select></label>
      <button id='darkToggle' style='margin-left:12px'>Dark</button>
    </div>

    <div class='card-grid'>
  <!-- Row 1: 3 columns -->
  <div class='card'>
    <h3>Timeline</h3>
    <div class='chart-box'><canvas id='chart_timeline'></canvas></div>
  </div>
  
  <div class='card'>
    <h3>DNS Top</h3>
    <div class='chart-box'><canvas id='chart_dns'></canvas></div>
    <div class='table-wrap'><table id='tbl_dns' class='display'><thead><tr><th>DOMAIN</th><th>COUNT</th><th>%</th></tr></thead><tbody></tbody></table></div>
  </div>
  
  <div class='card'>
    <h3>HTTP Top</h3>
    <div class='chart-box'><canvas id='chart_http'></canvas></div>
    <div class='table-wrap'><table id='tbl_http' class='display'><thead><tr><th>DOMAIN</th><th>COUNT</th><th>%</th></tr></thead><tbody></tbody></table></div>
  </div>
  
  <!-- Row 2: 3 columns -->
  <div class='card'>
    <h3>TLS SNI / JA3</h3>
    <div class='chart-box'><canvas id='chart_tls'></canvas></div>
    <div class='table-wrap'><table id='tbl_tls' class='display'><thead><tr><th>SNI</th><th>JA3</th><th>SRC</th><th>DST</th><th>CNT</th><th>%</th></tr></thead><tbody></tbody></table></div>
  </div>
  
  <div class='card'>
    <h3>TCP Flags</h3>
    <div class='chart-box'><canvas id='chart_tcp'></canvas></div>
    <div class='table-wrap'><table id='tbl_tcp' class='display'><thead><tr><th>SRC_IP</th><th>DST_IP</th><th>FLAGS</th><th>CNT</th><th>%</th></tr></thead><tbody></tbody></table></div>
  </div>
  
  <div class='card'>
    <h3>DDoS Detection Summary</h3>
    <div style='padding:20px 0;text-align:center'>
      <div style='font-size:32px;font-weight:bold;color:#dc2626' id='ddos_count'>0</div>
      <div style='font-size:11px;color:#6b7280;margin-top:4px'>Attacks Detected</div>
    </div>
    <div class='table-wrap'><table id='tbl_ddos' class='display'><thead><tr><th>INDICATOR</th><th>TYPE</th><th>SCORE</th><th>COUNT</th></tr></thead><tbody></tbody></table></div>
  </div>
</div>

<!-- Full-width graphs -->
<div class='card-grid'>
  <div class='card card-full'>
    <h3>C2 Command & Control Graph</h3>
    <div id='c2graph'></div>
  </div>
</div>

<div class='card-grid'>
  <div class='card card-full'>
    <h3>DDoS Attack Graph</h3>
    <div id='ddosgraph'></div>
  </div>
</div>

<!-- Continue with full-width sections below -->
<div style='margin-top:18px' class='card'>
  <h3>HTTP C2 Target Distribution</h3>
  <div class='table-wrap'><table id='tbl_http_c2' class='display'><thead><tr><th>C2 Server</th><th>Bots</th><th>IPs Extracted</th><th>Targets Distributed</th><th>Payload Sample</th><th>Attacked</th><th>Correlation</th><th>Time</th><th>Score</th></tr></thead><tbody></tbody></table></div>
</div>

<div style='margin-top:18px' class='card'>
  <h3>TCP IP Distribution (All Protocols)</h3>
  <p style='font-size:10px;opacity:0.8;margin-bottom:8px'>Scans all TCP payloads for IP address lists (detects C2 commands in raw TCP data)</p>
  <div class='table-wrap'><table id='tbl_tcp_ip' class='display'><thead><tr><th>SRC IP</th><th>SRC Port</th><th>DST IP</th><th>DST Port</th><th>IPs Found</th><th>IP Addresses</th><th>Payload Sample</th><th>Score</th></tr></thead><tbody></tbody></table></div>
</div>

<div style='margin-top:18px' class='card'>
  <h3>Advanced Heuristics</h3>
  <div class='table-wrap'><table id='tbl_adv' class='display'><thead><tr><th>INDICATOR</th><th>TYPE</th><th>SCORE</th><th>COUNT</th></tr></thead><tbody></tbody></table></div>
</div>

<div style='margin-top:18px' class='card'>
  <h3>Beaconing Detection</h3>
  <div class='table-wrap'><table id='tbl_beacon' class='display'><thead><tr><th>INDICATOR</th><th>TYPE</th><th>SCORE</th><th>COUNT</th></tr></thead><tbody></tbody></table></div>
</div>

<div style='margin-top:18px' class='card'>
  <h3>DNS Tunneling</h3>
  <div class='table-wrap'><table id='tbl_dnstunnel' class='display'><thead><tr><th>INDICATOR</th><th>TYPE</th><th>SCORE</th><th>COUNT</th><th>NOTES</th></tr></thead><tbody></tbody></table></div>
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
        print("\n=== Stability v20.4: Enhanced C2 Detection with HTTP Response + TCP Payload Scanning ===\n")

        print("[1/16] Parsing PCAP (enhanced for payload detection)...")
        dns, tcp, http, tls, udp, icmp, dns_detail = parse_streams(pcap)

        print("[2/16] Aggregating DNS...")
        dnsA = agg(dns, ['DOMAIN'])

        print("[3/16] Aggregating HTTP...")
        httpA = agg(http, ['DOMAIN'])

        print("[4/16] Aggregating TLS...")
        tls_cols = ['SNI', 'JA3', 'SRC_IP', 'DST_IP']
        for col in tls_cols:
            if col not in tls.columns:
                tls[col] = None
        tlsA = agg(tls, tls_cols)

        print("[5/16] Aggregating TCP...")
        tcpA = agg(tcp, ['SRC_IP', 'DST_IP', 'FLAGS'])

        print("[6/16] Building HTTP Timeline...")
        timeline = {}
        if os.path.exists(pcap) and PcapReader:
            if not http.empty and 'TS' in http.columns:
                for _, row in http.iterrows():
                    ts = int(row['TS'])
                    key = time.strftime('%Y-%m-%d %H:%M', time.localtime(ts))
                    timeline[key] = timeline.get(key, 0) + 1
        timeline_list = [{'label': k, 'count': v} for k, v in sorted(timeline.items())]

        print("[7/16] Computing full C2 heuristic indicators...")
        c2_full = compute_c2_heuristics(dnsA, httpA, tlsA, tcpA)

        print("[8/16] Preparing compact C2 dataset for graph...")
        important_prefixes = [
            "JA3 Match",
            "High-Entropy TLS SNI",
            "High-Entropy SNI + Rare JA3",
            "High-Entropy DNS",
            "Rare JA3 Fingerprint",
        ]

        def is_graph_worthy_row(r):
            if r.get('GRAPH_SKIP', False):
                return False
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
            if c2_graph.empty:
                c2_graph = c2_full.sort_values(['SCORE','COUNT'], ascending=[False,False]).head(MAX_GRAPH_EDGES).copy()
            if len(c2_graph) > MAX_GRAPH_EDGES:
                c2_graph = c2_graph.head(MAX_GRAPH_EDGES)
        else:
            c2_graph = pd.DataFrame(columns=['INDICATOR','TYPE','SCORE','COUNT'])

        print(f"  - c2_full rows: {len(c2_full)}")
        print(f"  - c2_graph rows: {len(c2_graph)}")

        print("[9/16] Computing Advanced Heuristics...")
        adv = compute_advanced_heuristics(dnsA, httpA, tlsA, tcpA, timeline_list)

        print("[10/16] Detecting Beaconing...")
        beacon = detect_beaconing(tcp)

        print("[11/16] Detecting DNS Tunneling...")
        dnstunnel = detect_dnstunneling(dns)
        
        print("[12/16] Detecting HTTP C2 Target Distribution...")
        http_c2 = detect_http_target_distribution(http, tcp)
        print(f"  - HTTP C2 detections: {len(http_c2)}")
        
        print("[13/16] Computing DDoS Attack Heuristics...")
        ddos = compute_ddos_heuristics(tcp, udp, icmp, http, dns_detail, c2_full)
        print(f"  - DDoS detections: {len(ddos)}")
        
        print("[14/16] Preparing DDoS graph subset...")
        if not ddos.empty:
            ddos_graph = ddos[ddos['SCORE'] >= GRAPH_MIN_SCORE].copy()
            if len(ddos_graph) > MAX_GRAPH_EDGES:
                ddos_graph = ddos_graph.head(MAX_GRAPH_EDGES)
        else:
            ddos_graph = pd.DataFrame(columns=['INDICATOR','TYPE','SCORE','COUNT','SRC_IP','DST_IP'])
        print(f"  - ddos_graph rows: {len(ddos_graph)}")
        
        # ✅ NEW: TCP IP Distribution Detection
        print("[15/16] Detecting IP lists in TCP payloads (all protocols)...")
        tcp_ip_dist = detect_tcp_ip_distribution(tcp)  # Use RAW tcp, not aggregated
        print(f"  - TCP IP distributions found: {len(tcp_ip_dist)}")

        print("[16/16] Writing dashboard.js and dashboard.html ...")
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
            .replace('%%DDOS%%', safe_js_json(ddos.to_dict(orient='records')))
            .replace('%%DDOSGRAPH%%', safe_js_json(ddos_graph.to_dict(orient='records')))
            .replace('%%HTTPC2%%', safe_js_json(http_c2.to_dict(orient='records')))
            .replace('%%TCPIP%%', safe_js_json(tcp_ip_dist.to_dict(orient='records')))  # ✅ NEW
        )

        with open('dashboard.js', 'w', encoding='utf-8') as jf:
            jf.write(js)
        print("→ dashboard.js written.")

        html_output = HTML_TEMPLATE.replace('%%FILE%%', pcap)
        with open('dashboard.html', 'w', encoding='utf-8') as hf:
            hf.write(html_output)
        print("→ dashboard.html written.")

        print("\n=== DONE: Stability v20.4 dashboard with enhanced C2 detection generated ===\n")

    except Exception:
        print("\n\n=== PIPELINE CRASH ===")
        traceback.print_exc()
        raise

# -----------------------
# Entry point
# -----------------------
if __name__ == '__main__':
    pipeline()
