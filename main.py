
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Stability v20.3 — Comprehensive DDoS Detection Module
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
FILE_PCAP = "ataques_out_novembro_2025.pcapng"

TRUSTED_DOMAINS = {
    "google.com","facebook.com","oracle.com","microsoft.com","apple.com",
    "amazon.com","linkedin.com","cloudflare.com","youtube.com","whatsapp.net",
    "googleapis.com","twitter.com","ytimg.com","fbcdn.net","tiktokv.com","instagram.com","gstatic.com"
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
# Single-pass PCAP parser (enhanced for DDoS detection)
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
            pd.DataFrame(columns=['SRC_IP','DST_IP','FLAGS','COUNT','TS','SIZE','SRC_PORT','DST_PORT']),
            pd.DataFrame(columns=['DOMAIN','REQUEST','COUNT','METHOD','TS','SRC_IP','PAYLOAD']),
            pd.DataFrame(columns=['SNI','JA3','SRC_IP','DST_IP','COUNT']),
            pd.DataFrame(columns=['SRC_IP','DST_IP','SRC_PORT','DST_PORT','TS','SIZE']),
            pd.DataFrame(columns=['SRC_IP','DST_IP','ICMP_TYPE','TS','SIZE']),
            pd.DataFrame(columns=['SRC_IP','DST_IP','QUERY_SIZE','RESPONSE_SIZE','DOMAIN','TS'])
        )

    if not os.path.exists(pcap_path):
        return (
            pd.DataFrame(columns=['DOMAIN','A','COUNT','ENTROPY']),
            pd.DataFrame(columns=['SRC_IP','DST_IP','FLAGS','COUNT','TS','SIZE','SRC_PORT','DST_PORT']),
            pd.DataFrame(columns=['DOMAIN','REQUEST','COUNT','METHOD','TS','SRC_IP','PAYLOAD']),
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

                # TCP + IP flows with enhanced data
                if getattr(p, 'haslayer', lambda x: False)(TCP) and getattr(p, 'haslayer', lambda x: False)(IP):
                    src = p[IP].src
                    dst = p[IP].dst
                    src_port = p[TCP].sport
                    dst_port = p[TCP].dport
                    flags = tcp_flags_str_local(p)
                    tcp_rows.append({
                        'SRC_IP':src,
                        'DST_IP':dst,
                        'FLAGS':flags,
                        'COUNT':1,
                        'TS':ts,
                        'SIZE':pkt_size,
                        'SRC_PORT':src_port,
                        'DST_PORT':dst_port
                    })

                    # payload analysis
                    if getattr(p, 'haslayer', lambda x: False)(Raw):
                        payload = bytes(p[Raw])

                        # Robust HTTP detection with method extraction
                        try:
                            txt = payload.decode(errors='ignore')
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
                                # Store payload (limit to first 2048 bytes)
                                payload_text = txt[:2048] if len(txt) > 2048 else txt
                                if host and not is_trusted_domain(host):
                                    http_rows.append({
                                        'DOMAIN': host,
                                        'REQUEST': request_line,
                                        'COUNT': 1,
                                        'METHOD': method,
                                        'TS': ts,
                                        'SRC_IP': src,
                                        'PAYLOAD': payload_text
                                    })
                        except Exception:
                            pass

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
    tcp_df = pd.DataFrame(tcp_rows) if tcp_rows else pd.DataFrame(columns=['SRC_IP','DST_IP','FLAGS','COUNT','TS','SIZE','SRC_PORT','DST_PORT'])
    http_df = pd.DataFrame(http_rows) if http_rows else pd.DataFrame(columns=['DOMAIN','REQUEST','COUNT','METHOD','TS','SRC_IP','PAYLOAD'])
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

def compute_c2_heuristics(dnsA, httpA, tlsA, tcpA, http_full=None):
    rows = []
    def high_entropy(name): return bool(name) and (shannon_entropy(name) >= 3.8 or len(name) >= 45)

    # C2 Payload Pattern Detection (if http_full DataFrame provided with PAYLOAD column)
    if http_full is not None and not http_full.empty:
        try:
            c2_payload_detections = detect_c2_payload_patterns(http_full, tcpA)
            if not c2_payload_detections.empty:
                for _, r in c2_payload_detections.iterrows():
                    rows.append({
                        'INDICATOR': r.get('INDICATOR', ''),
                        'TYPE': r.get('TYPE', ''),
                        'SCORE': int(r.get('SCORE', 0)),
                        'COUNT': int(r.get('COUNT', 0)),
                        'SRC_IP': r.get('SRC_IP', ''),
                        'DST_IP': r.get('DST_IP', ''),
                    })
        except Exception:
            pass

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

    # TLS JA3 / SNI checks - THESE HAVE IP DATA
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
# C2 Payload Detection Functions
# -----------------------

def extract_ip_port_lists_from_payload(payload_text):
    """Extract IP:port pairs from payload using regex pattern"""
    if not payload_text:
        return []
    try:
        # Pattern for IP:port (e.g., 207.174.105.76:9998)
        ip_port_pattern = r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)\b'
        matches = re.findall(ip_port_pattern, payload_text)
        # Return list of tuples (ip, port)
        return [(ip, port) for ip, port in matches if all(int(octet) <= 255 for octet in ip.split('.'))]
    except Exception:
        return []

def detect_attack_command_parameters(payload_text):
    """Detect numeric parameter sequences that indicate attack configuration"""
    if not payload_text:
        return {'has_params': False, 'param_count': 0, 'params': []}
    try:
        # Look for sequences of numbers separated by semicolons or commas
        # Pattern: number;number;number or number,number,number
        param_patterns = [
            r'\b(\d+)[;,](\d+)[;,](\d+)',  # At least 3 numeric parameters
            r'^(\d+)[;,]',  # Start with number followed by separator
        ]
        
        params = []
        for pattern in param_patterns:
            matches = re.findall(pattern, payload_text)
            if matches:
                # Flatten tuples and convert to integers
                for match in matches:
                    if isinstance(match, tuple):
                        params.extend([int(x) for x in match if x.isdigit()])
                    elif match.isdigit():
                        params.append(int(match))
        
        # Also look for semicolon/comma-separated numeric sequences
        lines = payload_text.split('\n')
        for line in lines[:10]:  # Check first 10 lines
            # Split by semicolon or comma
            parts = re.split('[;,]', line.strip())
            numeric_parts = [p.strip() for p in parts if p.strip().isdigit()]
            if len(numeric_parts) >= 5:  # At least 5 numeric parameters
                params.extend([int(p) for p in numeric_parts])
                break
        
        return {
            'has_params': len(params) > 0,
            'param_count': len(params),
            'params': params[:20]  # Limit to first 20 params
        }
    except Exception:
        return {'has_params': False, 'param_count': 0, 'params': []}

def detect_base64_payload(payload_text):
    """Detect base64-encoded content in payload"""
    if not payload_text or len(payload_text) < 20:
        return None
    try:
        import base64
        # Look for base64-like strings (at least 20 chars)
        base64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
        matches = re.findall(base64_pattern, payload_text)
        
        for match in matches[:5]:  # Check first 5 matches
            if len(match) >= 20:
                try:
                    # Try to decode
                    decoded = base64.b64decode(match, validate=True).decode(errors='ignore')
                    # Check if decoded content contains IP:port patterns
                    ip_ports = extract_ip_port_lists_from_payload(decoded)
                    if len(ip_ports) >= 3:
                        return decoded[:500]  # Return decoded content (limited)
                except Exception:
                    continue
        return None
    except Exception:
        return None

def detect_c2_payload_patterns(http_df, tcp_df):
    """Detect C2 command patterns in HTTP payloads"""
    rows = []
    if http_df.empty or 'PAYLOAD' not in http_df.columns:
        return pd.DataFrame(columns=['INDICATOR','TYPE','SCORE','COUNT','SRC_IP','DST_IP','IP_COUNT','PARAM_COUNT','PAYLOAD_EXCERPT'])
    
    try:
        for _, row in http_df.iterrows():
            payload = row.get('PAYLOAD', '')
            if not payload or len(payload) < 10:
                continue
            
            src_ip = row.get('SRC_IP', '')
            domain = row.get('DOMAIN', '')
            ts = row.get('TS', 0)
            
            # Extract IP:port lists
            ip_ports = extract_ip_port_lists_from_payload(payload)
            ip_count = len(ip_ports)
            
            # Detect numeric parameters
            param_info = detect_attack_command_parameters(payload)
            param_count = param_info['param_count']
            
            # Check for base64-encoded commands
            decoded_payload = detect_base64_payload(payload)
            if decoded_payload:
                # Re-analyze decoded payload
                decoded_ip_ports = extract_ip_port_lists_from_payload(decoded_payload)
                if len(decoded_ip_ports) > ip_count:
                    ip_ports = decoded_ip_ports
                    ip_count = len(ip_ports)
            
            # Scoring based on patterns detected
            score = 0
            detection_type = ''
            
            if ip_count >= 5 and ip_count < 10:
                score = 85
                detection_type = 'C2 Attack Command (5+ targets)'
            elif ip_count >= 10:
                score = 95
                detection_type = 'C2 Attack Command (10+ targets)'
            
            # Bonus for parameter sequences
            if ip_count >= 5 and param_count >= 5:
                score = min(98, score + 10)
                detection_type = 'C2 Attack Command (IP list + parameters)'
            
            # Check for known botnet patterns
            botnet_keywords = ['mirai', 'gafgyt', 'qbot', 'emotet', 'trickbot']
            payload_lower = payload.lower()
            if any(keyword in payload_lower for keyword in botnet_keywords):
                score = 99
                detection_type = 'Known Botnet C2 Command'
            
            # Only create alert if score is high enough
            if score >= 85:
                # Create payload excerpt for display
                excerpt = payload[:200].replace('\n', ' ').replace('\r', '')
                if len(payload) > 200:
                    excerpt += '...'
                
                rows.append({
                    'INDICATOR': f'{src_ip} → {domain}',
                    'TYPE': detection_type,
                    'SCORE': score,
                    'COUNT': 1,
                    'SRC_IP': src_ip,
                    'DST_IP': '',  # HTTP doesn't have direct DST_IP in aggregated form
                    'IP_COUNT': ip_count,
                    'PARAM_COUNT': param_count,
                    'PAYLOAD_EXCERPT': excerpt,
                    'TS': ts
                })
    except Exception:
        pass
    
    return pd.DataFrame(rows) if rows else pd.DataFrame(columns=['INDICATOR','TYPE','SCORE','COUNT','SRC_IP','DST_IP','IP_COUNT','PARAM_COUNT','PAYLOAD_EXCERPT'])

def correlate_c2_commands_to_attacks(c2_commands_df, tcp_df, time_window=300):
    """Correlate C2 commands with subsequent traffic spikes within time window"""
    rows = []
    
    try:
        if c2_commands_df.empty or tcp_df.empty:
            return pd.DataFrame(columns=['INDICATOR','TYPE','SCORE','C2_TIME','ATTACK_TIME','TIME_DELTA','SRC_IP','DST_IP'])
        
        if 'TS' not in c2_commands_df.columns or 'TS' not in tcp_df.columns:
            return pd.DataFrame(columns=['INDICATOR','TYPE','SCORE','C2_TIME','ATTACK_TIME','TIME_DELTA','SRC_IP','DST_IP'])
        
        # For each C2 command, look for traffic spikes within time window
        for _, c2_row in c2_commands_df.iterrows():
            c2_time = c2_row.get('TS', 0)
            c2_src = c2_row.get('SRC_IP', '')
            
            if not c2_src or c2_time == 0:
                continue
            
            # Look for traffic from same source within time window
            time_mask = (tcp_df['TS'] >= c2_time) & (tcp_df['TS'] <= c2_time + time_window)
            src_mask = tcp_df['SRC_IP'] == c2_src
            
            relevant_traffic = tcp_df[time_mask & src_mask]
            
            if len(relevant_traffic) >= 50:  # Significant traffic increase
                # Calculate time delta
                attack_time = relevant_traffic['TS'].min()
                time_delta = int(attack_time - c2_time)
                
                rows.append({
                    'INDICATOR': f'C2→Attack: {c2_src}',
                    'TYPE': 'C2 Command Followed by Attack',
                    'SCORE': 90,
                    'C2_TIME': c2_time,
                    'ATTACK_TIME': attack_time,
                    'TIME_DELTA': time_delta,
                    'SRC_IP': c2_src,
                    'DST_IP': ''
                })
    except Exception:
        pass
    
    return pd.DataFrame(rows) if rows else pd.DataFrame(columns=['INDICATOR','TYPE','SCORE','C2_TIME','ATTACK_TIME','TIME_DELTA','SRC_IP','DST_IP'])

# -----------------------
# DDoS Detection Functions
# -----------------------

def detect_syn_flood(tcp_df):
    """Detect SYN flood attacks by analyzing SYN/ACK ratios"""
    rows = []
    if tcp_df.empty or 'FLAGS' not in tcp_df.columns:
        return pd.DataFrame(columns=['INDICATOR','TYPE','SCORE','COUNT','SRC_IP','DST_IP','SYN_RATIO','PPS'])
    
    try:
        # Group by source-destination pairs
        for (src, dst), group in tcp_df.groupby(['SRC_IP', 'DST_IP']):
            syn_count = len(group[group['FLAGS'].str.contains('SYN', na=False) & ~group['FLAGS'].str.contains('ACK', na=False)])
            ack_count = len(group[group['FLAGS'].str.contains('ACK', na=False)])
            total_count = len(group)
            
            # Calculate SYN/ACK ratio
            syn_ratio = syn_count / max(1, ack_count)
            
            # Detect SYN flood
            if syn_count >= DDOS_SYN_FLOOD_THRESHOLD and syn_ratio >= DDOS_SYN_RATIO_THRESHOLD:
                # Calculate PPS if timestamps available
                pps = 0
                if 'TS' in group.columns:
                    times = group['TS'].dropna()
                    if len(times) > 1:
                        duration = times.max() - times.min()
                        pps = int(total_count / max(1, duration))
                
                # Score based on volume and ratio
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
            
            # Calculate PPS if timestamps available
            pps = 0
            duration = 1
            if 'TS' in group.columns:
                times = group['TS'].dropna()
                if len(times) > 1:
                    duration = times.max() - times.min()
                    pps = int(packet_count / max(1, duration))
            
            # Convert to packets per minute for threshold check
            ppm = int(pps * 60) if pps > 0 else packet_count
            
            if ppm >= DDOS_UDP_FLOOD_THRESHOLD:
                # Check for common flood ports
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
                # Count echo requests (type 8)
                echo_requests = len(group[group['ICMP_TYPE'] == 8]) if 'ICMP_TYPE' in group.columns else packet_count
                
                score = min(85, 65 + int(min(20, (packet_count - DDOS_ICMP_FLOOD_THRESHOLD) / 50)))
                
                # Get most targeted destination
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
        # Combine all traffic
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
        
        # Flag high packet rates
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
        # Group by victim IP (receives large responses)
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
        
        # Create indicators for victims
        for victim, data in amplification_map.items():
            if data['queries'] >= 5:  # Minimum queries to consider
                avg_factor = sum(data['factors']) / len(data['factors'])
                score = min(95, 85 + int(min(10, (avg_factor - DDOS_AMPLIFICATION_FACTOR) / 5)))
                
                # Get a representative source
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
            
            # Calculate requests per minute
            rpm = request_count
            if 'TS' in group.columns:
                times = group['TS'].dropna()
                if len(times) > 1:
                    duration_min = (times.max() - times.min()) / 60
                    rpm = int(request_count / max(0.1, duration_min))
            
            if rpm >= DDOS_HTTP_FLOOD_THRESHOLD:
                # Analyze request patterns
                methods = group['METHOD'].value_counts() if 'METHOD' in group.columns else {}
                primary_method = methods.index[0] if len(methods) > 0 else 'UNKNOWN'
                
                # Check for suspicious patterns (same URI repeatedly)
                uri_diversity = len(group['REQUEST'].unique()) if 'REQUEST' in group.columns else 1
                pattern_bonus = 10 if uri_diversity < 5 else 0
                
                score = min(85, 70 + int(min(15, (rpm - DDOS_HTTP_FLOOD_THRESHOLD) / 50)) + pattern_bonus)
                
                # Get most targeted domain
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
        # Combine TCP and UDP traffic
        all_traffic = []
        
        for df, proto in [(tcp_df, 'TCP'), (udp_df, 'UDP')]:
            if df.empty:
                continue
            for dst, group in df.groupby('DST_IP'):
                unique_sources = group['SRC_IP'].nunique() if 'SRC_IP' in group.columns else 0
                total_packets = len(group)
                all_traffic.append((dst, unique_sources, total_packets, proto))
        
        # Detect multi-source attacks
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
        # Analyze TCP traffic for coordinated patterns
        if not tcp_df.empty and 'TS' in tcp_df.columns and 'SIZE' in tcp_df.columns:
            # Group by destination and look for synchronized sources
            for dst, group in tcp_df.groupby('DST_IP'):
                if len(group) < 50:  # Need enough samples
                    continue
                
                # Check for similar packet sizes from multiple sources
                size_groups = group.groupby('SIZE')['SRC_IP'].nunique()
                coordinated_sizes = size_groups[size_groups >= 5]  # 5+ sources with same size
                
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
        
        # Extract C2 IPs and timestamps (if available)
        c2_ips = set()
        for _, row in c2_df.iterrows():
            if row.get('SRC_IP'):
                c2_ips.add(row['SRC_IP'])
            if row.get('DST_IP'):
                c2_ips.add(row['DST_IP'])
        
        # Check for overlap between C2 participants and DDoS sources
        if not tcp_df.empty and 'SRC_IP' in tcp_df.columns:
            ddos_sources = set(ddos_df['SRC_IP'].dropna().unique()) if 'SRC_IP' in ddos_df.columns else set()
            tcp_sources = set(tcp_df['SRC_IP'].dropna().unique())
            
            # Find potential bots (appear in both C2 and attack traffic)
            potential_bots = c2_ips.intersection(tcp_sources)
            
            if len(potential_bots) >= 2:
                # Create correlation indicator
                for c2_ip in c2_ips:
                    bot_count = len(potential_bots)
                    
                    # Get attack types
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
                    break  # Only create one correlation entry
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
        # Ensure SRC_IP and DST_IP columns exist
        if 'SRC_IP' not in df.columns:
            df['SRC_IP'] = ''
        if 'DST_IP' not in df.columns:
            df['DST_IP'] = ''
        
        # Fill NaN values
        df['SRC_IP'] = df['SRC_IP'].fillna('')
        df['DST_IP'] = df['DST_IP'].fillna('')
        
        # Sort by score
        df = df.sort_values(['SCORE', 'COUNT'], ascending=[False, False], ignore_index=True)
    
    # Add C2-DDoS correlation
    c2_ddos_corr = correlate_c2_to_ddos(c2_df, df, tcp_df)
    if not c2_ddos_corr.empty:
        df = pd.concat([c2_ddos_corr, df], ignore_index=True)
    
    return df

# -----------------------
# JS and HTML templates (embedded)
# -----------------------
# Note: These strings are intentionally raw-like content — they will be written to files by pipeline()
JS_TEMPLATE = r"""
// === Dashboard JS (Stability v20.3 - DDoS Detection) ===
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
const c2CommandsData = %%C2COMMANDS%%; // C2 payload detection results

const advData       = %%ADV%%;
const beaconData    = %%BEACON%%;
const dnstunnelData = %%DNSTUNNEL%%;

// DDoS Detection Data
const ddosData      = %%DDOS%%;      // all DDoS detections
const ddosGraphData = %%DDOSGRAPH%%; // DDoS graph subset


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
  
  // DDoS Detection table
  const ddosSlice = (ddosData||[]).slice().sort((a,b)=>(b.SCORE||0)-(a.SCORE||0)).slice(0,topN);
  renderTableRows(document.querySelector('#tbl_ddos tbody'), ddosSlice, ['INDICATOR','TYPE','SCORE','COUNT']);

  // C2 Commands Detection table
  const c2CommandsSlice = (c2CommandsData||[]).slice().sort((a,b)=>(b.SCORE||0)-(a.SCORE||0)).slice(0,topN);
  renderTableRows(document.querySelector('#tbl_c2_commands tbody'), c2CommandsSlice, ['INDICATOR','TYPE','SCORE','IP_COUNT','PARAM_COUNT','PAYLOAD_EXCERPT']);

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
  // DDoS GRAPH
  // ------------------------
  let ddosEdgesForGraph = (ddosGraphData || []).slice();
  if(ddosEdgesForGraph.length > 150){
    console.warn("DDoS graph trimmed to 150 edges for readability.");
    ddosEdgesForGraph = ddosEdgesForGraph.slice(0,150);
  }
  renderC2Graph('ddosgraph', ddosEdgesForGraph);

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
<title>PCAP Dashboard (Stability v20.3 - DDoS Detection)</title>
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
.app{display:flex;min-height:100vh}.sidebar{width:260px;background:#0f1724;color:#fff;padding:18px;font-size:11px}.content{flex:1;padding:18px}.card-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:18px;align-items:start}.card{background:#fff;padding:14px;border-radius:10px;box-shadow:0 6px 18px rgba(13,26,40,0.06);display:flex;flex-direction:column}.chart-box{width:100%;height:220px;min-height:220px;max-height:220px;flex:0 0 auto;position:relative;overflow:hidden}.chart-box canvas{width:100% !important;height:100% !important;display:block}.table-wrap{overflow:auto;max-height:220px;margin-top:8px}.display{width:100%;table-layout:fixed !important;white-space:nowrap}.display th,.display td{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;padding:6px 8px;font-size:11px}#heatmap_canvas{width:100%;height:360px;border:1px solid #e6e9ef;background:#fff;display:block}#c2graph,#ddosgraph{width:100%;height:320px;border:1px solid #e6e9ef;background:#fff}
body.dark { background: #0b1116 !important; color: #e6eef6 !important; }
body.dark .sidebar { background:#071018 !important; color:#e6eef6 !important; }
body.dark .card { background:#0e1620 !important; color:#e6eef6 !important; box-shadow: 0 6px 18px rgba(0,0,0,0.6); }
body.dark .display th, body.dark .display td { color:#d6e6f6 !important; background: transparent !important; }
body.dark #c2graph, body.dark #ddosgraph, body.dark #heatmap_canvas { background:#071018 !important; border-color:#21313d !important; }
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
    <h1 style='margin:0 0 12px 0'>PCAP Analysis Dashboard (Stability v20.3 - DDoS Detection)</h1>

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
      <div class='card'><h3>DDoS Attack Graph</h3><div id='ddosgraph'></div></div>
      <div class='card'><h3>DNS Top</h3><div class='chart-box'><canvas id='chart_dns'></canvas></div><div class='table-wrap'><table id='tbl_dns' class='display'><thead><tr><th>DOMAIN</th><th>COUNT</th><th>PERCENT</th></tr></thead><tbody></tbody></table></div></div>
      <div class='card'><h3>HTTP Top</h3><div class='chart-box'><canvas id='chart_http'></canvas></div><div class='table-wrap'><table id='tbl_http' class='display'><thead><tr><th>DOMAIN</th><th>COUNT</th><th>PERCENT</th></tr></thead><tbody></tbody></table></div></div>
      <div class='card'><h3>TLS SNI / JA3</h3><div class='chart-box'><canvas id='chart_tls'></canvas></div><div class='table-wrap'><table id='tbl_tls' class='display'><thead><tr><th>SNI</th><th>JA3</th><th>SRC_IP</th><th>DST_IP</th><th>COUNT</th><th>PERCENT</th></tr></thead><tbody></tbody></table></div></div>
      <div class='card'><h3>TCP Flags</h3><div class='chart-box'><canvas id='chart_tcp'></canvas></div><div class='table-wrap'><table id='tbl_tcp' class='display'><thead><tr><th>SRC_IP</th><th>DST_IP</th><th>FLAGS</th><th>COUNT</th><th>PERCENT</th></tr></thead><tbody></tbody></table></div></div>
    </div>

    <div style='margin-top:18px' class='card'>
      <h3>DDoS Attack Detection</h3>
      <div class='table-wrap'><table id='tbl_ddos' class='display'><thead><tr><th>INDICATOR</th><th>TYPE</th><th>SCORE</th><th>COUNT</th></tr></thead><tbody></tbody></table></div>
    </div>

    <div style='margin-top:18px' class='card'>
      <h3>C2 Commands Detected (HTTP Payload Analysis)</h3>
      <div class='table-wrap'><table id='tbl_c2_commands' class='display'><thead><tr><th>INDICATOR</th><th>TYPE</th><th>SCORE</th><th>IP_COUNT</th><th>PARAM_COUNT</th><th>PAYLOAD_EXCERPT</th></tr></thead><tbody></tbody></table></div>
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
        print("\n=== Stability v20.3: Starting pipeline with DDoS Detection ===\n")

        print("[1/14] Parsing PCAP (enhanced for DDoS detection)...")
        dns, tcp, http, tls, udp, icmp, dns_detail = parse_streams(pcap)

        print("[2/14] Aggregating DNS...")
        dnsA = agg(dns, ['DOMAIN'])

        print("[3/14] Aggregating HTTP...")
        httpA = agg(http, ['DOMAIN'])

        print("[4/14] Aggregating TLS (ensure columns exist)...")
        tls_cols = ['SNI', 'JA3', 'SRC_IP', 'DST_IP']
        for col in tls_cols:
            if col not in tls.columns:
                tls[col] = None
        tlsA = agg(tls, tls_cols)

        print("[5/14] Aggregating TCP...")
        tcpA = agg(tcp, ['SRC_IP', 'DST_IP', 'FLAGS'])

        print("[6/14] Building HTTP Timeline...")
        timeline = {}
        if os.path.exists(pcap) and PcapReader:
            # Use http dataframe if it already has timestamps
            if not http.empty and 'TS' in http.columns:
                for _, row in http.iterrows():
                    ts = int(row['TS'])
                    key = time.strftime('%Y-%m-%d %H:%M', time.localtime(ts))
                    timeline[key] = timeline.get(key, 0) + 1
        timeline_list = [{'label': k, 'count': v} for k, v in sorted(timeline.items())]

        print("[7/14] Computing full C2 heuristic indicators (with payload analysis)...")
        c2_full = compute_c2_heuristics(dnsA, httpA, tlsA, tcpA, http_full=http)

        # Build graph subset (filtered) for readable graph
        print("[8/14] Preparing compact C2 dataset for graph (filter + cap)...")

        # pick only "graph-worthy" types and high scores, but keep fallback to some rows if empty
        important_prefixes = [
            "JA3 Match",
            "High-Entropy TLS SNI",
            "High-Entropy SNI + Rare JA3",
            "High-Entropy DNS",
            "Rare JA3 Fingerprint",
            "C2 Attack Command",  # Add C2 payload detections
            "Known Botnet C2",
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

        print("[9/14] Computing Advanced Heuristics...")
        adv = compute_advanced_heuristics(dnsA, httpA, tlsA, tcpA, timeline_list)

        print("[10/14] Detecting Beaconing...")
        beacon = detect_beaconing(tcp)

        print("[11/14] Detecting DNS Tunneling...")
        dnstunnel = detect_dnstunneling(dns)
        
        print("[12/14] Extracting C2 Payload Commands...")
        # Extract C2 command detections from c2_full for separate display
        if not c2_full.empty:
            c2_commands = c2_full[c2_full['TYPE'].str.contains('C2 Attack Command|Known Botnet C2', na=False, case=False)].copy()
        else:
            c2_commands = pd.DataFrame(columns=['INDICATOR','TYPE','SCORE','COUNT','SRC_IP','DST_IP'])
        print(f"  - C2 command detections: {len(c2_commands)}")
        
        print("[13/14] Computing DDoS Attack Heuristics...")
        ddos = compute_ddos_heuristics(tcp, udp, icmp, http, dns_detail, c2_full)
        print(f"  - DDoS detections: {len(ddos)}")
        
        print("[14/14] Preparing DDoS graph subset...")
        # Create graph-worthy DDoS subset (similar to C2 graph logic)
        if not ddos.empty:
            ddos_graph = ddos[ddos['SCORE'] >= GRAPH_MIN_SCORE].copy()
            if len(ddos_graph) > MAX_GRAPH_EDGES:
                ddos_graph = ddos_graph.head(MAX_GRAPH_EDGES)
        else:
            ddos_graph = pd.DataFrame(columns=['INDICATOR','TYPE','SCORE','COUNT','SRC_IP','DST_IP'])
        print(f"  - ddos_graph rows: {len(ddos_graph)}")

        # Build JS and HTML files
        print("[15/15] Writing dashboard.js and dashboard.html ...")
        
        # Get detailed C2 command data from http if available
        c2_commands_detailed = detect_c2_payload_patterns(http, tcp) if not http.empty else pd.DataFrame(columns=['INDICATOR','TYPE','SCORE','COUNT','SRC_IP','DST_IP','IP_COUNT','PARAM_COUNT','PAYLOAD_EXCERPT'])
        
        js = (
            JS_TEMPLATE
            .replace('%%DNS%%', safe_js_json(dnsA.to_dict(orient='records')))
            .replace('%%HTTP%%', safe_js_json(httpA.to_dict(orient='records')))
            .replace('%%TLS%%', safe_js_json(tlsA.to_dict(orient='records')))
            .replace('%%TCP%%', safe_js_json(tcpA.to_dict(orient='records')))
            .replace('%%TIMELINE%%', safe_js_json(timeline_list))
            .replace('%%C2GRAPH%%', safe_js_json(c2_graph.to_dict(orient='records')))
            .replace('%%C2FULL%%', safe_js_json(c2_full.to_dict(orient='records')))
            .replace('%%C2COMMANDS%%', safe_js_json(c2_commands_detailed.to_dict(orient='records')))
            .replace('%%ADV%%', safe_js_json(adv.to_dict(orient='records')))
            .replace('%%BEACON%%', safe_js_json(beacon.to_dict(orient='records')))
            .replace('%%DNSTUNNEL%%', safe_js_json(dnstunnel.to_dict(orient='records')))
            .replace('%%DDOS%%', safe_js_json(ddos.to_dict(orient='records')))
            .replace('%%DDOSGRAPH%%', safe_js_json(ddos_graph.to_dict(orient='records')))
        )

        with open('dashboard.js', 'w', encoding='utf-8') as jf:
            jf.write(js)
        print("→ dashboard.js written.")

        html_output = HTML_TEMPLATE.replace('%%FILE%%', pcap)
        with open('dashboard.html', 'w', encoding='utf-8') as hf:
            hf.write(html_output)
        print("→ dashboard.html written.")

        print("\n=== DONE: Stability v20.3 dashboard with DDoS detection generated ===\n")

    except Exception:
        print("\n\n=== PIPELINE CRASH ===")
        traceback.print_exc()
        raise

# -----------------------
# Entry point
# -----------------------
if __name__ == '__main__':
    pipeline()
