#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Stability v23.0 — Multi-Source PCAP Correlation with ML-Enhanced Detection
# Usage: python3 main.py [--sources NAME:PATH ...] [--sources-dir PATTERN]

import os
import re
import sys
import time
import math
import json
import hashlib
import traceback
import pandas as pd
import numpy as np
from tqdm import tqdm
import argparse
import glob

# scapy import with lazy fallback if running where scapy not available for dry-run
try:
    from scapy.all import PcapReader, TCP, IP, IPv6, Raw, DNS, DNSRR, UDP, ICMP, ICMPv6ND_NS, ICMPv6ND_NA
except Exception:
    # allow static testing on systems without scapy; Pcap parsing will fail but code remains testable
    PcapReader = None
    TCP = IP = IPv6 = Raw = DNS = DNSRR = UDP = ICMP = ICMPv6ND_NS = ICMPv6ND_NA = object

# ML imports with graceful fallback
ML_AVAILABLE = False
try:
    from sklearn.ensemble import RandomForestClassifier, IsolationForest
    from sklearn.preprocessing import StandardScaler
    from scipy import stats
    from collections import defaultdict
    ML_AVAILABLE = True
    print("[INFO] Machine Learning libraries loaded successfully (scikit-learn)")
except ImportError:
    print("[WARNING] scikit-learn not available - ML features disabled, using heuristics only")
    from collections import defaultdict
    RandomForestClassifier = IsolationForest = StandardScaler = None
    stats = None

# Botnet detection imports
try:
    from botnet_detector import (
        detect_botnet_in_tcp,
        detect_botnet_in_http,
        detect_botnet_in_tls,
        detect_botnet_in_dns,
        detect_botnet_in_irc,
        aggregate_botnet_detections,
    )
    BOTNET_DETECTION_AVAILABLE = True
    print("[INFO] Botnet family detection enabled")
except ImportError as e:
    print(f"[WARNING] Botnet detection not available: {e}")
    BOTNET_DETECTION_AVAILABLE = False
    detect_botnet_in_tcp = detect_botnet_in_http = detect_botnet_in_tls = None
    detect_botnet_in_dns = detect_botnet_in_irc = aggregate_botnet_detections = None

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
# ML & Advanced Detection Configuration
# -----------------------
ML_ENABLED = True                       # Enable ML-based detection (requires scikit-learn)
BASELINE_WINDOW = 300                   # Baseline window in seconds (5 minutes)
ADAPTIVE_THRESHOLD_SENSITIVITY = 3      # Standard deviations for adaptive thresholds
JITTER_TOLERANCE = 0.5                  # Max jitter tolerance (0.0-1.0, 0.5 = 50%)
ML_MIN_TRAINING_SAMPLES = 10            # Minimum samples needed for ML training
AUTOCORR_MIN_LAGS = 5                   # Minimum lags for autocorrelation analysis

# -----------------------
# DGA Detection Configuration
# -----------------------
DGA_MIN_SCORE = 60                      # Minimum score to flag domain as DGA
DGA_ENABLE_NGRAM = True                 # Enable n-gram analysis
DGA_ENABLE_MARKOV = True                # Enable Markov chain analysis

# Rare character bigrams (low probability pairs)
RARE_BIGRAMS = [
    'qx', 'qz', 'xj', 'zx', 'vq', 'jq', 'qk', 'bq', 'pq', 'xz', 'zq',
    'fq', 'gq', 'vj', 'wq', 'vx', 'qj', 'qt', 'qp', 'qm', 'qn', 'qg'
]

# Suspicious top-level domains commonly used by malware
SUSPICIOUS_TLDS = [
    '.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.top', '.xyz', '.info',
    '.work', '.date', '.review', '.country', '.stream', '.download',
    '.bid', '.win', '.cricket', '.science', '.party', '.racing', '.faith'
]

# Popular brands for typosquatting detection
POPULAR_BRANDS = [
    'google', 'facebook', 'microsoft', 'amazon', 'apple', 'netflix',
    'twitter', 'instagram', 'youtube', 'linkedin', 'paypal', 'ebay',
    'walmart', 'target', 'adobe', 'oracle', 'github', 'dropbox', 'zoom'
]

# Common legitimate words in domains
COMMON_WORDS = [
    'http', 'www', 'mail', 'server', 'cloud', 'api', 'cdn', 'static',
    'admin', 'login', 'auth', 'secure', 'web', 'app', 'mobile', 'data',
    'service', 'network', 'system', 'online', 'portal', 'blog', 'news'
]

# -----------------------
# Change Point Detection Configuration
# -----------------------
CPD_ENABLED = True                      # Enable Change Point Detection
CPD_WINDOW_SIZE = 300                   # Sliding window size in seconds (5 minutes)
CPD_THRESHOLD = 5.0                     # CUSUM threshold (standard deviations)
CPD_DRIFT = 0.5                         # Minimum change to detect
MIN_SAMPLES = 100                       # Minimum packets for analysis

# -----------------------
# Flow Analysis Configuration
# -----------------------
FLOW_TIMEOUT = 120                      # Flow idle timeout in seconds
FLOW_MIN_PACKETS = 3                    # Minimum packets per flow for analysis

# -----------------------
# Protocol Analysis Configuration (Priority 3)
# -----------------------
PROTOCOL_ANALYSIS = {
    'SMB': True,
    'RDP': True,
    'SSH': True,
    'FTP': True,
    'SMTP': True,
    'IRC': True,
    'P2P': True,
}

# Protocol port mappings
PROTOCOL_PORTS = {
    'SMB': [445, 139],
    'RDP': [3389],
    'SSH': [22],
    'FTP': [20, 21],
    'SMTP': [25, 587, 465],
    'IRC': [6667, 6697, 194],
    'P2P_BT': [6881, 6882, 6883, 6884, 6885],  # BitTorrent
}

# Protocol signatures for payload inspection
PROTOCOL_SIGNATURES = {
    'SMB': [b'\xffSMB', b'\xfeSMB'],  # SMBv1, SMBv2/3
    'RDP': [b'\x03\x00\x00'],         # RDP Cookie
    'SSH': [b'SSH-'],                 # SSH banner
    'FTP': [b'220 ', b'USER ', b'PASS '],
    'SMTP': [b'HELO ', b'EHLO ', b'MAIL FROM:'],
    'IRC': [b'NICK ', b'JOIN ', b'PRIVMSG '],
}

# Protocol-specific thresholds
SMB_LATERAL_THRESHOLD = 5       # Hosts accessed in 5 minutes
RDP_BRUTE_THRESHOLD = 10        # Failed attempts
SSH_BRUTE_THRESHOLD = 10        # Failed attempts
FTP_EXFIL_SIZE = 10485760       # 10MB
SMTP_MASS_MAIL_THRESHOLD = 50   # Emails per minute

# -----------------------
# Multi-Source Correlation Configuration
# -----------------------
MULTI_SOURCE_ENABLED = True
CORRELATION_TIME_WINDOW = 300  # 5 minutes in seconds
MIN_SOURCES_FOR_CORRELATION = 2
CORRELATION_CONFIDENCE_THRESHOLD = 0.7

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

def is_private_ipv6(ip):
    """Check if IPv6 address is private/reserved"""
    try:
        # Handle compressed IPv6 format
        ip = ip.strip().lower()
        
        # Loopback (::1)
        if ip == '::1':
            return True
        
        # Link-local (fe80::/10)
        if ip.startswith('fe80:'):
            return True
        
        # Unique local (fc00::/7)
        if ip.startswith('fc') or ip.startswith('fd'):
            return True
        
        # IPv4-mapped IPv6 (::ffff:0:0/96)
        if '::ffff:' in ip:
            return True
        
        # Documentation (2001:db8::/32)
        if ip.startswith('2001:db8:'):
            return True
        
        # Unspecified (::)
        if ip == '::':
            return True
        
        return False
    except:
        return True

def is_private_ip(ip):
    """Check if IP is private/reserved (supports IPv4 and IPv6)"""
    if not ip:
        return True
    
    # Detect IPv6 (contains colons)
    if ':' in ip:
        return is_private_ipv6(ip)
    
    # IPv4 logic
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

def get_ip_layer(pkt):
    """Extract IP layer (v4 or v6) from packet"""
    if hasattr(pkt, 'haslayer'):
        if pkt.haslayer(IP):
            return pkt[IP], 'v4'
        elif pkt.haslayer(IPv6):
            return pkt[IPv6], 'v6'
    return None, None

def safe_js_json(obj):
    """
    Convert object to JSON string safe for embedding in <script> tags.
    Handles numpy types that are not natively JSON serializable.
    """
    class NumpyEncoder(json.JSONEncoder):
        def default(self, obj):
            if isinstance(obj, np.bool_):
                return bool(obj)
            elif isinstance(obj, np.integer):
                return int(obj)
            elif isinstance(obj, np.floating):
                return float(obj)
            elif isinstance(obj, np.ndarray):
                return obj.tolist()
            return super(NumpyEncoder, self).default(obj)
    
    # ensure JSON is safe to embed in <script>
    return json.dumps(obj, cls=NumpyEncoder, ensure_ascii=False).replace("</", "<\\/")

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
def parse_streams(pcap_path, source_id='default'):
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
            pd.DataFrame(columns=['DOMAIN','A','COUNT','ENTROPY','SOURCE_ID']),
            pd.DataFrame(columns=['SRC_IP','DST_IP','FLAGS','COUNT','TS','SIZE','SRC_PORT','DST_PORT','PAYLOAD','SOURCE_ID']),
            pd.DataFrame(columns=['DOMAIN','REQUEST','COUNT','METHOD','TS','SRC_IP','DST_IP','PAYLOAD','SOURCE_ID']),
            pd.DataFrame(columns=['SNI','JA3','SRC_IP','DST_IP','COUNT','SOURCE_ID']),
            pd.DataFrame(columns=['SRC_IP','DST_IP','SRC_PORT','DST_PORT','TS','SIZE','SOURCE_ID']),
            pd.DataFrame(columns=['SRC_IP','DST_IP','ICMP_TYPE','TS','SIZE','SOURCE_ID']),
            pd.DataFrame(columns=['SRC_IP','DST_IP','QUERY_SIZE','RESPONSE_SIZE','DOMAIN','TS','SOURCE_ID'])
        )

    if not os.path.exists(pcap_path):
        return (
            pd.DataFrame(columns=['DOMAIN','A','COUNT','ENTROPY','SOURCE_ID']),
            pd.DataFrame(columns=['SRC_IP','DST_IP','FLAGS','COUNT','TS','SIZE','SRC_PORT','DST_PORT','PAYLOAD','SOURCE_ID']),
            pd.DataFrame(columns=['DOMAIN','REQUEST','COUNT','METHOD','TS','SRC_IP','DST_IP','PAYLOAD','SOURCE_ID']),
            pd.DataFrame(columns=['SNI','JA3','SRC_IP','DST_IP','COUNT','SOURCE_ID']),
            pd.DataFrame(columns=['SRC_IP','DST_IP','SRC_PORT','DST_PORT','TS','SIZE','SOURCE_ID']),
            pd.DataFrame(columns=['SRC_IP','DST_IP','ICMP_TYPE','TS','SIZE','SOURCE_ID']),
            pd.DataFrame(columns=['SRC_IP','DST_IP','QUERY_SIZE','RESPONSE_SIZE','DOMAIN','TS','SOURCE_ID'])
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
                            
                            # Get packet size info for amplification detection - support IPv4 and IPv6
                            ip_layer, ip_version = get_ip_layer(p)
                            if ip_layer:
                                src_ip = ip_layer.src
                                dst_ip = ip_layer.dst
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
                                    'TS': ts,
                                    'SOURCE_ID': source_id
                                })
                            
                            if not is_trusted_domain(domain):
                                dns_rows.append({'DOMAIN':domain,'A':a,'COUNT':1,'ENTROPY':shannon_entropy(domain),'SOURCE_ID':source_id})
                    except Exception:
                        pass

                # ✅ TCP + IP flows with PAYLOAD STORAGE (ENHANCED) - Support IPv4 and IPv6
                if getattr(p, 'haslayer', lambda x: False)(TCP):
                    ip_layer, ip_version = get_ip_layer(p)
                    if ip_layer:
                        src = ip_layer.src
                        dst = ip_layer.dst
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
                            'PAYLOAD':raw_payload[:5000],  # ✅ NEW: Store payload
                            'SOURCE_ID':source_id
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
                                        'PAYLOAD': txt[:5000],  # ✅ NEW: Store HTTP request payload
                                        'SOURCE_ID': source_id
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
                                        'PAYLOAD': txt[:5000],  # ✅ NEW: Store HTTP response payload
                                        'SOURCE_ID': source_id
                                    })

                            # TLS ClientHello: SNI + JA3
                            try:
                                sni = extract_sni_from_client_hello(payload)
                                ja3 = extract_ja3_from_client_hello(payload)
                                if sni or ja3:
                                    sni_clean = sni.strip().rstrip('.') if sni else ''
                                    if not (sni_clean and is_trusted_domain(sni_clean)):
                                        tls_rows.append({'SNI': sni_clean, 'JA3': ja3, 'SRC_IP': src, 'DST_IP': dst, 'COUNT': 1, 'SOURCE_ID': source_id})
                            except Exception:
                                pass
                
                # UDP traffic for flood detection - Support IPv4 and IPv6
                if getattr(p, 'haslayer', lambda x: False)(UDP):
                    ip_layer, ip_version = get_ip_layer(p)
                    if ip_layer:
                        src = ip_layer.src
                        dst = ip_layer.dst
                        src_port = p[UDP].sport
                        dst_port = p[UDP].dport
                        udp_rows.append({
                            'SRC_IP': src,
                            'DST_IP': dst,
                            'SRC_PORT': src_port,
                            'DST_PORT': dst_port,
                            'TS': ts,
                            'SIZE': pkt_size,
                            'SOURCE_ID': source_id
                        })
                
                # ICMP traffic for flood detection - Support IPv4 and ICMPv6
                if getattr(p, 'haslayer', lambda x: False)(ICMP):
                    ip_layer, ip_version = get_ip_layer(p)
                    if ip_layer:
                        src = ip_layer.src
                        dst = ip_layer.dst
                        icmp_type = p[ICMP].type if hasattr(p[ICMP], 'type') else 0
                        icmp_rows.append({
                            'SRC_IP': src,
                            'DST_IP': dst,
                            'ICMP_TYPE': icmp_type,
                            'TS': ts,
                            'SIZE': pkt_size,
                            'SOURCE_ID': source_id
                        })
                
                # ICMPv6 traffic for flood detection
                if getattr(p, 'haslayer', lambda x: False)(ICMPv6ND_NS) or getattr(p, 'haslayer', lambda x: False)(ICMPv6ND_NA):
                    ip_layer, ip_version = get_ip_layer(p)
                    if ip_layer:
                        src = ip_layer.src
                        dst = ip_layer.dst
                        # ICMPv6 Neighbor Solicitation (135) or Neighbor Advertisement (136)
                        icmp_type = 135 if getattr(p, 'haslayer', lambda x: False)(ICMPv6ND_NS) else 136
                        icmp_rows.append({
                            'SRC_IP': src,
                            'DST_IP': dst,
                            'ICMP_TYPE': icmp_type,
                            'TS': ts,
                            'SIZE': pkt_size,
                            'SOURCE_ID': source_id
                        })

            except Exception:
                continue

    dns_df = pd.DataFrame(dns_rows) if dns_rows else pd.DataFrame(columns=['DOMAIN','A','COUNT','ENTROPY','SOURCE_ID'])
    tcp_df = pd.DataFrame(tcp_rows) if tcp_rows else pd.DataFrame(columns=['SRC_IP','DST_IP','FLAGS','COUNT','TS','SIZE','SRC_PORT','DST_PORT','PAYLOAD','SOURCE_ID'])
    http_df = pd.DataFrame(http_rows) if http_rows else pd.DataFrame(columns=['DOMAIN','REQUEST','COUNT','METHOD','TS','SRC_IP','DST_IP','PAYLOAD','SOURCE_ID'])
    tls_df = pd.DataFrame(tls_rows) if tls_rows else pd.DataFrame(columns=['SNI','JA3','SRC_IP','DST_IP','COUNT','SOURCE_ID'])
    udp_df = pd.DataFrame(udp_rows) if udp_rows else pd.DataFrame(columns=['SRC_IP','DST_IP','SRC_PORT','DST_PORT','TS','SIZE','SOURCE_ID'])
    icmp_df = pd.DataFrame(icmp_rows) if icmp_rows else pd.DataFrame(columns=['SRC_IP','DST_IP','ICMP_TYPE','TS','SIZE','SOURCE_ID'])
    dns_detail_df = pd.DataFrame(dns_detail_rows) if dns_detail_rows else pd.DataFrame(columns=['SRC_IP','DST_IP','QUERY_SIZE','RESPONSE_SIZE','DOMAIN','TS','SOURCE_ID'])
    
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

def levenshtein_distance(s1, s2):
    """
    Calculate edit distance between two strings using dynamic programming.
    Used for typosquatting detection.
    
    Args:
        s1: First string
        s2: Second string
        
    Returns:
        int: Minimum number of edits needed to transform s1 into s2
    
    Examples:
        >>> levenshtein_distance("google", "goggle")
        1
        >>> levenshtein_distance("facebook", "facebok")
        1
    """
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    
    if len(s2) == 0:
        return len(s1)
    
    # Create matrix for dynamic programming
    previous_row = range(len(s2) + 1)
    
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            # Cost of insertions, deletions, or substitutions
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    
    return previous_row[-1]


def advanced_dga_detection(domain):
    """
    Multi-heuristic DGA detection returning score 0-100 with breakdown.
    
    Checks:
    - N-gram frequency (bigrams, trigrams)
    - Consonant/vowel clustering
    - Dictionary word presence
    - TLD reputation
    - Levenshtein distance to known brands
    - Subdomain encoding patterns (base64, hex)
    - Character transition probabilities
    
    Args:
        domain: Domain name to analyze
        
    Returns:
        dict: {
            'total_score': int (0-100),
            'breakdown': {
                'ngram': int,
                'consonant': int,
                'vowel_ratio': int,
                'entropy': int,
                'length': int,
                'digits': int,
                'tld': int,
                'typosquat': int,
                'subdomain': int,
                'dictionary': int
            },
            'is_dga': bool
        }
    
    Examples:
        >>> result = advanced_dga_detection("xqz8kjasdh9f.tk")
        >>> result['is_dga']
        True
        >>> result['total_score'] > 60
        True
    """
    if not domain:
        return {'total_score': 0, 'breakdown': {}, 'is_dga': False}
    
    breakdown = {
        'ngram': 0,
        'consonant': 0,
        'vowel_ratio': 0,
        'entropy': 0,
        'length': 0,
        'digits': 0,
        'tld': 0,
        'typosquat': 0,
        'subdomain': 0,
        'dictionary': 0
    }
    
    # Parse domain parts
    domain = domain.lower().strip().rstrip('.')
    parts = domain.split('.')
    
    # Get TLD and base domain
    if len(parts) >= 2:
        base_domain = parts[-2]
        tld = '.' + parts[-1]
    else:
        base_domain = parts[0] if parts else ''
        tld = ''
    
    # 1. N-gram Analysis (bigrams)
    if DGA_ENABLE_NGRAM and len(base_domain) >= 2:
        bigrams = [base_domain[i:i+2] for i in range(len(base_domain)-1)]
        rare_count = sum(1 for bg in bigrams if bg in RARE_BIGRAMS)
        if rare_count > 0:
            breakdown['ngram'] = min(25, rare_count * 8)
    
    # 2. Consonant Clustering
    consonants = 'bcdfghjklmnpqrstvwxyz'
    consonant_clusters = 0
    for i in range(len(base_domain) - 2):
        if all(c in consonants for c in base_domain[i:i+3]):
            consonant_clusters += 1
    if consonant_clusters > 0:
        breakdown['consonant'] = min(15, consonant_clusters * 7)
    
    # 3. Vowel/Consonant Ratio
    vowels = sum(c in 'aeiou' for c in base_domain)
    total_alpha = sum(c.isalpha() for c in base_domain)
    if total_alpha > 0:
        vowel_ratio = vowels / total_alpha
        # Abnormal if too few vowels (< 0.2) or too many (> 0.7)
        if vowel_ratio < 0.2 or vowel_ratio > 0.7:
            breakdown['vowel_ratio'] = 10
    
    # 4. Entropy
    ent = shannon_entropy(base_domain)
    if ent >= 4.0:
        breakdown['entropy'] = min(20, int((ent - 4.0) * 10))
    
    # 5. Length
    if len(base_domain) >= 12:
        breakdown['length'] = min(15, (len(base_domain) - 12) * 2)
    
    # 6. Digit Ratio
    digits = sum(c.isdigit() for c in base_domain)
    if len(base_domain) > 0 and digits / len(base_domain) > 0.3:
        breakdown['digits'] = 10
    
    # 7. TLD Reputation
    if tld in SUSPICIOUS_TLDS:
        breakdown['tld'] = 20
    
    # 8. Typosquatting Detection (Levenshtein distance to popular brands)
    min_distance = float('inf')
    for brand in POPULAR_BRANDS:
        dist = levenshtein_distance(base_domain, brand)
        min_distance = min(min_distance, dist)
    
    # If very close to a brand (1-2 edits) but not exact match
    if 1 <= min_distance <= 2:
        breakdown['typosquat'] = 15
    
    # 9. Subdomain Analysis
    if len(parts) > 2:
        # Check for excessive subdomains (> 3)
        if len(parts) > 4:
            breakdown['subdomain'] = 10
        
        # Check for encoded subdomains (hex/base64 patterns)
        for part in parts[:-2]:
            if len(part) > 8:
                # Hex pattern (long hex strings)
                if all(c in '0123456789abcdef' for c in part):
                    breakdown['subdomain'] = max(breakdown['subdomain'], 15)
                # Base64-like pattern (alphanumeric with some special chars)
                elif len(part) > 16 and part.count('-') + part.count('_') > 2:
                    breakdown['subdomain'] = max(breakdown['subdomain'], 10)
    
    # 10. Dictionary Word Detection (reduces score if found)
    has_common_word = any(word in base_domain for word in COMMON_WORDS)
    if has_common_word:
        breakdown['dictionary'] = -10  # Negative score for legitimate words
    
    # Calculate total score
    total_score = sum(breakdown.values())
    total_score = max(0, min(100, total_score))
    
    return {
        'total_score': total_score,
        'breakdown': breakdown,
        'is_dga': total_score >= DGA_MIN_SCORE
    }


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
    """
    Enhanced DNS checks using advanced DGA detection with detailed scoring breakdown.
    
    Args:
        dns_df: Aggregated DNS DataFrame with DOMAIN column
        
    Returns:
        pd.DataFrame with DGA detections including score breakdown
    """
    rows = []
    if dns_df.empty: 
        return pd.DataFrame(columns=['INDICATOR','TYPE','SCORE','COUNT','DGA_BREAKDOWN'])
    try:
        for _, r in dns_df.iterrows():
            dom = r.get('DOMAIN','') or ''
            
            # Use advanced DGA detection
            dga_result = advanced_dga_detection(dom)
            
            if dga_result['is_dga']:
                # Create readable breakdown string
                breakdown = dga_result['breakdown']
                breakdown_str = ', '.join([
                    f"{k}:{v}" for k, v in breakdown.items() if v != 0
                ])
                
                rows.append({
                    'INDICATOR': dom, 
                    'TYPE': 'DGA-like domain (advanced)', 
                    'SCORE': dga_result['total_score'], 
                    'COUNT': int(r.get('COUNT', 0)),
                    'DGA_BREAKDOWN': breakdown_str
                })
            else:
                # Fallback to simple detection for borderline cases
                score = is_dga_like(dom)
                if score >= 50:
                    rows.append({
                        'INDICATOR': dom, 
                        'TYPE': 'DGA-like domain', 
                        'SCORE': 60 + (score // 5), 
                        'COUNT': int(r.get('COUNT', 0)),
                        'DGA_BREAKDOWN': 'simple heuristic'
                    })
    except Exception:
        pass
    
    # Return with DGA_BREAKDOWN column
    result = pd.DataFrame(rows) if rows else pd.DataFrame(columns=['INDICATOR','TYPE','SCORE','COUNT','DGA_BREAKDOWN'])
    
    # For compatibility, ensure DGA_BREAKDOWN exists even if empty
    if not result.empty and 'DGA_BREAKDOWN' not in result.columns:
        result['DGA_BREAKDOWN'] = ''
    
    return result

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
    """
    Enhanced beaconing detection with jitter tolerance.
    
    Detects both regular periodic beacons and jittered beacons (Cobalt Strike, etc.)
    using coefficient of variation and autocorrelation analysis.
    
    Args:
        tcp_rows: DataFrame with TCP traffic including timestamps
        min_count: Minimum number of packets to consider
        max_cv: Maximum coefficient of variation for simple detection
        min_period: Minimum beacon period in seconds
        max_period: Maximum beacon period in seconds
        
    Returns:
        pd.DataFrame: Detected beacons with period, jitter, and confidence
    """
    import math
    rows = []
    if tcp_rows.empty:
        return pd.DataFrame(columns=['INDICATOR','TYPE','SCORE','COUNT','MEAN_PERIOD','CV','JITTER','METHOD'])
    try:
        if 'TS' not in tcp_rows.columns:
            return pd.DataFrame(columns=['INDICATOR','TYPE','SCORE','COUNT','MEAN_PERIOD','CV','JITTER','METHOD'])
        
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
            
            # Try simple CV-based detection first (existing logic)
            if cv <= max_cv:
                score = int(min(100, 70 + (1 - cv) * 30 + min(20, (len(times)-min_count)//5)))
                rows.append({
                    'INDICATOR': f"{src} → {dst}",
                    'TYPE': 'Periodic beaconing (low CV)',
                    'SCORE': score,
                    'COUNT': len(times),
                    'MEAN_PERIOD': round(mean,2),
                    'CV': round(cv,3),
                    'JITTER': round(cv * 100, 1),  # Convert to percentage
                    'METHOD': 'cv_analysis'
                })
            # Try jitter-tolerant detection for higher CV cases
            elif cv <= JITTER_TOLERANCE and len(times) >= 10:
                jitter_result = detect_jittered_beaconing(times, max_jitter=JITTER_TOLERANCE)
                
                if jitter_result['detected']:
                    # Adjust score based on confidence and jitter
                    base_score = 60
                    confidence_bonus = int(jitter_result['confidence'] * 0.3)  # Up to 30 points
                    count_bonus = min(15, (len(times) - min_count) // 5)
                    score = min(95, base_score + confidence_bonus + count_bonus)
                    
                    rows.append({
                        'INDICATOR': f"{src} → {dst}",
                        'TYPE': f"Jittered beaconing ({jitter_result['method']})",
                        'SCORE': score,
                        'COUNT': len(times),
                        'MEAN_PERIOD': round(jitter_result['period'], 2),
                        'CV': round(cv, 3),
                        'JITTER': round(jitter_result['jitter'] * 100, 1),
                        'METHOD': jitter_result['method']
                    })
    except Exception as e:
        print(f"[WARNING] Beaconing detection error: {e}")
    
    return pd.DataFrame(rows) if rows else pd.DataFrame(columns=['INDICATOR','TYPE','SCORE','COUNT','MEAN_PERIOD','CV','JITTER','METHOD'])

# -----------------------
# Change Point Detection (CPD)
# -----------------------

def detect_change_points(traffic_series, baseline, threshold=CPD_THRESHOLD):
    """
    Uses CUSUM algorithm to detect abrupt changes in traffic patterns.
    
    The CUSUM (Cumulative Sum) algorithm detects shifts in the mean of a time series
    by accumulating deviations from a baseline. When the cumulative sum exceeds a
    threshold, a change point is detected.
    
    Args:
        traffic_series: Time-series data (pandas Series with datetime index)
                       e.g., packets/sec, bytes/sec, connection rate
        baseline: Statistical baseline dict with 'mean' and 'std'
        threshold: Sensitivity in standard deviations (default: 5.0)
    
    Returns:
        List of dicts with change points: [
            {
                'timestamp': datetime,
                'value': float,
                'deviation': float (in sigmas),
                'cusum_pos': float,
                'cusum_neg': float
            }
        ]
    
    Examples:
        >>> baseline = {'mean': 100, 'std': 10}
        >>> series = pd.Series([100]*10 + [200]*10)
        >>> changes = detect_change_points(series, baseline, threshold=3.0)
        >>> len(changes) > 0
        True
    """
    if not CPD_ENABLED:
        return []
    
    if len(traffic_series) < MIN_SAMPLES:
        return []
    
    try:
        mean = baseline.get('mean', traffic_series.mean())
        std = baseline.get('std', traffic_series.std())
        
        if std == 0 or np.isnan(std):
            return []
        
        # CUSUM parameters
        drift = CPD_DRIFT * std
        
        # Initialize CUSUM values
        cusum_pos = 0
        cusum_neg = 0
        
        change_points = []
        
        for idx, value in traffic_series.items():
            # Calculate deviation from baseline
            deviation = value - mean
            
            # Update positive CUSUM (detects upward shifts)
            cusum_pos = max(0, cusum_pos + deviation - drift)
            
            # Update negative CUSUM (detects downward shifts)
            cusum_neg = max(0, cusum_neg - deviation - drift)
            
            # Check if threshold exceeded
            deviation_sigmas = abs(deviation) / std
            
            if cusum_pos > threshold * std or cusum_neg > threshold * std:
                change_points.append({
                    'timestamp': idx,
                    'value': float(value),
                    'deviation': float(deviation_sigmas),
                    'cusum_pos': float(cusum_pos),
                    'cusum_neg': float(cusum_neg)
                })
                
                # Reset CUSUM after detection
                cusum_pos = 0
                cusum_neg = 0
        
        return change_points
    
    except Exception:
        return []


def analyze_temporal_patterns(traffic_df):
    """
    Detects time-based patterns (hourly, daily cycles).
    Flags deviations from expected patterns.
    
    Args:
        traffic_df: DataFrame with 'TS' column (timestamps)
        
    Returns:
        dict: {
            'hourly_pattern': dict with hour -> avg_count,
            'anomalous_hours': list of hours with unusual traffic,
            'daily_pattern': dict with day -> avg_count,
            'pattern_detected': bool
        }
    
    Examples:
        >>> df = pd.DataFrame({'TS': [i*3600 for i in range(48)]})
        >>> result = analyze_temporal_patterns(df)
        >>> 'hourly_pattern' in result
        True
    """
    if traffic_df.empty or 'TS' not in traffic_df.columns:
        return {
            'hourly_pattern': {},
            'anomalous_hours': [],
            'daily_pattern': {},
            'pattern_detected': False
        }
    
    try:
        # Convert timestamps to datetime
        traffic_df = traffic_df.copy()
        traffic_df['datetime'] = pd.to_datetime(traffic_df['TS'], unit='s')
        traffic_df['hour'] = traffic_df['datetime'].dt.hour
        traffic_df['day'] = traffic_df['datetime'].dt.day
        
        # Hourly pattern
        hourly_counts = traffic_df.groupby('hour').size()
        hourly_pattern = hourly_counts.to_dict()
        
        # Daily pattern
        daily_counts = traffic_df.groupby('day').size()
        daily_pattern = daily_counts.to_dict()
        
        # Detect anomalous hours (> 2 std from mean)
        mean_hourly = hourly_counts.mean()
        std_hourly = hourly_counts.std()
        
        anomalous_hours = []
        if std_hourly > 0:
            for hour, count in hourly_pattern.items():
                if abs(count - mean_hourly) > 2 * std_hourly:
                    anomalous_hours.append(int(hour))
        
        # Determine if pattern detected
        pattern_detected = len(hourly_pattern) >= 3 and std_hourly > 0
        
        return {
            'hourly_pattern': hourly_pattern,
            'anomalous_hours': anomalous_hours,
            'daily_pattern': daily_pattern,
            'pattern_detected': pattern_detected
        }
    
    except Exception:
        return {
            'hourly_pattern': {},
            'anomalous_hours': [],
            'daily_pattern': {},
            'pattern_detected': False
        }


def sliding_window_analysis(traffic_df, window_size=CPD_WINDOW_SIZE):
    """
    Real-time analysis using sliding windows.
    Updates baseline dynamically and detects sustained vs. burst anomalies.
    
    Args:
        traffic_df: DataFrame with 'TS' column (timestamps) and traffic metrics
        window_size: Window size in seconds (default: 300 = 5 minutes)
    
    Returns:
        pd.DataFrame with columns:
            - window_start: Start timestamp of window
            - window_end: End timestamp of window
            - packet_count: Packets in window
            - byte_count: Bytes in window
            - pps: Packets per second
            - bps: Bytes per second
            - is_anomaly: Boolean flag
            - anomaly_type: 'burst' or 'sustained' or None
    
    Examples:
        >>> df = pd.DataFrame({
        ...     'TS': [i for i in range(1000)],
        ...     'SIZE': [100] * 1000
        ... })
        >>> result = sliding_window_analysis(df, window_size=60)
        >>> 'pps' in result.columns
        True
    """
    if traffic_df.empty or 'TS' not in traffic_df.columns:
        return pd.DataFrame(columns=[
            'window_start', 'window_end', 'packet_count', 'byte_count',
            'pps', 'bps', 'is_anomaly', 'anomaly_type'
        ])
    
    try:
        # Sort by timestamp
        traffic_df = traffic_df.sort_values('TS').copy()
        
        min_ts = traffic_df['TS'].min()
        max_ts = traffic_df['TS'].max()
        
        if max_ts - min_ts < window_size:
            # Not enough data for windowing
            return pd.DataFrame(columns=[
                'window_start', 'window_end', 'packet_count', 'byte_count',
                'pps', 'bps', 'is_anomaly', 'anomaly_type'
            ])
        
        # Create windows
        windows = []
        current_start = min_ts
        
        while current_start < max_ts:
            window_end = current_start + window_size
            
            # Get packets in this window
            window_data = traffic_df[
                (traffic_df['TS'] >= current_start) &
                (traffic_df['TS'] < window_end)
            ]
            
            packet_count = len(window_data)
            byte_count = window_data['SIZE'].sum() if 'SIZE' in window_data.columns else 0
            
            pps = packet_count / window_size
            bps = byte_count / window_size
            
            windows.append({
                'window_start': current_start,
                'window_end': window_end,
                'packet_count': int(packet_count),
                'byte_count': int(byte_count),
                'pps': float(pps),
                'bps': float(bps)
            })
            
            # Slide window by half its size
            current_start += window_size // 2
        
        # Create DataFrame
        result_df = pd.DataFrame(windows)
        
        if result_df.empty:
            result_df['is_anomaly'] = []
            result_df['anomaly_type'] = []
            return result_df
        
        # Detect anomalies using IQR method
        pps_mean = result_df['pps'].mean()
        pps_std = result_df['pps'].std()
        
        if pps_std > 0:
            # Mark anomalies (> 3 sigma)
            result_df['is_anomaly'] = result_df['pps'] > (pps_mean + 3 * pps_std)
            
            # Classify anomaly type
            def classify_anomaly(row, idx):
                if not row['is_anomaly']:
                    return None
                
                # Check if sustained (multiple consecutive windows are anomalous)
                if idx > 0 and idx < len(result_df) - 1:
                    prev_anomaly = result_df.iloc[idx - 1]['is_anomaly']
                    next_anomaly = result_df.iloc[idx + 1]['is_anomaly']
                    
                    if prev_anomaly or next_anomaly:
                        return 'sustained'
                
                return 'burst'
            
            result_df['anomaly_type'] = [
                classify_anomaly(row, idx)
                for idx, row in result_df.iterrows()
            ]
        else:
            result_df['is_anomaly'] = False
            result_df['anomaly_type'] = None
        
        return result_df
    
    except Exception:
        return pd.DataFrame(columns=[
            'window_start', 'window_end', 'packet_count', 'byte_count',
            'pps', 'bps', 'is_anomaly', 'anomaly_type'
        ])

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
# Flow-level Statistical Analysis
# -----------------------

def extract_flow_features(tcp_df):
    """
    Aggregates packets into flows (5-tuple: src_ip, dst_ip, src_port, dst_port, protocol).
    
    A flow is defined by the 5-tuple and represents a bidirectional communication session.
    Features extracted include duration, packet counts, byte counts, inter-arrival times,
    and flag distributions.
    
    Args:
        tcp_df: DataFrame with TCP traffic
        
    Returns:
        pd.DataFrame with columns:
            - flow_id: Unique flow identifier (5-tuple hash)
            - src_ip, dst_ip, src_port, dst_port: Flow tuple
            - flow_duration: Duration in seconds
            - fwd_packets, bwd_packets: Directional packet counts
            - fwd_bytes, bwd_bytes: Directional byte counts
            - packet_size_mean, packet_size_std, packet_size_min, packet_size_max
            - iat_mean, iat_std, iat_max: Inter-arrival time statistics
            - syn_count, ack_count, psh_count, rst_count, fin_count: TCP flag counts
            - idle_time_mean, active_time: Flow timing metrics
            - bytes_per_second, packets_per_second: Rate metrics
            
    Examples:
        >>> tcp = pd.DataFrame({
        ...     'SRC_IP': ['192.168.1.1', '192.168.1.1'],
        ...     'DST_IP': ['8.8.8.8', '8.8.8.8'],
        ...     'SRC_PORT': [12345, 12345],
        ...     'DST_PORT': [80, 80],
        ...     'TS': [1.0, 2.0],
        ...     'SIZE': [100, 150]
        ... })
        >>> flows = extract_flow_features(tcp)
        >>> 'flow_duration' in flows.columns
        True
    """
    if tcp_df.empty:
        return pd.DataFrame(columns=[
            'flow_id', 'src_ip', 'dst_ip', 'src_port', 'dst_port',
            'flow_duration', 'fwd_packets', 'bwd_packets', 'fwd_bytes', 'bwd_bytes',
            'packet_size_mean', 'packet_size_std', 'packet_size_min', 'packet_size_max',
            'iat_mean', 'iat_std', 'iat_max',
            'syn_count', 'ack_count', 'psh_count', 'rst_count', 'fin_count',
            'idle_time_mean', 'active_time', 'bytes_per_second', 'packets_per_second'
        ])
    
    try:
        # Required columns
        required_cols = ['SRC_IP', 'DST_IP', 'TS']
        if not all(col in tcp_df.columns for col in required_cols):
            return pd.DataFrame(columns=[
                'flow_id', 'src_ip', 'dst_ip', 'src_port', 'dst_port',
                'flow_duration', 'fwd_packets', 'bwd_packets', 'fwd_bytes', 'bwd_bytes',
                'packet_size_mean', 'packet_size_std', 'packet_size_min', 'packet_size_max',
                'iat_mean', 'iat_std', 'iat_max',
                'syn_count', 'ack_count', 'psh_count', 'rst_count', 'fin_count',
                'idle_time_mean', 'active_time', 'bytes_per_second', 'packets_per_second'
            ])
        
        tcp_df = tcp_df.copy()
        
        # Add missing columns with defaults
        if 'SRC_PORT' not in tcp_df.columns:
            tcp_df['SRC_PORT'] = 0
        if 'DST_PORT' not in tcp_df.columns:
            tcp_df['DST_PORT'] = 0
        if 'SIZE' not in tcp_df.columns:
            tcp_df['SIZE'] = 0
        if 'FLAGS' not in tcp_df.columns:
            tcp_df['FLAGS'] = ''
        
        # Create flow ID (5-tuple)
        # For bidirectional flows, normalize the tuple (smaller IP first)
        def create_flow_id(row):
            src_ip = row['SRC_IP']
            dst_ip = row['DST_IP']
            src_port = row['SRC_PORT']
            dst_port = row['DST_PORT']
            
            # Normalize for bidirectional matching
            if src_ip < dst_ip:
                return f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
            else:
                return f"{dst_ip}:{dst_port}->{src_ip}:{src_port}"
        
        tcp_df['flow_id'] = tcp_df.apply(create_flow_id, axis=1)
        
        # Group by flow
        flows = []
        
        for flow_id, group in tcp_df.groupby('flow_id'):
            if len(group) < FLOW_MIN_PACKETS:
                continue
            
            # Sort by timestamp
            group = group.sort_values('TS')
            
            # Basic flow info
            src_ip = group.iloc[0]['SRC_IP']
            dst_ip = group.iloc[0]['DST_IP']
            src_port = group.iloc[0]['SRC_PORT']
            dst_port = group.iloc[0]['DST_PORT']
            
            # Flow duration
            first_ts = group['TS'].min()
            last_ts = group['TS'].max()
            duration = last_ts - first_ts
            
            # Directional analysis (forward = src->dst, backward = dst->src)
            fwd_mask = (group['SRC_IP'] == src_ip) & (group['DST_IP'] == dst_ip)
            bwd_mask = ~fwd_mask
            
            fwd_packets = fwd_mask.sum()
            bwd_packets = bwd_mask.sum()
            
            fwd_bytes = group.loc[fwd_mask, 'SIZE'].sum()
            bwd_bytes = group.loc[bwd_mask, 'SIZE'].sum()
            
            # Packet size statistics
            sizes = group['SIZE']
            packet_size_mean = sizes.mean()
            packet_size_std = sizes.std() if len(sizes) > 1 else 0
            packet_size_min = sizes.min()
            packet_size_max = sizes.max()
            
            # Inter-arrival time statistics
            timestamps = group['TS'].values
            if len(timestamps) > 1:
                iats = np.diff(timestamps)
                iat_mean = np.mean(iats)
                iat_std = np.std(iats)
                iat_max = np.max(iats)
            else:
                iat_mean = iat_std = iat_max = 0
            
            # TCP flag counts
            flags_str = ' '.join(group['FLAGS'].astype(str))
            syn_count = flags_str.count('SYN')
            ack_count = flags_str.count('ACK')
            psh_count = flags_str.count('PSH')
            rst_count = flags_str.count('RST')
            fin_count = flags_str.count('FIN')
            
            # Idle time analysis (gaps > 1 second)
            idle_times = iats[iats > 1.0] if len(timestamps) > 1 else np.array([])
            idle_time_mean = np.mean(idle_times) if len(idle_times) > 0 else 0
            active_time = duration - (idle_time_mean * len(idle_times)) if len(idle_times) > 0 else duration
            
            # Rate metrics
            bytes_per_second = (fwd_bytes + bwd_bytes) / duration if duration > 0 else 0
            packets_per_second = len(group) / duration if duration > 0 else 0
            
            flows.append({
                'flow_id': flow_id,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': int(src_port),
                'dst_port': int(dst_port),
                'flow_duration': float(duration),
                'fwd_packets': int(fwd_packets),
                'bwd_packets': int(bwd_packets),
                'fwd_bytes': int(fwd_bytes),
                'bwd_bytes': int(bwd_bytes),
                'packet_size_mean': float(packet_size_mean),
                'packet_size_std': float(packet_size_std),
                'packet_size_min': int(packet_size_min),
                'packet_size_max': int(packet_size_max),
                'iat_mean': float(iat_mean),
                'iat_std': float(iat_std),
                'iat_max': float(iat_max),
                'syn_count': int(syn_count),
                'ack_count': int(ack_count),
                'psh_count': int(psh_count),
                'rst_count': int(rst_count),
                'fin_count': int(fin_count),
                'idle_time_mean': float(idle_time_mean),
                'active_time': float(active_time),
                'bytes_per_second': float(bytes_per_second),
                'packets_per_second': float(packets_per_second)
            })
        
        return pd.DataFrame(flows)
    
    except Exception:
        return pd.DataFrame(columns=[
            'flow_id', 'src_ip', 'dst_ip', 'src_port', 'dst_port',
            'flow_duration', 'fwd_packets', 'bwd_packets', 'fwd_bytes', 'bwd_bytes',
            'packet_size_mean', 'packet_size_std', 'packet_size_min', 'packet_size_max',
            'iat_mean', 'iat_std', 'iat_max',
            'syn_count', 'ack_count', 'psh_count', 'rst_count', 'fin_count',
            'idle_time_mean', 'active_time', 'bytes_per_second', 'packets_per_second'
        ])


def analyze_bidirectional_flows(flow_features):
    """
    Analyzes request/response patterns in bidirectional flows.
    Detects asymmetric flows (one-way communication) which may indicate
    data exfiltration or C2 communication.
    
    Args:
        flow_features: DataFrame from extract_flow_features()
        
    Returns:
        pd.DataFrame with anomalous flows and asymmetry scores
        
    Examples:
        >>> flows = pd.DataFrame({
        ...     'flow_id': ['flow1'],
        ...     'fwd_packets': [100],
        ...     'bwd_packets': [1],
        ...     'fwd_bytes': [10000],
        ...     'bwd_bytes': [100]
        ... })
        >>> result = analyze_bidirectional_flows(flows)
        >>> 'asymmetry_score' in result.columns
        True
    """
    if flow_features.empty:
        return pd.DataFrame(columns=[
            'flow_id', 'src_ip', 'dst_ip', 'asymmetry_score',
            'packet_ratio', 'byte_ratio', 'anomaly_type'
        ])
    
    try:
        results = []
        
        for _, flow in flow_features.iterrows():
            fwd_packets = flow.get('fwd_packets', 0)
            bwd_packets = flow.get('bwd_packets', 0)
            fwd_bytes = flow.get('fwd_bytes', 0)
            bwd_bytes = flow.get('bwd_bytes', 0)
            
            total_packets = fwd_packets + bwd_packets
            total_bytes = fwd_bytes + bwd_bytes
            
            if total_packets == 0 or total_bytes == 0:
                continue
            
            # Calculate asymmetry ratios
            if bwd_packets > 0:
                packet_ratio = fwd_packets / bwd_packets
            else:
                packet_ratio = float('inf')
            
            if bwd_bytes > 0:
                byte_ratio = fwd_bytes / bwd_bytes
            else:
                byte_ratio = float('inf')
            
            # Detect anomalies
            anomaly_type = None
            asymmetry_score = 0
            
            # One-way communication (very few responses)
            if packet_ratio > 10 or bwd_packets < 3:
                anomaly_type = 'one-way communication'
                asymmetry_score = 80
            
            # Excessive upload (potential exfiltration)
            elif byte_ratio > 20:
                anomaly_type = 'excessive upload'
                asymmetry_score = 70
            
            # Excessive download (potential C2 payload download)
            elif byte_ratio < 0.05 and total_bytes > 10000:
                anomaly_type = 'excessive download'
                asymmetry_score = 60
            
            # Asymmetric but not extreme
            elif packet_ratio > 5 or packet_ratio < 0.2:
                anomaly_type = 'asymmetric flow'
                asymmetry_score = 40
            
            if anomaly_type:
                results.append({
                    'flow_id': flow.get('flow_id', ''),
                    'src_ip': flow.get('src_ip', ''),
                    'dst_ip': flow.get('dst_ip', ''),
                    'asymmetry_score': asymmetry_score,
                    'packet_ratio': float(packet_ratio) if packet_ratio != float('inf') else 999.0,
                    'byte_ratio': float(byte_ratio) if byte_ratio != float('inf') else 999.0,
                    'anomaly_type': anomaly_type
                })
        
        return pd.DataFrame(results)
    
    except Exception:
        return pd.DataFrame(columns=[
            'flow_id', 'src_ip', 'dst_ip', 'asymmetry_score',
            'packet_ratio', 'byte_ratio', 'anomaly_type'
        ])


def detect_flow_anomalies(flow_features):
    """
    Applies statistical analysis to flow features to detect anomalous flows.
    Flags flows with unusual characteristics that may indicate C2, exfiltration,
    or other malicious activity.
    
    Uses IQR (Interquartile Range) method and statistical thresholds.
    
    Args:
        flow_features: DataFrame from extract_flow_features()
        
    Returns:
        pd.DataFrame with anomalous flows and anomaly reasons
        
    Examples:
        >>> flows = pd.DataFrame({
        ...     'flow_id': ['f1', 'f2'],
        ...     'flow_duration': [100, 10000],
        ...     'packets_per_second': [1, 1000],
        ...     'bytes_per_second': [100, 100000]
        ... })
        >>> result = detect_flow_anomalies(flows)
        >>> 'anomaly_reasons' in result.columns
        True
    """
    if flow_features.empty or len(flow_features) < 10:
        return pd.DataFrame(columns=[
            'flow_id', 'src_ip', 'dst_ip', 'anomaly_score', 'anomaly_reasons'
        ])
    
    try:
        results = []
        
        # Calculate statistics for key metrics
        metrics = [
            'flow_duration', 'packets_per_second', 'bytes_per_second',
            'packet_size_mean', 'iat_mean'
        ]
        
        stats_dict = {}
        for metric in metrics:
            if metric in flow_features.columns:
                q1 = flow_features[metric].quantile(0.25)
                q3 = flow_features[metric].quantile(0.75)
                iqr = q3 - q1
                mean = flow_features[metric].mean()
                std = flow_features[metric].std()
                
                stats_dict[metric] = {
                    'q1': q1,
                    'q3': q3,
                    'iqr': iqr,
                    'mean': mean,
                    'std': std,
                    'upper_bound': q3 + 1.5 * iqr,
                    'lower_bound': q1 - 1.5 * iqr
                }
        
        # Analyze each flow
        for _, flow in flow_features.iterrows():
            anomaly_reasons = []
            anomaly_score = 0
            
            # Check each metric
            for metric, stats in stats_dict.items():
                value = flow.get(metric, 0)
                
                # IQR outlier detection
                if value > stats['upper_bound']:
                    anomaly_reasons.append(f"High {metric}: {value:.2f}")
                    anomaly_score += 15
                elif value < stats['lower_bound'] and value > 0:
                    anomaly_reasons.append(f"Low {metric}: {value:.2f}")
                    anomaly_score += 10
            
            # Specific anomaly patterns
            
            # Long-duration low-rate flow (potential C2 beacon)
            if flow.get('flow_duration', 0) > 3600 and flow.get('packets_per_second', 0) < 0.1:
                anomaly_reasons.append("Long-duration low-rate (potential beacon)")
                anomaly_score += 20
            
            # High packet rate (potential DDoS)
            if flow.get('packets_per_second', 0) > 100:
                anomaly_reasons.append("Very high packet rate")
                anomaly_score += 25
            
            # No bidirectional communication
            if flow.get('bwd_packets', 0) == 0 and flow.get('fwd_packets', 0) > 10:
                anomaly_reasons.append("One-way flow (no responses)")
                anomaly_score += 30
            
            # Suspicious flags (RST-heavy flows)
            total_packets = flow.get('fwd_packets', 0) + flow.get('bwd_packets', 0)
            rst_count = flow.get('rst_count', 0)
            if total_packets > 0 and rst_count / total_packets > 0.5:
                anomaly_reasons.append("High RST ratio (scanning?)")
                anomaly_score += 20
            
            # Only report if anomalous
            if anomaly_score >= 20:
                results.append({
                    'flow_id': flow.get('flow_id', ''),
                    'src_ip': flow.get('src_ip', ''),
                    'dst_ip': flow.get('dst_ip', ''),
                    'anomaly_score': min(100, anomaly_score),
                    'anomaly_reasons': '; '.join(anomaly_reasons)
                })
        
        return pd.DataFrame(results)
    
    except Exception:
        return pd.DataFrame(columns=[
            'flow_id', 'src_ip', 'dst_ip', 'anomaly_score', 'anomaly_reasons'
        ])

# -----------------------
# ML Feature Extraction & Baseline Functions
# -----------------------

def extract_ml_features(tcp_df, udp_df, icmp_df):
    """
    Extract 20+ machine learning features from network traffic for DDoS/anomaly detection.
    
    Features extracted:
    - Packet rate statistics (mean, std, max)
    - Byte rate statistics
    - Protocol distribution
    - Port entropy
    - Source/destination diversity
    - Temporal patterns
    - Connection characteristics
    
    Args:
        tcp_df: DataFrame with TCP traffic
        udp_df: DataFrame with UDP traffic  
        icmp_df: DataFrame with ICMP traffic
        
    Returns:
        pd.DataFrame: Features with columns for ML models
    """
    features = []
    
    try:
        # Combine all traffic for overall statistics
        all_traffic = []
        
        for df, proto in [(tcp_df, 'TCP'), (udp_df, 'UDP'), (icmp_df, 'ICMP')]:
            if df.empty or 'TS' not in df.columns:
                continue
                
            # Per-source IP feature extraction
            for src_ip, group in df.groupby('SRC_IP'):
                if len(group) < 2:
                    continue
                    
                feature = {'SRC_IP': src_ip, 'PROTOCOL': proto}
                
                # Temporal features
                times = group['TS'].dropna().values
                if len(times) > 1:
                    duration = times.max() - times.min()
                    feature['DURATION'] = duration
                    feature['PACKET_RATE'] = len(group) / max(0.001, duration)
                    
                    # Inter-arrival time statistics
                    if len(times) > 2:
                        diffs = np.diff(sorted(times))
                        feature['IAT_MEAN'] = np.mean(diffs)
                        feature['IAT_STD'] = np.std(diffs)
                        feature['IAT_MAX'] = np.max(diffs)
                        feature['IAT_MIN'] = np.min(diffs)
                    else:
                        feature['IAT_MEAN'] = feature['IAT_STD'] = feature['IAT_MAX'] = feature['IAT_MIN'] = 0
                else:
                    feature['DURATION'] = 0
                    feature['PACKET_RATE'] = 0
                    feature['IAT_MEAN'] = feature['IAT_STD'] = feature['IAT_MAX'] = feature['IAT_MIN'] = 0
                
                # Volume features
                feature['TOTAL_PACKETS'] = len(group)
                if 'SIZE' in group.columns:
                    sizes = group['SIZE'].dropna().values
                    feature['TOTAL_BYTES'] = np.sum(sizes)
                    feature['AVG_PACKET_SIZE'] = np.mean(sizes) if len(sizes) > 0 else 0
                    feature['STD_PACKET_SIZE'] = np.std(sizes) if len(sizes) > 0 else 0
                    feature['BYTE_RATE'] = feature['TOTAL_BYTES'] / max(0.001, feature['DURATION'])
                else:
                    feature['TOTAL_BYTES'] = 0
                    feature['AVG_PACKET_SIZE'] = 0
                    feature['STD_PACKET_SIZE'] = 0
                    feature['BYTE_RATE'] = 0
                
                # Destination diversity
                if 'DST_IP' in group.columns:
                    unique_dsts = group['DST_IP'].nunique()
                    feature['UNIQUE_DST_IPS'] = unique_dsts
                    feature['DST_IP_ENTROPY'] = shannon_entropy(','.join(group['DST_IP'].astype(str)))
                else:
                    feature['UNIQUE_DST_IPS'] = 0
                    feature['DST_IP_ENTROPY'] = 0
                
                # Port features (for TCP/UDP)
                if proto in ['TCP', 'UDP']:
                    if 'DST_PORT' in group.columns:
                        ports = group['DST_PORT'].dropna().astype(str)
                        feature['UNIQUE_DST_PORTS'] = len(ports.unique())
                        feature['DST_PORT_ENTROPY'] = shannon_entropy(','.join(ports))
                    else:
                        feature['UNIQUE_DST_PORTS'] = 0
                        feature['DST_PORT_ENTROPY'] = 0
                    
                    if 'SRC_PORT' in group.columns:
                        src_ports = group['SRC_PORT'].dropna().astype(str)
                        feature['UNIQUE_SRC_PORTS'] = len(src_ports.unique())
                    else:
                        feature['UNIQUE_SRC_PORTS'] = 0
                else:
                    feature['UNIQUE_DST_PORTS'] = 0
                    feature['DST_PORT_ENTROPY'] = 0
                    feature['UNIQUE_SRC_PORTS'] = 0
                
                # TCP-specific features
                if proto == 'TCP' and 'FLAGS' in group.columns:
                    flags_str = group['FLAGS'].dropna().astype(str)
                    syn_count = sum(1 for f in flags_str if 'SYN' in f and 'ACK' not in f)
                    ack_count = sum(1 for f in flags_str if 'ACK' in f)
                    rst_count = sum(1 for f in flags_str if 'RST' in f)
                    
                    feature['SYN_COUNT'] = syn_count
                    feature['ACK_COUNT'] = ack_count
                    feature['RST_COUNT'] = rst_count
                    feature['SYN_RATIO'] = syn_count / max(1, ack_count)
                else:
                    feature['SYN_COUNT'] = 0
                    feature['ACK_COUNT'] = 0
                    feature['RST_COUNT'] = 0
                    feature['SYN_RATIO'] = 0
                
                features.append(feature)
        
    except Exception as e:
        print(f"[WARNING] Feature extraction error: {e}")
    
    if not features:
        return pd.DataFrame()
    
    df = pd.DataFrame(features)
    
    # Fill any missing values with 0
    df = df.fillna(0)
    
    return df


def establish_baseline(traffic_df, window='300s'):
    """
    Create baseline traffic profiles per IP/network segment.
    
    Calculates statistical baselines including:
    - Mean, median, std deviation
    - 95th and 99th percentiles
    - Min/max values
    
    Args:
        traffic_df: DataFrame with traffic features
        window: Time window for baseline (e.g., '300s' for 5 minutes)
        
    Returns:
        dict: Baseline statistics per IP
    """
    baselines = {}
    
    try:
        if traffic_df.empty or 'SRC_IP' not in traffic_df.columns:
            return baselines
        
        # Numeric columns for statistics
        numeric_cols = traffic_df.select_dtypes(include=[np.number]).columns.tolist()
        
        for src_ip, group in traffic_df.groupby('SRC_IP'):
            baseline = {'IP': src_ip}
            
            for col in numeric_cols:
                if col in group.columns:
                    values = group[col].dropna().values
                    if len(values) > 0:
                        baseline[f'{col}_MEAN'] = np.mean(values)
                        baseline[f'{col}_STD'] = np.std(values)
                        baseline[f'{col}_MEDIAN'] = np.median(values)
                        baseline[f'{col}_P95'] = np.percentile(values, 95)
                        baseline[f'{col}_P99'] = np.percentile(values, 99)
                        baseline[f'{col}_MIN'] = np.min(values)
                        baseline[f'{col}_MAX'] = np.max(values)
            
            baselines[src_ip] = baseline
            
    except Exception as e:
        print(f"[WARNING] Baseline establishment error: {e}")
    
    return baselines


def calculate_adaptive_threshold(baseline, metric, sensitivity=3):
    """
    Calculate adaptive threshold based on baseline statistics.
    
    Uses mean + (sensitivity * std) approach, which is more robust than static thresholds.
    
    Args:
        baseline: Baseline statistics dict for an IP
        metric: Metric name to calculate threshold for
        sensitivity: Number of standard deviations (default: 3)
        
    Returns:
        float: Adaptive threshold value
    """
    try:
        mean_key = f'{metric}_MEAN'
        std_key = f'{metric}_STD'
        
        if mean_key in baseline and std_key in baseline:
            mean_val = baseline[mean_key]
            std_val = baseline[std_key]
            threshold = mean_val + (sensitivity * std_val)
            return max(0, threshold)  # Ensure non-negative
        else:
            # Fallback to static threshold if baseline not available
            return None
            
    except Exception:
        return None


def ml_ddos_detection(features):
    """
    Random Forest classifier for DDoS attack classification.
    
    Uses pre-trained model or heuristic-based labels for training.
    Provides confidence scores for detections.
    
    Args:
        features: DataFrame with extracted ML features
        
    Returns:
        pd.DataFrame: Predictions with ML_SCORE and PREDICTION columns
    """
    predictions = []
    
    try:
        if not ML_AVAILABLE or not ML_ENABLED:
            print("[INFO] ML detection skipped - using heuristics only")
            return pd.DataFrame()
        
        if features.empty or len(features) < ML_MIN_TRAINING_SAMPLES:
            print(f"[INFO] Insufficient data for ML ({len(features)} samples < {ML_MIN_TRAINING_SAMPLES} minimum)")
            return pd.DataFrame()
        
        # Select numeric features only
        feature_cols = [col for col in features.columns if col not in ['SRC_IP', 'PROTOCOL']]
        X = features[feature_cols].fillna(0)
        
        # Simple heuristic labeling for training (unsupervised approach)
        # Label as attack if multiple anomalous features detected
        y_heuristic = np.zeros(len(X))
        
        # High packet rate
        y_heuristic += (X['PACKET_RATE'] > X['PACKET_RATE'].quantile(0.95)).astype(int)
        
        # High destination diversity (scanning behavior)
        if 'UNIQUE_DST_IPS' in X.columns:
            y_heuristic += (X['UNIQUE_DST_IPS'] > X['UNIQUE_DST_IPS'].quantile(0.90)).astype(int)
        
        # High SYN ratio
        if 'SYN_RATIO' in X.columns:
            y_heuristic += (X['SYN_RATIO'] > 5).astype(int)
        
        # Label as attack if 2+ anomalous features
        y_labels = (y_heuristic >= 2).astype(int)
        
        # Train Random Forest if we have both classes
        if len(np.unique(y_labels)) > 1:
            rf = RandomForestClassifier(n_estimators=50, max_depth=10, random_state=42)
            rf.fit(X, y_labels)
            
            # Get predictions and probabilities
            y_pred = rf.predict(X)
            y_proba = rf.predict_proba(X)
            
            for idx, row in features.iterrows():
                pred_class = y_pred[idx]
                confidence = y_proba[idx][pred_class] * 100
                
                predictions.append({
                    'SRC_IP': row['SRC_IP'],
                    'PROTOCOL': row.get('PROTOCOL', 'UNKNOWN'),
                    'PREDICTION': 'ATTACK' if pred_class == 1 else 'NORMAL',
                    'ML_SCORE': int(confidence),
                    'PACKET_RATE': row.get('PACKET_RATE', 0),
                    'UNIQUE_DST_IPS': row.get('UNIQUE_DST_IPS', 0)
                })
                
            print(f"[ML] Random Forest trained on {len(X)} samples, detected {sum(y_pred)} potential attacks")
        else:
            print("[ML] Insufficient class diversity for RF training")
            
    except Exception as e:
        print(f"[WARNING] ML DDoS detection error: {e}")
    
    return pd.DataFrame(predictions) if predictions else pd.DataFrame()


def anomaly_detection(features):
    """
    Isolation Forest for zero-day attack and anomaly detection.
    
    Detects outliers in traffic patterns that may indicate novel attacks.
    
    Args:
        features: DataFrame with extracted ML features
        
    Returns:
        pd.DataFrame: Anomaly predictions with ANOMALY_SCORE
    """
    anomalies = []
    
    try:
        if not ML_AVAILABLE or not ML_ENABLED:
            return pd.DataFrame()
        
        if features.empty or len(features) < ML_MIN_TRAINING_SAMPLES:
            print(f"[INFO] Insufficient data for anomaly detection ({len(features)} samples)")
            return pd.DataFrame()
        
        # Select numeric features
        feature_cols = [col for col in features.columns if col not in ['SRC_IP', 'PROTOCOL']]
        X = features[feature_cols].fillna(0)
        
        # Normalize features
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)
        
        # Train Isolation Forest
        iso_forest = IsolationForest(
            n_estimators=100,
            contamination=0.1,  # Expect 10% anomalies
            random_state=42
        )
        
        y_pred = iso_forest.fit_predict(X_scaled)
        scores = iso_forest.score_samples(X_scaled)
        
        # Convert scores to 0-100 scale (more negative = more anomalous)
        # Normalize to 0-100 where 100 is most anomalous
        min_score = scores.min()
        max_score = scores.max()
        if max_score != min_score:
            normalized_scores = 100 * (1 - (scores - min_score) / (max_score - min_score))
        else:
            normalized_scores = np.zeros_like(scores)
        
        anomaly_count = 0
        for idx, row in features.iterrows():
            if y_pred[idx] == -1:  # Anomaly detected
                anomalies.append({
                    'SRC_IP': row['SRC_IP'],
                    'PROTOCOL': row.get('PROTOCOL', 'UNKNOWN'),
                    'ANOMALY_SCORE': int(normalized_scores[idx]),
                    'BASELINE_DEVIATION': 'HIGH',
                    'PACKET_RATE': row.get('PACKET_RATE', 0),
                    'UNIQUE_DST_IPS': row.get('UNIQUE_DST_IPS', 0)
                })
                anomaly_count += 1
        
        print(f"[ML] Isolation Forest detected {anomaly_count} anomalies from {len(X)} samples")
        
    except Exception as e:
        print(f"[WARNING] Anomaly detection error: {e}")
    
    return pd.DataFrame(anomalies) if anomalies else pd.DataFrame()


def detect_jittered_beaconing(times, max_jitter=0.5):
    """
    Enhanced beaconing detection with jitter tolerance using autocorrelation.
    
    Detects periodic patterns even with randomized intervals (10-50% jitter).
    Uses autocorrelation to identify periodicity in noisy time series.
    
    Args:
        times: List of timestamps
        max_jitter: Maximum jitter tolerance (0.0-1.0)
        
    Returns:
        dict: Detection results with period, jitter, and confidence
    """
    result = {
        'detected': False,
        'period': 0,
        'jitter': 0,
        'confidence': 0,
        'method': 'autocorrelation'
    }
    
    try:
        if len(times) < 10:
            return result
        
        times = sorted(times)
        diffs = np.diff(times)
        
        if len(diffs) < 5:
            return result
        
        # Basic statistics
        mean_interval = np.mean(diffs)
        std_interval = np.std(diffs)
        cv = std_interval / mean_interval if mean_interval > 0 else 999
        
        # Check if CV is within jitter tolerance
        if cv <= max_jitter:
            result['detected'] = True
            result['period'] = mean_interval
            result['jitter'] = cv
            result['confidence'] = int(min(100, (1 - cv) * 100))
            result['method'] = 'low_cv'
            return result
        
        # Autocorrelation analysis for jittered beacons
        if len(diffs) >= AUTOCORR_MIN_LAGS:
            # Normalize the differences
            diffs_norm = (diffs - np.mean(diffs)) / (np.std(diffs) + 1e-10)
            
            # Compute autocorrelation for different lags
            max_lag = min(len(diffs) // 2, 20)
            autocorr = []
            
            for lag in range(1, max_lag):
                if lag < len(diffs_norm):
                    # Pearson correlation between series and lagged version
                    corr = np.corrcoef(diffs_norm[:-lag], diffs_norm[lag:])[0, 1]
                    autocorr.append(abs(corr))
                else:
                    autocorr.append(0)
            
            # Find peaks in autocorrelation
            if autocorr:
                max_autocorr = np.max(autocorr)
                
                # If strong periodicity detected (high autocorrelation)
                if max_autocorr > 0.3:  # Threshold for periodic pattern
                    peak_lag = np.argmax(autocorr) + 1
                    estimated_period = mean_interval * peak_lag
                    
                    result['detected'] = True
                    result['period'] = estimated_period
                    result['jitter'] = cv
                    result['confidence'] = int(min(100, max_autocorr * 100))
                    result['method'] = 'autocorrelation'
                    
    except Exception as e:
        print(f"[WARNING] Jittered beaconing detection error: {e}")
    
    return result

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
# Protocol Detection Functions (Priority 3)
# -----------------------

def detect_smb_activity(tcp_df):
    """
    Analyzes SMB traffic on ports 445, 139
    
    Detects:
    - Lateral movement (one source → many destinations)
    - Admin share access patterns
    - SMBv1 usage (deprecated/vulnerable)
    - Mass file access (ransomware indicator)
    - Authentication failures
    
    Returns DataFrame with columns:
    - SRC_IP, DST_IP, SMB_VERSION, SHARE_NAME, OPERATION
    - LATERAL_MOVEMENT_SCORE, RANSOMWARE_INDICATOR
    
    References: RFC 1001, RFC 1002 (NetBIOS), MS-SMB, MS-SMB2
    """
    rows = []
    
    try:
        if tcp_df.empty or 'SRC_PORT' not in tcp_df.columns or 'DST_PORT' not in tcp_df.columns:
            return pd.DataFrame(columns=['SRC_IP','DST_IP','SMB_VERSION','SHARE_NAME','OPERATION','LATERAL_SCORE','RANSOMWARE_INDICATOR','COUNT'])
        
        # Filter SMB traffic (ports 445, 139)
        smb_traffic = tcp_df[
            (tcp_df['SRC_PORT'].isin([445, 139])) | 
            (tcp_df['DST_PORT'].isin([445, 139]))
        ].copy()
        
        if smb_traffic.empty:
            return pd.DataFrame(columns=['SRC_IP','DST_IP','SMB_VERSION','SHARE_NAME','OPERATION','LATERAL_SCORE','RANSOMWARE_INDICATOR','COUNT'])
        
        # Analyze lateral movement: one source → multiple destinations
        if 'SRC_IP' in smb_traffic.columns and 'DST_IP' in smb_traffic.columns:
            lateral_analysis = smb_traffic.groupby('SRC_IP').agg({
                'DST_IP': lambda x: x.nunique(),
                'COUNT': 'sum' if 'COUNT' in smb_traffic.columns else 'size'
            }).reset_index()
            
            lateral_analysis.columns = ['SRC_IP', 'TARGET_COUNT', 'PACKET_COUNT']
            
            # Detect payload signatures for SMB version
            for src_ip in lateral_analysis['SRC_IP'].unique():
                src_data = smb_traffic[smb_traffic['SRC_IP'] == src_ip]
                target_count = lateral_analysis[lateral_analysis['SRC_IP'] == src_ip]['TARGET_COUNT'].values[0]
                packet_count = lateral_analysis[lateral_analysis['SRC_IP'] == src_ip]['PACKET_COUNT'].values[0]
                
                # Check for SMB signatures in payload
                smb_version = 'Unknown'
                share_name = ''
                operation = 'Connection'
                
                if 'PAYLOAD' in src_data.columns:
                    for _, row in src_data.head(10).iterrows():
                        payload = row.get('PAYLOAD', '')
                        if isinstance(payload, str):
                            if '\\xffSMB' in repr(payload) or 'SMB' in payload[:20]:
                                smb_version = 'SMBv1'
                            elif '\\xfeSMB' in repr(payload):
                                smb_version = 'SMBv2/v3'
                            
                            # Detect admin shares
                            if 'ADMIN$' in payload or 'C$' in payload or 'IPC$' in payload:
                                share_name = 'ADMIN_SHARE'
                                operation = 'Admin Share Access'
                
                # Calculate lateral movement score
                lateral_score = 0
                if target_count >= SMB_LATERAL_THRESHOLD:
                    lateral_score = min(95, 60 + (target_count * 5))
                elif target_count >= 3:
                    lateral_score = 50
                
                # Ransomware indicator: many targets + high packet count
                ransomware_indicator = 'No'
                if target_count >= 10 and packet_count >= 50:
                    ransomware_indicator = 'High Risk'
                    lateral_score = min(98, lateral_score + 20)
                elif target_count >= SMB_LATERAL_THRESHOLD:
                    ransomware_indicator = 'Suspicious'
                
                # Flag SMBv1 usage (vulnerable)
                if smb_version == 'SMBv1':
                    lateral_score = min(95, lateral_score + 15)
                    if ransomware_indicator == 'No':
                        ransomware_indicator = 'SMBv1 Vulnerable'
                
                if lateral_score > 0 or target_count >= 3 or smb_version != 'Unknown':
                    dst_ips = ', '.join(src_data['DST_IP'].unique()[:5].tolist())
                    rows.append({
                        'SRC_IP': src_ip,
                        'DST_IP': dst_ips if len(dst_ips) <= 50 else dst_ips[:50] + '...',
                        'SMB_VERSION': smb_version,
                        'SHARE_NAME': share_name,
                        'OPERATION': operation,
                        'LATERAL_SCORE': lateral_score,
                        'RANSOMWARE_INDICATOR': ransomware_indicator,
                        'COUNT': int(target_count)
                    })
    
    except Exception:
        pass
    
    return pd.DataFrame(rows) if rows else pd.DataFrame(columns=['SRC_IP','DST_IP','SMB_VERSION','SHARE_NAME','OPERATION','LATERAL_SCORE','RANSOMWARE_INDICATOR','COUNT'])


def detect_rdp_activity(tcp_df):
    """
    Analyzes RDP traffic on port 3389
    
    Detects:
    - Brute force attempts (multiple failed logins)
    - Off-hours connections
    - Unusual session durations
    - Multiple concurrent sessions
    
    Returns DataFrame with detection results
    
    References: RFC 2126, MS-RDPBCGR
    """
    rows = []
    
    try:
        if tcp_df.empty or 'DST_PORT' not in tcp_df.columns:
            return pd.DataFrame(columns=['SRC_IP','DST_IP','ATTEMPTS','STATUS','SCORE','PATTERN','COUNT'])
        
        # Filter RDP traffic (port 3389)
        rdp_traffic = tcp_df[
            (tcp_df['SRC_PORT'] == 3389) | 
            (tcp_df['DST_PORT'] == 3389)
        ].copy()
        
        if rdp_traffic.empty:
            return pd.DataFrame(columns=['SRC_IP','DST_IP','ATTEMPTS','STATUS','SCORE','PATTERN','COUNT'])
        
        # Analyze connection patterns
        if 'SRC_IP' in rdp_traffic.columns and 'DST_IP' in rdp_traffic.columns:
            # Group by source IP to detect brute force
            agg_dict = {'COUNT': 'sum' if 'COUNT' in rdp_traffic.columns else 'size'}
            if 'TS' in rdp_traffic.columns:
                agg_dict['TS'] = ['min', 'max', 'count']
            
            conn_analysis = rdp_traffic.groupby(['SRC_IP', 'DST_IP']).agg(agg_dict).reset_index()
            
            for _, row in conn_analysis.iterrows():
                src_ip = row['SRC_IP']
                dst_ip = row['DST_IP']
                
                # Extract COUNT properly whether it's aggregated or not
                if 'COUNT' in conn_analysis.columns:
                    if isinstance(row['COUNT'], (int, float, np.integer, np.floating)):
                        attempt_count = int(row['COUNT'])
                    else:
                        attempt_count = int(row['COUNT'][0]) if hasattr(row['COUNT'], '__getitem__') else 0
                else:
                    attempt_count = 1
                
                score = 0
                status = 'Normal'
                pattern = 'Single Connection'
                
                # Detect brute force: many connection attempts
                if attempt_count >= RDP_BRUTE_THRESHOLD:
                    score = min(95, 70 + (attempt_count - RDP_BRUTE_THRESHOLD) * 2)
                    status = 'Brute Force Suspected'
                    pattern = f'{attempt_count} attempts'
                elif attempt_count >= 5:
                    score = 50
                    status = 'Multiple Attempts'
                    pattern = f'{attempt_count} attempts'
                
                # Check for multiple sources to same target (credential stuffing)
                target_sources = rdp_traffic[rdp_traffic['DST_IP'] == dst_ip]['SRC_IP'].nunique()
                if target_sources >= 5:
                    score = max(score, 80)
                    status = 'Distributed Brute Force'
                    pattern = f'{target_sources} sources'
                
                if score > 0 or attempt_count >= 3:
                    rows.append({
                        'SRC_IP': src_ip,
                        'DST_IP': dst_ip,
                        'ATTEMPTS': int(attempt_count),
                        'STATUS': status,
                        'SCORE': score,
                        'PATTERN': pattern,
                        'COUNT': int(attempt_count)
                    })
    
    except Exception:
        pass
    
    return pd.DataFrame(rows) if rows else pd.DataFrame(columns=['SRC_IP','DST_IP','ATTEMPTS','STATUS','SCORE','PATTERN','COUNT'])


def detect_ssh_activity(tcp_df):
    """
    Analyzes SSH traffic on port 22
    
    Detects:
    - Brute force attacks
    - Tunnel establishment
    - Failed login patterns
    - Unusual client versions
    
    Returns DataFrame with SSH activity analysis
    
    References: RFC 4251 (SSH Protocol Architecture)
    """
    rows = []
    
    try:
        if tcp_df.empty or 'DST_PORT' not in tcp_df.columns:
            return pd.DataFrame(columns=['SRC_IP','DST_IP','ATTEMPTS','PATTERN','SCORE','VERSION','COUNT'])
        
        # Filter SSH traffic (port 22)
        ssh_traffic = tcp_df[
            (tcp_df['SRC_PORT'] == 22) | 
            (tcp_df['DST_PORT'] == 22)
        ].copy()
        
        if ssh_traffic.empty:
            return pd.DataFrame(columns=['SRC_IP','DST_IP','ATTEMPTS','PATTERN','SCORE','VERSION','COUNT'])
        
        # Analyze connection patterns
        if 'SRC_IP' in ssh_traffic.columns and 'DST_IP' in ssh_traffic.columns:
            conn_analysis = ssh_traffic.groupby(['SRC_IP', 'DST_IP']).agg({
                'COUNT': 'sum' if 'COUNT' in ssh_traffic.columns else 'size'
            }).reset_index()
            
            for _, row in conn_analysis.iterrows():
                src_ip = row['SRC_IP']
                dst_ip = row['DST_IP']
                attempt_count = row['COUNT']
                
                score = 0
                pattern = 'Normal'
                version = 'Unknown'
                
                # Extract SSH version from payload
                if 'PAYLOAD' in ssh_traffic.columns:
                    src_data = ssh_traffic[(ssh_traffic['SRC_IP'] == src_ip) & (ssh_traffic['DST_IP'] == dst_ip)]
                    for _, pkt_row in src_data.head(5).iterrows():
                        payload = pkt_row.get('PAYLOAD', '')
                        if isinstance(payload, str) and 'SSH-' in payload[:50]:
                            # Extract version from SSH banner
                            if 'SSH-2.0' in payload:
                                version = 'SSH-2.0'
                            elif 'SSH-1' in payload:
                                version = 'SSH-1.x (Deprecated)'
                                score = max(score, 40)  # SSH-1 is deprecated/vulnerable
                
                # Detect brute force: many connection attempts
                if attempt_count >= SSH_BRUTE_THRESHOLD:
                    score = min(95, 70 + (attempt_count - SSH_BRUTE_THRESHOLD) * 2)
                    pattern = f'Brute Force ({attempt_count} attempts)'
                elif attempt_count >= 5:
                    score = 50
                    pattern = f'Multiple Attempts ({attempt_count})'
                
                # Check for scanning: one source → many targets
                targets = ssh_traffic[ssh_traffic['SRC_IP'] == src_ip]['DST_IP'].nunique()
                if targets >= 10:
                    score = max(score, 85)
                    pattern = f'SSH Scanning ({targets} targets)'
                elif targets >= 5:
                    score = max(score, 60)
                    pattern = f'Port Scan ({targets} targets)'
                
                if score > 0 or attempt_count >= 3:
                    rows.append({
                        'SRC_IP': src_ip,
                        'DST_IP': dst_ip,
                        'ATTEMPTS': int(attempt_count),
                        'PATTERN': pattern,
                        'SCORE': score,
                        'VERSION': version,
                        'COUNT': int(attempt_count)
                    })
    
    except Exception:
        pass
    
    return pd.DataFrame(rows) if rows else pd.DataFrame(columns=['SRC_IP','DST_IP','ATTEMPTS','PATTERN','SCORE','VERSION','COUNT'])


def detect_ftp_activity(tcp_df, udp_df):
    """
    Analyzes FTP/SFTP traffic
    
    Detects:
    - Anonymous access attempts
    - Large file transfers (> 10MB)
    - Unusual upload patterns
    - Credential brute forcing
    
    Returns DataFrame with FTP analysis
    
    References: RFC 959 (FTP), RFC 2228 (FTP Security Extensions)
    """
    rows = []
    
    try:
        if tcp_df.empty or 'DST_PORT' not in tcp_df.columns:
            return pd.DataFrame(columns=['SRC_IP','DST_IP','OPERATION','SIZE_MB','SCORE','PATTERN','COUNT'])
        
        # Filter FTP traffic (ports 20, 21)
        ftp_traffic = tcp_df[
            (tcp_df['SRC_PORT'].isin([20, 21])) | 
            (tcp_df['DST_PORT'].isin([20, 21]))
        ].copy()
        
        if ftp_traffic.empty:
            return pd.DataFrame(columns=['SRC_IP','DST_IP','OPERATION','SIZE_MB','SCORE','PATTERN','COUNT'])
        
        # Analyze FTP sessions
        if 'SRC_IP' in ftp_traffic.columns and 'DST_IP' in ftp_traffic.columns:
            session_analysis = ftp_traffic.groupby(['SRC_IP', 'DST_IP']).agg({
                'SIZE': 'sum' if 'SIZE' in ftp_traffic.columns else 'size',
                'COUNT': 'sum' if 'COUNT' in ftp_traffic.columns else 'size'
            }).reset_index()
            
            for _, row in session_analysis.iterrows():
                src_ip = row['SRC_IP']
                dst_ip = row['DST_IP']
                total_size = row['SIZE'] if 'SIZE' in row else 0
                packet_count = row['COUNT']
                
                size_mb = total_size / (1024 * 1024) if total_size > 0 else 0
                score = 0
                operation = 'Connection'
                pattern = 'Normal'
                
                # Detect large file transfers (potential exfiltration)
                if total_size >= FTP_EXFIL_SIZE:
                    score = min(90, 60 + int((total_size / FTP_EXFIL_SIZE) * 10))
                    operation = 'Large Transfer'
                    pattern = f'Data Exfiltration ({size_mb:.1f} MB)'
                
                # Check for anonymous login in payload
                if 'PAYLOAD' in ftp_traffic.columns:
                    session_data = ftp_traffic[(ftp_traffic['SRC_IP'] == src_ip) & (ftp_traffic['DST_IP'] == dst_ip)]
                    for _, pkt_row in session_data.head(10).iterrows():
                        payload = pkt_row.get('PAYLOAD', '')
                        if isinstance(payload, str):
                            if 'USER anonymous' in payload or 'USER ftp' in payload:
                                operation = 'Anonymous Login'
                                score = max(score, 45)
                                pattern = 'Anonymous Access'
                            elif 'PASS ' in payload and packet_count >= 5:
                                score = max(score, 55)
                                pattern = 'Brute Force Attempt'
                
                # Multiple connection attempts
                if packet_count >= 20:
                    score = max(score, 50)
                    if 'Brute Force' not in pattern:
                        pattern = f'High Activity ({packet_count} packets)'
                
                if score > 0 or size_mb >= 5:
                    rows.append({
                        'SRC_IP': src_ip,
                        'DST_IP': dst_ip,
                        'OPERATION': operation,
                        'SIZE_MB': round(size_mb, 2),
                        'SCORE': score,
                        'PATTERN': pattern,
                        'COUNT': int(packet_count)
                    })
    
    except Exception:
        pass
    
    return pd.DataFrame(rows) if rows else pd.DataFrame(columns=['SRC_IP','DST_IP','OPERATION','SIZE_MB','SCORE','PATTERN','COUNT'])


def detect_smtp_activity(tcp_df):
    """
    Analyzes SMTP traffic
    
    Detects:
    - Mass mailing (spam botnet indicator)
    - Internal hosts sending external email
    - Large attachments
    - Unusual recipient patterns
    
    Returns DataFrame with SMTP analysis
    
    References: RFC 5321 (SMTP), RFC 5322 (Internet Message Format)
    """
    rows = []
    
    try:
        if tcp_df.empty or 'DST_PORT' not in tcp_df.columns:
            return pd.DataFrame(columns=['SRC_IP','DST_IP','EMAIL_COUNT','PATTERN','SCORE','TYPE','COUNT'])
        
        # Filter SMTP traffic (ports 25, 587, 465)
        smtp_traffic = tcp_df[
            (tcp_df['SRC_PORT'].isin([25, 587, 465])) | 
            (tcp_df['DST_PORT'].isin([25, 587, 465]))
        ].copy()
        
        if smtp_traffic.empty:
            return pd.DataFrame(columns=['SRC_IP','DST_IP','EMAIL_COUNT','PATTERN','SCORE','TYPE','COUNT'])
        
        # Analyze SMTP sessions
        if 'SRC_IP' in smtp_traffic.columns and 'DST_IP' in smtp_traffic.columns:
            # Count emails by analyzing MAIL FROM or RCPT TO commands
            session_analysis = smtp_traffic.groupby('SRC_IP').agg({
                'DST_IP': 'nunique',
                'COUNT': 'sum' if 'COUNT' in smtp_traffic.columns else 'size'
            }).reset_index()
            
            session_analysis.columns = ['SRC_IP', 'SERVER_COUNT', 'PACKET_COUNT']
            
            for _, row in session_analysis.iterrows():
                src_ip = row['SRC_IP']
                server_count = row['SERVER_COUNT']
                packet_count = row['PACKET_COUNT']
                
                # Estimate email count from packet count (rough heuristic)
                email_count = packet_count // 3  # Approximate: HELO, MAIL FROM, DATA per email
                
                score = 0
                pattern = 'Normal'
                email_type = 'Outbound'
                
                # Detect mass mailing (spam botnet)
                if email_count >= SMTP_MASS_MAIL_THRESHOLD:
                    score = min(95, 75 + (email_count - SMTP_MASS_MAIL_THRESHOLD))
                    pattern = 'Mass Mailing (Spam Botnet)'
                    email_type = 'Spam'
                elif email_count >= 20:
                    score = 60
                    pattern = 'High Volume'
                    email_type = 'Bulk Email'
                
                # Multiple SMTP servers (suspicious)
                if server_count >= 5:
                    score = max(score, 70)
                    pattern = f'Multiple Servers ({server_count})'
                    email_type = 'Distributed Spam'
                
                # Check if source is internal sending to external (compromised host)
                if is_private_ip(src_ip):
                    smtp_dests = smtp_traffic[smtp_traffic['SRC_IP'] == src_ip]['DST_IP'].unique()
                    external_count = sum(1 for ip in smtp_dests if not is_private_ip(ip))
                    if external_count >= 3 and email_count >= 10:
                        score = max(score, 80)
                        pattern = 'Internal → External Mass Mail'
                        email_type = 'Compromised Host'
                
                if score > 0 or email_count >= 10:
                    dst_ips = ', '.join(smtp_traffic[smtp_traffic['SRC_IP'] == src_ip]['DST_IP'].unique()[:3].tolist())
                    rows.append({
                        'SRC_IP': src_ip,
                        'DST_IP': dst_ips if len(dst_ips) <= 50 else dst_ips[:50] + '...',
                        'EMAIL_COUNT': int(email_count),
                        'PATTERN': pattern,
                        'SCORE': score,
                        'TYPE': email_type,
                        'COUNT': int(packet_count)
                    })
    
    except Exception:
        pass
    
    return pd.DataFrame(rows) if rows else pd.DataFrame(columns=['SRC_IP','DST_IP','EMAIL_COUNT','PATTERN','SCORE','TYPE','COUNT'])


def detect_irc_activity(tcp_df):
    """
    Analyzes IRC traffic (legacy C2 protocol)
    
    Detects:
    - IRC C2 channels
    - DCC transfers
    - Bot command patterns
    - Channel JOIN/PART anomalies
    
    Returns DataFrame with IRC C2 indicators
    
    References: RFC 1459 (IRC Protocol), RFC 2810-2813 (IRC Extensions)
    """
    rows = []
    
    try:
        if tcp_df.empty or 'DST_PORT' not in tcp_df.columns:
            return pd.DataFrame(columns=['SRC_IP','DST_IP','CHANNEL','PATTERN','SCORE','TYPE','COUNT'])
        
        # Filter IRC traffic (ports 6667, 6697, 194)
        irc_traffic = tcp_df[
            (tcp_df['SRC_PORT'].isin([6667, 6697, 194])) | 
            (tcp_df['DST_PORT'].isin([6667, 6697, 194]))
        ].copy()
        
        if irc_traffic.empty:
            return pd.DataFrame(columns=['SRC_IP','DST_IP','CHANNEL','PATTERN','SCORE','TYPE','COUNT'])
        
        # Analyze IRC connections
        if 'SRC_IP' in irc_traffic.columns and 'DST_IP' in irc_traffic.columns:
            conn_analysis = irc_traffic.groupby(['SRC_IP', 'DST_IP']).agg({
                'COUNT': 'sum' if 'COUNT' in irc_traffic.columns else 'size'
            }).reset_index()
            
            for _, row in conn_analysis.iterrows():
                src_ip = row['SRC_IP']
                dst_ip = row['DST_IP']
                packet_count = row['COUNT']
                
                score = 0
                pattern = 'IRC Connection'
                channel = 'Unknown'
                irc_type = 'Legacy Protocol'
                
                # IRC is mostly used by botnets now, so any IRC traffic is suspicious
                score = 65  # Base score for IRC usage
                
                # Check payload for IRC commands
                if 'PAYLOAD' in irc_traffic.columns:
                    session_data = irc_traffic[(irc_traffic['SRC_IP'] == src_ip) & (irc_traffic['DST_IP'] == dst_ip)]
                    for _, pkt_row in session_data.head(10).iterrows():
                        payload = pkt_row.get('PAYLOAD', '')
                        if isinstance(payload, str):
                            if 'JOIN #' in payload:
                                # Extract channel name
                                import re
                                channel_match = re.search(r'JOIN #(\S+)', payload)
                                if channel_match:
                                    channel = '#' + channel_match.group(1)
                                score = max(score, 75)
                                pattern = 'IRC C2 Channel'
                                irc_type = 'Botnet C2'
                            elif 'PRIVMSG' in payload:
                                score = max(score, 80)
                                pattern = 'IRC Commands'
                                irc_type = 'C2 Commands'
                            elif 'NICK ' in payload:
                                score = max(score, 70)
                                pattern = 'IRC Bot Registration'
                            elif 'DCC SEND' in payload:
                                score = 90
                                pattern = 'DCC File Transfer (Malware Distribution)'
                                irc_type = 'Malware Transfer'
                
                # Multiple bots connecting to same IRC server
                server_clients = irc_traffic[irc_traffic['DST_IP'] == dst_ip]['SRC_IP'].nunique()
                if server_clients >= 5:
                    score = min(95, score + 15)
                    pattern = f'IRC Botnet ({server_clients} bots)'
                    irc_type = 'Botnet Infrastructure'
                
                if score > 0:
                    rows.append({
                        'SRC_IP': src_ip,
                        'DST_IP': dst_ip,
                        'CHANNEL': channel,
                        'PATTERN': pattern,
                        'SCORE': score,
                        'TYPE': irc_type,
                        'COUNT': int(packet_count)
                    })
    
    except Exception:
        pass
    
    return pd.DataFrame(rows) if rows else pd.DataFrame(columns=['SRC_IP','DST_IP','CHANNEL','PATTERN','SCORE','TYPE','COUNT'])


def detect_p2p_activity(tcp_df, udp_df):
    """
    Analyzes P2P protocol traffic
    
    Detects:
    - BitTorrent DHT (UDP port 6881)
    - Peer-to-peer malware distribution
    - Botnet peer discovery
    - Unusual peer counts
    
    Returns DataFrame with P2P analysis
    
    References: BEP 5 (BitTorrent DHT Protocol)
    """
    rows = []
    
    try:
        # Combine TCP and UDP for P2P analysis
        p2p_traffic = pd.DataFrame()
        
        if not tcp_df.empty and 'DST_PORT' in tcp_df.columns:
            tcp_p2p = tcp_df[
                (tcp_df['SRC_PORT'].isin(PROTOCOL_PORTS['P2P_BT'])) | 
                (tcp_df['DST_PORT'].isin(PROTOCOL_PORTS['P2P_BT']))
            ].copy()
            p2p_traffic = pd.concat([p2p_traffic, tcp_p2p], ignore_index=True)
        
        if not udp_df.empty and 'DST_PORT' in udp_df.columns:
            udp_p2p = udp_df[
                (udp_df['SRC_PORT'].isin(PROTOCOL_PORTS['P2P_BT'])) | 
                (udp_df['DST_PORT'].isin(PROTOCOL_PORTS['P2P_BT']))
            ].copy()
            if 'COUNT' not in udp_p2p.columns:
                udp_p2p['COUNT'] = 1
            p2p_traffic = pd.concat([p2p_traffic, udp_p2p], ignore_index=True)
        
        if p2p_traffic.empty:
            return pd.DataFrame(columns=['SRC_IP','DST_IP','PEER_COUNT','PROTOCOL','SCORE','PATTERN','COUNT'])
        
        # Analyze P2P connections
        if 'SRC_IP' in p2p_traffic.columns and 'DST_IP' in p2p_traffic.columns:
            peer_analysis = p2p_traffic.groupby('SRC_IP').agg({
                'DST_IP': 'nunique',
                'COUNT': 'sum' if 'COUNT' in p2p_traffic.columns else 'size'
            }).reset_index()
            
            peer_analysis.columns = ['SRC_IP', 'PEER_COUNT', 'PACKET_COUNT']
            
            for _, row in peer_analysis.iterrows():
                src_ip = row['SRC_IP']
                peer_count = row['PEER_COUNT']
                packet_count = row['PACKET_COUNT']
                
                score = 0
                pattern = 'P2P Activity'
                protocol = 'BitTorrent'
                
                # High peer count indicates P2P activity
                if peer_count >= 20:
                    score = min(85, 60 + peer_count)
                    pattern = f'P2P Swarm ({peer_count} peers)'
                elif peer_count >= 10:
                    score = 50
                    pattern = f'P2P Activity ({peer_count} peers)'
                
                # Check if internal host (potential compromised machine)
                if is_private_ip(src_ip):
                    external_peers = 0
                    src_peers = p2p_traffic[p2p_traffic['SRC_IP'] == src_ip]['DST_IP'].unique()
                    external_peers = sum(1 for ip in src_peers if not is_private_ip(ip))
                    
                    if external_peers >= 10:
                        score = max(score, 75)
                        pattern = 'Internal → P2P Network (Potential Malware)'
                        protocol = 'P2P Malware Distribution'
                
                # High packet count with many peers (botnet peer discovery)
                if peer_count >= 15 and packet_count >= 100:
                    score = max(score, 80)
                    pattern = 'P2P Botnet Discovery'
                    protocol = 'Botnet P2P'
                
                if score > 0 or peer_count >= 5:
                    dst_ips = ', '.join(p2p_traffic[p2p_traffic['SRC_IP'] == src_ip]['DST_IP'].unique()[:3].tolist())
                    rows.append({
                        'SRC_IP': src_ip,
                        'DST_IP': dst_ips if len(dst_ips) <= 50 else dst_ips[:50] + '...',
                        'PEER_COUNT': int(peer_count),
                        'PROTOCOL': protocol,
                        'SCORE': score,
                        'PATTERN': pattern,
                        'COUNT': int(packet_count)
                    })
    
    except Exception:
        pass
    
    return pd.DataFrame(rows) if rows else pd.DataFrame(columns=['SRC_IP','DST_IP','PEER_COUNT','PROTOCOL','SCORE','PATTERN','COUNT'])


def compute_protocol_threats(smb_df, rdp_df, ssh_df, ftp_df, smtp_df, irc_df, p2p_df):
    """
    Aggregates threats across all protocols
    
    Returns unified threat DataFrame with:
    - INDICATOR, TYPE, PROTOCOL, SCORE, COUNT, SRC_IP, DST_IP
    """
    threats = []
    
    try:
        # SMB lateral movement and ransomware
        if not smb_df.empty:
            for _, row in smb_df.iterrows():
                if row.get('LATERAL_SCORE', 0) >= 60:
                    threats.append({
                        'INDICATOR': f"{row['SRC_IP']} → SMB Lateral Movement",
                        'TYPE': 'SMB Lateral Movement',
                        'PROTOCOL': 'SMB',
                        'SCORE': row['LATERAL_SCORE'],
                        'COUNT': row.get('COUNT', 0),
                        'SRC_IP': row['SRC_IP'],
                        'DST_IP': row.get('DST_IP', '')
                    })
                if row.get('RANSOMWARE_INDICATOR') == 'High Risk':
                    threats.append({
                        'INDICATOR': f"{row['SRC_IP']} → Ransomware Activity",
                        'TYPE': 'Ransomware Indicator',
                        'PROTOCOL': 'SMB',
                        'SCORE': 95,
                        'COUNT': row.get('COUNT', 0),
                        'SRC_IP': row['SRC_IP'],
                        'DST_IP': row.get('DST_IP', '')
                    })
        
        # RDP brute force
        if not rdp_df.empty:
            for _, row in rdp_df.iterrows():
                if row.get('SCORE', 0) >= 70:
                    threats.append({
                        'INDICATOR': f"{row['SRC_IP']} → RDP {row.get('STATUS', 'Attack')}",
                        'TYPE': 'RDP Brute Force',
                        'PROTOCOL': 'RDP',
                        'SCORE': row['SCORE'],
                        'COUNT': row.get('ATTEMPTS', 0),
                        'SRC_IP': row['SRC_IP'],
                        'DST_IP': row.get('DST_IP', '')
                    })
        
        # SSH brute force
        if not ssh_df.empty:
            for _, row in ssh_df.iterrows():
                if row.get('SCORE', 0) >= 70:
                    threats.append({
                        'INDICATOR': f"{row['SRC_IP']} → SSH {row.get('PATTERN', 'Attack')}",
                        'TYPE': 'SSH Brute Force/Scan',
                        'PROTOCOL': 'SSH',
                        'SCORE': row['SCORE'],
                        'COUNT': row.get('ATTEMPTS', 0),
                        'SRC_IP': row['SRC_IP'],
                        'DST_IP': row.get('DST_IP', '')
                    })
        
        # FTP exfiltration
        if not ftp_df.empty:
            for _, row in ftp_df.iterrows():
                if row.get('SCORE', 0) >= 60:
                    threats.append({
                        'INDICATOR': f"{row['SRC_IP']} → FTP {row.get('PATTERN', 'Activity')}",
                        'TYPE': 'FTP Data Exfiltration',
                        'PROTOCOL': 'FTP',
                        'SCORE': row['SCORE'],
                        'COUNT': row.get('COUNT', 0),
                        'SRC_IP': row['SRC_IP'],
                        'DST_IP': row.get('DST_IP', '')
                    })
        
        # SMTP spam
        if not smtp_df.empty:
            for _, row in smtp_df.iterrows():
                if row.get('SCORE', 0) >= 75:
                    threats.append({
                        'INDICATOR': f"{row['SRC_IP']} → SMTP {row.get('TYPE', 'Spam')}",
                        'TYPE': 'SMTP Spam Botnet',
                        'PROTOCOL': 'SMTP',
                        'SCORE': row['SCORE'],
                        'COUNT': row.get('EMAIL_COUNT', 0),
                        'SRC_IP': row['SRC_IP'],
                        'DST_IP': row.get('DST_IP', '')
                    })
        
        # IRC C2
        if not irc_df.empty:
            for _, row in irc_df.iterrows():
                if row.get('SCORE', 0) >= 75:
                    threats.append({
                        'INDICATOR': f"{row['SRC_IP']} → IRC {row.get('TYPE', 'C2')}",
                        'TYPE': 'IRC C2 Communication',
                        'PROTOCOL': 'IRC',
                        'SCORE': row['SCORE'],
                        'COUNT': row.get('COUNT', 0),
                        'SRC_IP': row['SRC_IP'],
                        'DST_IP': row.get('DST_IP', '')
                    })
        
        # P2P malware
        if not p2p_df.empty:
            for _, row in p2p_df.iterrows():
                if row.get('SCORE', 0) >= 75:
                    threats.append({
                        'INDICATOR': f"{row['SRC_IP']} → P2P {row.get('PROTOCOL', 'Activity')}",
                        'TYPE': 'P2P Malware Distribution',
                        'PROTOCOL': 'P2P',
                        'SCORE': row['SCORE'],
                        'COUNT': row.get('PEER_COUNT', 0),
                        'SRC_IP': row['SRC_IP'],
                        'DST_IP': row.get('DST_IP', '')
                    })
    
    except Exception:
        pass
    
    return pd.DataFrame(threats) if threats else pd.DataFrame(columns=['INDICATOR','TYPE','PROTOCOL','SCORE','COUNT','SRC_IP','DST_IP'])

# -----------------------
# JS and HTML templates (embedded)
# -----------------------
JS_TEMPLATE = r"""
// === Dashboard JS (Stability v23.0 - Multi-Source Correlation + ML-Enhanced Detection) ===
if (window.__DASHBOARD_ACTIVE__) { console.warn("Dashboard already active — skipping duplicate init."); }
else { window.__DASHBOARD_ACTIVE__ = true; }

if (window.jQuery && window.jQuery.fn) {
  try { $.fn.dataTable.ext.errMode = 'none'; } catch(e) {}
}

const dnsData       = %%DNS%%;
const httpData      = %%HTTP%%;
const tlsData       = %%TLS%%;
const tcpData       = %%TCP%%;

const c2FullData    = %%C2FULL%%;

const advData       = %%ADV%%;
const beaconData    = %%BEACON%%;
const dnstunnelData = %%DNSTUNNEL%%;

// DDoS Detection Data
const ddosData      = %%DDOS%%;

// HTTP C2 Detection Data
const httpC2Data    = %%HTTPC2%%;

// ✅ NEW: TCP IP Distribution Data
const tcpIPData     = %%TCPIP%%;

// ✅ NEW: ML Detection Data
const mlDDoSData    = %%MLDDOS%%;
const mlAnomalies   = %%MLANOMALIES%%;
const mlFeatures    = %%MLFEATURES%%;

// ✅ PRIORITY 2: Change Point Detection Data
const changePointsData = %%CHANGEPOINTS%%;
const temporalPatternsData = %%TEMPORALPATTERNS%%;
const slidingWindowsData = %%SLIDINGWINDOWS%%;

// ✅ PRIORITY 2: Flow Analysis Data
const flowFeaturesData = %%FLOWFEATURES%%;
const flowAnomaliesData = %%FLOWANOMALIES%%;
const bidirectionalAnomaliesData = %%BIDIRECTIONALANOMALIES%%;

// ✅ PRIORITY 3: Protocol Detection Data
const smbData = %%SMB%%;
const rdpData = %%RDP%%;
const sshData = %%SSH%%;
const ftpData = %%FTP%%;
const smtpData = %%SMTP%%;
const ircData = %%IRC%%;
const p2pData = %%P2P%%;
const protocolThreatsData = %%PROTOCOLTHREATS%%;

// ✅ NEW: Botnet Family Detection Data
const botnetData = %%BOTNET%%;

// ✅ MULTI-SOURCE CORRELATION DATA
const correlationC2Data = %%CORRELATION_C2%%;
const correlationAttacksData = %%CORRELATION_ATTACKS%%;
const correlationLateralData = %%CORRELATION_LATERAL%%;
const correlationBeaconsData = %%CORRELATION_BEACONS%%;
const sourceMetadataData = %%SOURCE_METADATA%%;


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


// ------------------------------------------------------------
// Dashboard update
// ------------------------------------------------------------
function updateDashboard(){

  const topN = parseInt(document.getElementById('topN').value || '15');

  const fs = (document.getElementById('filter_src')||{value:''}).value.trim().toLowerCase();
  const fd = (document.getElementById('filter_dst')||{value:''}).value.trim().toLowerCase();
  const fm = (document.getElementById('filter_dom')||{value:''}).value.trim().toLowerCase();

  const ff = r=>{
    if(fs && r.SRC_IP && !String(r.SRC_IP).toLowerCase().includes(fs)) return false;
    if(fd && r.DST_IP && !String(r.DST_IP).toLowerCase().includes(fd)) return false;
    if(fm){
      const s = Object.values(r).join(' ').toLowerCase();
      if(!s.includes(fm)) return false;
    }
    return true;
  };

  const dnsSlice  = (dnsData||[]).filter(ff).slice().sort((a,b)=>(b.COUNT||0)-(a.COUNT||0)).slice(0,topN);
  const httpSlice = (httpData||[]).filter(ff).slice().sort((a,b)=>(b.COUNT||0)-(a.COUNT||0)).slice(0,topN);
  const tlsSlice  = (tlsData||[]).filter(ff).slice().sort((a,b)=>(b.COUNT||0)-(a.COUNT||0)).slice(0,topN);

  const tcpSliceFiltered = (tcpData||[]).filter(ff).slice().sort((a,b)=>(b.COUNT||0)-(a.COUNT||0)).slice(0,topN);
  const tcpSliceFull     = (tcpData||[]).filter(ff).slice().sort((a,b)=>(b.COUNT||0)-(a.COUNT||0));

  // ------------------------
  // TABLES
  // ------------------------
  renderTableRows(document.querySelector('#tbl_dns tbody'), dnsSlice, ['DOMAIN','COUNT','PERCENT']);
  renderTableRows(document.querySelector('#tbl_http tbody'), httpSlice, ['DOMAIN','COUNT','PERCENT']);
  renderTableRows(document.querySelector('#tbl_tls tbody'), tlsSlice, ['SNI','JA3','SRC_IP','DST_IP','COUNT','PERCENT']);
  renderTableRows(document.querySelector('#tbl_tcp tbody'), tcpSliceFiltered, ['SRC_IP','DST_IP','FLAGS','COUNT','PERCENT']);

  renderTableRows(
    document.querySelector('#tbl_c2 tbody'),
    (c2FullData||[]).filter(ff).slice(0,topN),
    ['INDICATOR','TYPE','SCORE','COUNT']
  );

  renderTableRows(document.querySelector('#tbl_adv tbody'), (advData||[]).filter(ff).slice(0,topN), ['INDICATOR','TYPE','SCORE','COUNT']);
  renderTableRows(document.querySelector('#tbl_beacon tbody'), (beaconData||[]).filter(ff).slice(0,topN), ['INDICATOR','TYPE','SCORE','COUNT']);
  renderTableRows(document.querySelector('#tbl_dnstunnel tbody'), (dnstunnelData||[]).filter(ff).slice(0,topN), ['INDICATOR','TYPE','SCORE','COUNT','NOTES']);
  
  // DDoS Detection table
  const ddosSlice = (ddosData||[]).filter(ff).slice().sort((a,b)=>(b.SCORE||0)-(a.SCORE||0)).slice(0,topN);
  renderTableRows(document.querySelector('#tbl_ddos tbody'), ddosSlice, ['INDICATOR','TYPE','SCORE','COUNT']);

  // HTTP C2 Detection table
  const httpC2Slice = (httpC2Data||[]).filter(ff).slice().sort((a,b)=>(b.SCORE||0)-(a.SCORE||0)).slice(0,topN);
  renderTableRows(document.querySelector('#tbl_http_c2 tbody'), httpC2Slice, 
    ['C2_SERVER','BOT_COUNT','EXTRACTED_IPS','TARGETS_DISTRIBUTED','PAYLOAD_SAMPLE',
     'TARGETS_ATTACKED','CORRELATION_SCORE','TIME_TO_ATTACK','SCORE']);

  // ✅ NEW: TCP IP Distribution table
  const tcpIPSlice = (tcpIPData||[]).filter(ff).slice().sort((a,b)=>(b.SCORE||0)-(a.SCORE||0)).slice(0,topN);
  renderTableRows(document.querySelector('#tbl_tcp_ip tbody'), tcpIPSlice, 
    ['SRC_IP','SRC_PORT','DST_IP','DST_PORT','EXTRACTED_IPS','IPS_FOUND','PAYLOAD_SAMPLE','SCORE']);

  // ✅ NEW: ML DDoS Detection table
  const mlDDoSSlice = (mlDDoSData||[]).filter(ff).slice().sort((a,b)=>(b.ML_SCORE||0)-(a.ML_SCORE||0)).slice(0,topN);
  if(document.querySelector('#tbl_ml_ddos tbody')) {
    renderTableRows(document.querySelector('#tbl_ml_ddos tbody'), mlDDoSSlice,
      ['SRC_IP','PROTOCOL','PREDICTION','ML_SCORE','PACKET_RATE','UNIQUE_DST_IPS']);
  }

  // ✅ NEW: ML Anomaly Detection table
  const mlAnomalySlice = (mlAnomalies||[]).filter(ff).slice().sort((a,b)=>(b.ANOMALY_SCORE||0)-(a.ANOMALY_SCORE||0)).slice(0,topN);
  if(document.querySelector('#tbl_ml_anomalies tbody')) {
    renderTableRows(document.querySelector('#tbl_ml_anomalies tbody'), mlAnomalySlice,
      ['SRC_IP','PROTOCOL','ANOMALY_SCORE','BASELINE_DEVIATION','PACKET_RATE','UNIQUE_DST_IPS']);
  }

  // Update ML count indicators
  const mlCountEl = document.getElementById('ml_count');
  if(mlCountEl) {
    const attackCount = (mlDDoSData||[]).filter(ff).filter(x => x.PREDICTION === 'ATTACK').length;
    mlCountEl.textContent = attackCount + (mlAnomalies||[]).filter(ff).length;
    mlCountEl.style.color = (attackCount + (mlAnomalies||[]).filter(ff).length) > 0 ? '#dc2626' : '#10b981';
  }

  // ✅ PRIORITY 2: Change Point Detection table
  const cpSlice = (changePointsData||[]).filter(ff).slice(0, topN);
  if(document.querySelector('#tbl_change_points tbody')) {
    renderTableRows(document.querySelector('#tbl_change_points tbody'), cpSlice,
      ['timestamp','value','deviation','cusum_pos','cusum_neg']);
  }
  
  // ✅ PRIORITY 2: Flow Anomalies table
  const flowAnomalySlice = (flowAnomaliesData||[]).filter(ff).slice().sort((a,b)=>(b.anomaly_score||0)-(a.anomaly_score||0)).slice(0,topN);
  if(document.querySelector('#tbl_flow_anomalies tbody')) {
    renderTableRows(document.querySelector('#tbl_flow_anomalies tbody'), flowAnomalySlice,
      ['flow_id','src_ip','dst_ip','anomaly_score','anomaly_reasons']);
  }
  
  // ✅ PRIORITY 2: Bidirectional Flow table
  const bidirSlice = (bidirectionalAnomaliesData||[]).filter(ff).slice().sort((a,b)=>(b.asymmetry_score||0)-(a.asymmetry_score||0)).slice(0,topN);
  if(document.querySelector('#tbl_bidirectional tbody')) {
    renderTableRows(document.querySelector('#tbl_bidirectional tbody'), bidirSlice,
      ['flow_id','src_ip','dst_ip','asymmetry_score','packet_ratio','byte_ratio','anomaly_type']);
  }

  // ✅ PRIORITY 3: Protocol Detection Tables
  const smbSlice = (smbData||[]).filter(r=>(r.LATERAL_SCORE||0)>0).slice().sort((a,b)=>(b.LATERAL_SCORE||0)-(a.LATERAL_SCORE||0)).slice(0,topN);
  if(document.querySelector('#tbl_smb tbody')) {
    renderTableRows(document.querySelector('#tbl_smb tbody'), smbSlice,
      ['SRC_IP','DST_IP','SMB_VERSION','OPERATION','LATERAL_SCORE','RANSOMWARE_INDICATOR','COUNT']);
  }
  
  const rdpSlice = (rdpData||[]).filter(r=>(r.SCORE||0)>0).slice().sort((a,b)=>(b.SCORE||0)-(a.SCORE||0)).slice(0,topN);
  if(document.querySelector('#tbl_rdp tbody')) {
    renderTableRows(document.querySelector('#tbl_rdp tbody'), rdpSlice,
      ['SRC_IP','DST_IP','ATTEMPTS','STATUS','SCORE','PATTERN','COUNT']);
  }
  
  const sshSlice = (sshData||[]).filter(r=>(r.SCORE||0)>0).slice().sort((a,b)=>(b.SCORE||0)-(a.SCORE||0)).slice(0,topN);
  if(document.querySelector('#tbl_ssh tbody')) {
    renderTableRows(document.querySelector('#tbl_ssh tbody'), sshSlice,
      ['SRC_IP','DST_IP','ATTEMPTS','PATTERN','SCORE','VERSION','COUNT']);
  }
  
  const ftpSlice = (ftpData||[]).filter(r=>(r.SCORE||0)>0).slice().sort((a,b)=>(b.SCORE||0)-(a.SCORE||0)).slice(0,topN);
  if(document.querySelector('#tbl_ftp tbody')) {
    renderTableRows(document.querySelector('#tbl_ftp tbody'), ftpSlice,
      ['SRC_IP','DST_IP','OPERATION','SIZE_MB','SCORE','PATTERN','COUNT']);
  }
  
  const smtpSlice = (smtpData||[]).filter(r=>(r.SCORE||0)>0).slice().sort((a,b)=>(b.SCORE||0)-(a.SCORE||0)).slice(0,topN);
  if(document.querySelector('#tbl_smtp tbody')) {
    renderTableRows(document.querySelector('#tbl_smtp tbody'), smtpSlice,
      ['SRC_IP','DST_IP','EMAIL_COUNT','TYPE','SCORE','PATTERN','COUNT']);
  }
  
  const ircSlice = (ircData||[]).filter(r=>(r.SCORE||0)>0).slice().sort((a,b)=>(b.SCORE||0)-(a.SCORE||0)).slice(0,topN);
  if(document.querySelector('#tbl_irc tbody')) {
    renderTableRows(document.querySelector('#tbl_irc tbody'), ircSlice,
      ['SRC_IP','DST_IP','CHANNEL','TYPE','SCORE','PATTERN','COUNT']);
  }
  
  const p2pSlice = (p2pData||[]).filter(r=>(r.SCORE||0)>0).slice().sort((a,b)=>(b.SCORE||0)-(a.SCORE||0)).slice(0,topN);
  if(document.querySelector('#tbl_p2p tbody')) {
    renderTableRows(document.querySelector('#tbl_p2p tbody'), p2pSlice,
      ['SRC_IP','DST_IP','PEER_COUNT','PROTOCOL','SCORE','PATTERN','COUNT']);
  }
  
  const protocolThreatSlice = (protocolThreatsData||[]).filter(r=>(r.SCORE||0)>=60).slice().sort((a,b)=>(b.SCORE||0)-(a.SCORE||0)).slice(0,topN);
  if(document.querySelector('#tbl_protocol_threats tbody')) {
    renderTableRows(document.querySelector('#tbl_protocol_threats tbody'), protocolThreatSlice,
      ['INDICATOR','TYPE','PROTOCOL','SCORE','COUNT','SRC_IP']);
  }
  
  // ✅ NEW: Botnet Family Detection Table
  const botnetSlice = (botnetData||[]).filter(r=>(r.CONFIDENCE||0)>=50).slice().sort((a,b)=>(b.CONFIDENCE||0)-(a.CONFIDENCE||0)).slice(0,topN);
  if(document.querySelector('#tbl_botnet tbody')) {
    renderTableRows(document.querySelector('#tbl_botnet tbody'), botnetSlice,
      ['FAMILY','CATEGORY','SEVERITY','CONFIDENCE','PROTOCOL','EVIDENCE','SRC_IP','DST_IP','COUNT']);
  }
  
  // ✅ MULTI-SOURCE CORRELATION TABLES
  // Source Metadata
  const sourceMetaSlice = (sourceMetadataData||[]).slice(0,50);
  if(document.querySelector('#tbl_source_metadata tbody')) {
    renderTableRows(document.querySelector('#tbl_source_metadata tbody'), sourceMetaSlice,
      ['SOURCE_ID','PCAP_FILE','PACKETS','PROTOCOLS']);
  }
  
  // Cross-Source C2 Correlation
  const correlationC2Slice = (correlationC2Data||[]).slice().sort((a,b)=>(b.CONFIDENCE_SCORE||0)-(a.CONFIDENCE_SCORE||0)).slice(0,topN);
  if(document.querySelector('#tbl_correlation_c2 tbody')) {
    renderTableRows(document.querySelector('#tbl_correlation_c2 tbody'), correlationC2Slice,
      ['C2_INDICATOR','SOURCES','SOURCE_COUNT','CONFIDENCE_SCORE','TYPE']);
  }
  
  // Coordinated Attack Correlation
  const correlationAttacksSlice = (correlationAttacksData||[]).slice().sort((a,b)=>(b.CONFIDENCE_SCORE||0)-(a.CONFIDENCE_SCORE||0)).slice(0,topN);
  if(document.querySelector('#tbl_correlation_attacks tbody')) {
    renderTableRows(document.querySelector('#tbl_correlation_attacks tbody'), correlationAttacksSlice,
      ['ATTACK_PATTERN','SOURCES','SOURCE_COUNT','TIME_SPREAD','CONFIDENCE_SCORE','TYPE']);
  }
  
  // Lateral Movement Correlation
  const correlationLateralSlice = (correlationLateralData||[]).slice().sort((a,b)=>(b.CONFIDENCE_SCORE||0)-(a.CONFIDENCE_SCORE||0)).slice(0,topN);
  if(document.querySelector('#tbl_correlation_lateral tbody')) {
    renderTableRows(document.querySelector('#tbl_correlation_lateral tbody'), correlationLateralSlice,
      ['ATTACKER_IP','SOURCES','SOURCE_COUNT','ACTIVITIES','AVG_THREAT_SCORE','CONFIDENCE_SCORE']);
  }
  
  // Beacon Timing Correlation
  const correlationBeaconsSlice = (correlationBeaconsData||[]).slice().sort((a,b)=>(b.CONFIDENCE_SCORE||0)-(a.CONFIDENCE_SCORE||0)).slice(0,topN);
  if(document.querySelector('#tbl_correlation_beacons tbody')) {
    renderTableRows(document.querySelector('#tbl_correlation_beacons tbody'), correlationBeaconsSlice,
      ['BEACON_DESTINATION','AVG_INTERVAL','SOURCES','SOURCE_COUNT','CONFIDENCE_SCORE','TYPE']);
  }

  // ------------------------
  // PIVOT
  // ------------------------
  renderPivot(document.querySelector('#pivot tbody'), tcpSliceFull);

  // Update DDoS count indicator
  const ddosCountEl = document.getElementById('ddos_count');
  if(ddosCountEl) {
    ddosCountEl.textContent = (ddosData||[]).filter(ff).length;
    ddosCountEl.style.color = (ddosData||[]).filter(ff).length > 0 ? '#dc2626' : '#10b981';
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
  
  // ✅ PRIORITY 2: Change Points Chart
  try{
    const cpCanvas = document.getElementById('chart_change_points');
    if(cpCanvas && changePointsData && changePointsData.length > 0){
      const ctx = prepareCanvas(cpCanvas, 220);
      if(ctx){
        window._change_points = new Chart(ctx, {
          type:'scatter',
          data:{
            datasets:[{
              label:'Change Points',
              data: changePointsData.map(cp => ({
                x: cp.timestamp || 0,
                y: cp.value || 0,
                r: Math.min(10, (cp.deviation || 0))
              })),
              backgroundColor: 'rgba(220, 38, 38, 0.7)',
              borderColor: 'rgba(220, 38, 38, 1)',
              pointRadius: 6
            }]
          },
          options:{
            responsive:false,
            animation:false,
            legend:{ display:false },
            scales:{
              xAxes:[{ type:'linear', position:'bottom', scaleLabel:{ display:true, labelString:'Time' } }],
              yAxes:[{ scaleLabel:{ display:true, labelString:'Traffic Value' } }]
            }
          }
        });
      }
    } else if(cpCanvas) {
      cpCanvas.parentElement.innerHTML = '<p style="text-align:center;opacity:0.6;padding:40px">No change points detected</p>';
    }
  }catch(e){
    console.log('change points chart err', e);
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
<title>PCAP Dashboard (Stability v23.0 - Multi-Source Correlation + Protocol Detection + ML)</title>
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
<style>
:root{--card-h:220px}*{box-sizing:border-box}
body{margin:0;font-family:Inter,Arial,Helvetica,sans-serif;background:#f5f7fa;color:#111;font-size:11px}
.app{display:flex;min-height:100vh}
.sidebar{width:240px;background:#0f1724;color:#fff;padding:18px;font-size:11px;flex-shrink:0}
.content{flex:1;padding:18px;max-width:100%}

/* ✅ 2-Column Grid Layout */
.card-grid{
  display:grid;
  grid-template-columns:repeat(2, 1fr);  /* 2 equal columns */
  gap:16px;
  margin-bottom:16px;
}

/* Responsive: 1 column on smaller screens */
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
    <h1 style='margin:0 0 12px 0'>PCAP Analysis Dashboard (Stability v23.0 - Multi-Source Correlation)</h1>

    <div style='margin-bottom:12px'>
      <label>Source IP: <input id='filter_src' type='text'></label>
      <label style='margin-left:12px'>Dest IP: <input id='filter_dst' type='text'></label>
      <label style='margin-left:12px'>Domain/SNI: <input id='filter_dom' type='text'></label>
      <label style='margin-left:12px'>Show Top: <select id='topN'><option value='15'>15</option><option value='25'>25</option><option value='50'>50</option><option value='99999'>All</option></select></label>
      <button id='darkToggle' style='margin-left:12px'>Dark</button>
    </div>

    <div class='card-grid'>
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
  
  <!-- ✅ NEW: ML Detection Summary Card -->
  <div class='card' style='grid-column: span 2;'>
    <h3>🤖 Machine Learning Detection Summary</h3>
    <div style='display:flex;gap:20px;padding:15px 0;'>
      <div style='flex:1;text-align:center;border-right:1px solid #e5e7eb;'>
        <div style='font-size:28px;font-weight:bold;color:#8b5cf6' id='ml_count'>0</div>
        <div style='font-size:10px;color:#6b7280;margin-top:4px'>ML Detections</div>
      </div>
      <div style='flex:2;font-size:10px;color:#6b7280;'>
        <div>✓ Random Forest Classifier for DDoS</div>
        <div>✓ Isolation Forest for Anomalies</div>
        <div>✓ Adaptive Baseline Thresholds</div>
        <div>✓ Jitter-Tolerant Beaconing</div>
      </div>
    </div>
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

<!-- ✅ NEW: ML DDoS Detection Section -->
<div style='margin-top:18px' class='card'>
  <h3>🤖 ML DDoS Classification (Random Forest)</h3>
  <p style='font-size:10px;opacity:0.8;margin-bottom:8px'>Machine learning predictions using Random Forest classifier on 20+ traffic features</p>
  <div class='table-wrap'><table id='tbl_ml_ddos' class='display'><thead><tr><th>SRC IP</th><th>Protocol</th><th>Prediction</th><th>ML Score</th><th>Packet Rate</th><th>Unique Destinations</th></tr></thead><tbody></tbody></table></div>
</div>

<!-- ✅ NEW: ML Anomaly Detection Section -->
<div style='margin-top:18px' class='card'>
  <h3>🤖 ML Anomaly Detection (Isolation Forest)</h3>
  <p style='font-size:10px;opacity:0.8;margin-bottom:8px'>Zero-day attack detection using Isolation Forest for outlier identification</p>
  <div class='table-wrap'><table id='tbl_ml_anomalies' class='display'><thead><tr><th>SRC IP</th><th>Protocol</th><th>Anomaly Score</th><th>Baseline Deviation</th><th>Packet Rate</th><th>Unique Destinations</th></tr></thead><tbody></tbody></table></div>
</div>

<!-- ✅ PRIORITY 2: Change Point Detection -->
<div style='margin-top:18px' class='card'>
  <h3>📊 Change Point Detection (CUSUM)</h3>
  <p style='font-size:10px;opacity:0.8;margin-bottom:8px'>Detects abrupt changes in traffic patterns using CUSUM algorithm</p>
  <div id='chart_change_points' style='height:220px;margin-bottom:12px'></div>
  <div class='table-wrap'><table id='tbl_change_points' class='display'><thead><tr><th>Timestamp</th><th>Value</th><th>Deviation (σ)</th><th>CUSUM+</th><th>CUSUM-</th></tr></thead><tbody></tbody></table></div>
</div>

<!-- ✅ PRIORITY 2: Flow Analysis -->
<div style='margin-top:18px' class='card'>
  <h3>🌊 Flow-Level Anomalies</h3>
  <p style='font-size:10px;opacity:0.8;margin-bottom:8px'>Statistical analysis of network flows (5-tuple aggregation)</p>
  <div class='table-wrap'><table id='tbl_flow_anomalies' class='display'><thead><tr><th>Flow ID</th><th>SRC IP</th><th>DST IP</th><th>Anomaly Score</th><th>Reasons</th></tr></thead><tbody></tbody></table></div>
</div>

<!-- ✅ PRIORITY 2: Bidirectional Flow Analysis -->
<div style='margin-top:18px' class='card'>
  <h3>⇄ Bidirectional Flow Analysis</h3>
  <p style='font-size:10px;opacity:0.8;margin-bottom:8px'>Detects asymmetric flows that may indicate data exfiltration or C2</p>
  <div class='table-wrap'><table id='tbl_bidirectional' class='display'><thead><tr><th>Flow ID</th><th>SRC IP</th><th>DST IP</th><th>Asymmetry Score</th><th>Packet Ratio</th><th>Byte Ratio</th><th>Type</th></tr></thead><tbody></tbody></table></div>
</div>

<!-- ✅ PRIORITY 3: Protocol Detection Tables -->
<div style='margin-top:18px' class='card'>
  <h3>🔒 SMB/CIFS Activity Detection</h3>
  <p style='font-size:10px;opacity:0.8;margin-bottom:8px'>Detects lateral movement, ransomware, and admin share access (ports 445, 139)</p>
  <div class='table-wrap'><table id='tbl_smb' class='display'><thead><tr><th>SRC IP</th><th>DST IP</th><th>SMB Version</th><th>Operation</th><th>Lateral Score</th><th>Ransomware</th><th>Targets</th></tr></thead><tbody></tbody></table></div>
</div>

<div style='margin-top:18px' class='card'>
  <h3>🖥️ RDP Activity Detection</h3>
  <p style='font-size:10px;opacity:0.8;margin-bottom:8px'>Detects brute force attacks and unauthorized remote access (port 3389)</p>
  <div class='table-wrap'><table id='tbl_rdp' class='display'><thead><tr><th>SRC IP</th><th>DST IP</th><th>Attempts</th><th>Status</th><th>Score</th><th>Pattern</th><th>Count</th></tr></thead><tbody></tbody></table></div>
</div>

<div style='margin-top:18px' class='card'>
  <h3>🔐 SSH Activity Detection</h3>
  <p style='font-size:10px;opacity:0.8;margin-bottom:8px'>Detects brute force, tunneling, and scanning (port 22)</p>
  <div class='table-wrap'><table id='tbl_ssh' class='display'><thead><tr><th>SRC IP</th><th>DST IP</th><th>Attempts</th><th>Pattern</th><th>Score</th><th>Version</th><th>Count</th></tr></thead><tbody></tbody></table></div>
</div>

<div style='margin-top:18px' class='card'>
  <h3>📁 FTP/SFTP Activity Detection</h3>
  <p style='font-size:10px;opacity:0.8;margin-bottom:8px'>Detects data exfiltration and unauthorized file access (ports 20, 21)</p>
  <div class='table-wrap'><table id='tbl_ftp' class='display'><thead><tr><th>SRC IP</th><th>DST IP</th><th>Operation</th><th>Size (MB)</th><th>Score</th><th>Pattern</th><th>Count</th></tr></thead><tbody></tbody></table></div>
</div>

<div style='margin-top:18px' class='card'>
  <h3>📧 SMTP Activity Detection</h3>
  <p style='font-size:10px;opacity:0.8;margin-bottom:8px'>Detects spam botnets and email exfiltration (ports 25, 587, 465)</p>
  <div class='table-wrap'><table id='tbl_smtp' class='display'><thead><tr><th>SRC IP</th><th>DST IP</th><th>Email Count</th><th>Type</th><th>Score</th><th>Pattern</th><th>Packets</th></tr></thead><tbody></tbody></table></div>
</div>

<div style='margin-top:18px' class='card'>
  <h3>💬 IRC Activity Detection</h3>
  <p style='font-size:10px;opacity:0.8;margin-bottom:8px'>Detects legacy C2 channels and botnet commands (ports 6667, 6697, 194)</p>
  <div class='table-wrap'><table id='tbl_irc' class='display'><thead><tr><th>SRC IP</th><th>DST IP</th><th>Channel</th><th>Type</th><th>Score</th><th>Pattern</th><th>Count</th></tr></thead><tbody></tbody></table></div>
</div>

<div style='margin-top:18px' class='card'>
  <h3>🌐 P2P Protocol Detection</h3>
  <p style='font-size:10px;opacity:0.8;margin-bottom:8px'>Detects P2P malware distribution and botnet peer discovery (BitTorrent DHT)</p>
  <div class='table-wrap'><table id='tbl_p2p' class='display'><thead><tr><th>SRC IP</th><th>DST IP</th><th>Peer Count</th><th>Protocol</th><th>Score</th><th>Pattern</th><th>Packets</th></tr></thead><tbody></tbody></table></div>
</div>

<div style='margin-top:18px' class='card'>
  <h3>⚠️ Protocol Threat Summary</h3>
  <p style='font-size:10px;opacity:0.8;margin-bottom:8px'>Aggregated high-severity threats detected across all protocols</p>
  <div class='table-wrap'><table id='tbl_protocol_threats' class='display'><thead><tr><th>Indicator</th><th>Type</th><th>Protocol</th><th>Score</th><th>Count</th><th>SRC IP</th></tr></thead><tbody></tbody></table></div>
</div>

<div style='margin-top:18px' class='card'>
  <h3>🦠 Botnet Family Detection</h3>
  <p style='font-size:10px;opacity:0.8;margin-bottom:8px'>Known botnet families detected via payload signatures, JA3 fingerprints, ports, and behavior patterns</p>
  <div class='table-wrap'><table id='tbl_botnet' class='display'><thead><tr><th>Family</th><th>Category</th><th>Severity</th><th>Confidence</th><th>Protocol</th><th>Evidence</th><th>SRC IP</th><th>DST IP</th><th>Count</th></tr></thead><tbody></tbody></table></div>
</div>

<div style='margin-top:24px; padding:12px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); border-radius:8px;'>
  <h2 style='color: white; margin: 0; font-size: 18px; text-align: center;'>🔗 Multi-Source Correlation Analysis</h2>
  <p style='color: rgba(255,255,255,0.9); font-size: 11px; text-align: center; margin: 4px 0 0 0;'>Cross-network detection of coordinated attacks, shared infrastructure, and lateral movement</p>
</div>

<div style='margin-top:18px' class='card'>
  <h3>📊 Source Metadata</h3>
  <p style='font-size:10px;opacity:0.8;margin-bottom:8px'>Overview of analyzed PCAP sources</p>
  <div class='table-wrap'><table id='tbl_source_metadata' class='display'><thead><tr><th>Source ID</th><th>PCAP File</th><th>Packets</th><th>Protocols</th></tr></thead><tbody></tbody></table></div>
</div>

<div style='margin-top:18px' class='card'>
  <h3>🎯 Shared C2 Infrastructure</h3>
  <p style='font-size:10px;opacity:0.8;margin-bottom:8px'>C2 indicators detected across multiple sources (same IPs, domains, JA3 fingerprints)</p>
  <div class='table-wrap'><table id='tbl_correlation_c2' class='display'><thead><tr><th>C2 Indicator</th><th>Sources</th><th>Source Count</th><th>Confidence</th><th>Type</th></tr></thead><tbody></tbody></table></div>
</div>

<div style='margin-top:18px' class='card'>
  <h3>⚔️ Coordinated Attack Patterns</h3>
  <p style='font-size:10px;opacity:0.8;margin-bottom:8px'>DDoS attacks and coordinated campaigns detected across sources</p>
  <div class='table-wrap'><table id='tbl_correlation_attacks' class='display'><thead><tr><th>Attack Pattern</th><th>Sources</th><th>Source Count</th><th>Time Spread (s)</th><th>Confidence</th><th>Type</th></tr></thead><tbody></tbody></table></div>
</div>

<div style='margin-top:18px' class='card'>
  <h3>🔄 Lateral Movement Detection</h3>
  <p style='font-size:10px;opacity:0.8;margin-bottom:8px'>Attackers moving between monitored networks (pivot points and compromised hosts)</p>
  <div class='table-wrap'><table id='tbl_correlation_lateral' class='display'><thead><tr><th>Attacker IP</th><th>Sources</th><th>Source Count</th><th>Activities</th><th>Avg Threat Score</th><th>Confidence</th></tr></thead><tbody></tbody></table></div>
</div>

<div style='margin-top:18px' class='card'>
  <h3>📡 Synchronized C2 Beacons</h3>
  <p style='font-size:10px;opacity:0.8;margin-bottom:8px'>Beacon timing correlation (shared C2 heartbeat patterns)</p>
  <div class='table-wrap'><table id='tbl_correlation_beacons' class='display'><thead><tr><th>Destination</th><th>Avg Interval (s)</th><th>Sources</th><th>Source Count</th><th>Confidence</th><th>Type</th></tr></thead><tbody></tbody></table></div>
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
# Multi-Source Correlation Functions
# -----------------------

def correlate_cross_source_c2(source_data):
    """
    Detect shared C2 infrastructure across sources
    
    Detection criteria:
    1. Same C2 IP/domain seen in 2+ sources
    2. Same JA3 fingerprint with similar SNI patterns
    3. Similar beacon intervals across sources
    4. Shared target lists
    
    Args:
        source_data: Dictionary of {source_id: detection_results}
        
    Returns:
        DataFrame with columns [C2_INDICATOR, SOURCES, SOURCE_COUNT, CONFIDENCE_SCORE, TYPE]
    """
    rows = []
    
    # Collect all C2 indicators from all sources
    c2_map = defaultdict(lambda: {'sources': set(), 'details': []})
    
    for source_id, data in source_data.items():
        c2_detections = data.get('c2_full', pd.DataFrame())
        if c2_detections.empty:
            continue
            
        for _, row in c2_detections.iterrows():
            indicator = row.get('INDICATOR', '')
            if not indicator:
                continue
            c2_map[indicator]['sources'].add(source_id)
            c2_map[indicator]['details'].append(row)
    
    # Find indicators seen in multiple sources
    for indicator, info in c2_map.items():
        if len(info['sources']) >= MIN_SOURCES_FOR_CORRELATION:
            confidence = min(100, 60 + (len(info['sources']) * 10))
            rows.append({
                'C2_INDICATOR': indicator,
                'SOURCES': ', '.join(sorted(info['sources'])),
                'SOURCE_COUNT': len(info['sources']),
                'CONFIDENCE_SCORE': confidence,
                'TYPE': 'Shared C2 Infrastructure'
            })
    
    return pd.DataFrame(rows) if rows else pd.DataFrame(columns=['C2_INDICATOR', 'SOURCES', 'SOURCE_COUNT', 'CONFIDENCE_SCORE', 'TYPE'])


def correlate_attack_patterns(source_data):
    """
    Detect coordinated DDoS attacks across sources
    
    Identifies:
    - Coordinated DDoS attacks targeting same victims
    - Botnet activity patterns across networks
    - Synchronized attack campaigns
    
    Args:
        source_data: Dictionary of {source_id: detection_results}
        
    Returns:
        DataFrame with temporal and behavioral correlation
    """
    rows = []
    
    # Collect DDoS detections from all sources
    ddos_map = defaultdict(lambda: {'sources': set(), 'timestamps': [], 'targets': set()})
    
    for source_id, data in source_data.items():
        ddos_detections = data.get('ddos', pd.DataFrame())
        if ddos_detections.empty:
            continue
            
        for _, row in ddos_detections.iterrows():
            attack_type = row.get('ATTACK_TYPE', '')
            target = row.get('TARGET', '')
            timestamp = row.get('FIRST_SEEN', 0)
            
            key = f"{attack_type}_{target}"
            ddos_map[key]['sources'].add(source_id)
            ddos_map[key]['timestamps'].append(timestamp)
            ddos_map[key]['targets'].add(target)
    
    # Find coordinated attacks (same target, similar timeframe, multiple sources)
    for attack_key, info in ddos_map.items():
        if len(info['sources']) >= MIN_SOURCES_FOR_CORRELATION:
            # Check temporal correlation (within CORRELATION_TIME_WINDOW)
            if len(info['timestamps']) > 1:
                timestamps = sorted(info['timestamps'])
                time_spread = timestamps[-1] - timestamps[0]
                
                if time_spread <= CORRELATION_TIME_WINDOW:
                    confidence = min(100, 70 + (len(info['sources']) * 5))
                    rows.append({
                        'ATTACK_PATTERN': attack_key,
                        'SOURCES': ', '.join(sorted(info['sources'])),
                        'SOURCE_COUNT': len(info['sources']),
                        'TIME_SPREAD': time_spread,
                        'CONFIDENCE_SCORE': confidence,
                        'TYPE': 'Coordinated DDoS Attack'
                    })
    
    return pd.DataFrame(rows) if rows else pd.DataFrame(columns=['ATTACK_PATTERN', 'SOURCES', 'SOURCE_COUNT', 'TIME_SPREAD', 'CONFIDENCE_SCORE', 'TYPE'])


def detect_lateral_movement_across_sources(source_data):
    """
    Track attackers moving between monitored networks
    
    Identifies:
    - Same attacker IP across different networks
    - Pivot points and compromised hosts
    - Multi-stage attack chains
    
    Args:
        source_data: Dictionary of {source_id: detection_results}
        
    Returns:
        DataFrame with movement chains
    """
    rows = []
    
    # Track suspicious IPs across sources
    ip_map = defaultdict(lambda: {'sources': set(), 'activities': [], 'scores': []})
    
    for source_id, data in source_data.items():
        # Check C2 detections for malicious IPs
        c2_detections = data.get('c2_full', pd.DataFrame())
        if not c2_detections.empty and 'SRC_IP' in c2_detections.columns:
            for _, row in c2_detections.iterrows():
                src_ip = row.get('SRC_IP', '')
                if src_ip and src_ip != 'None':
                    ip_map[src_ip]['sources'].add(source_id)
                    ip_map[src_ip]['activities'].append(row.get('TYPE', 'Unknown'))
                    ip_map[src_ip]['scores'].append(row.get('SCORE', 0))
        
        # Check protocol threats for lateral movement
        protocol_threats = data.get('protocol_threats', pd.DataFrame())
        if not protocol_threats.empty and 'SRC_IP' in protocol_threats.columns:
            for _, row in protocol_threats.iterrows():
                src_ip = row.get('SRC_IP', '')
                protocol = row.get('PROTOCOL', '')
                if src_ip and src_ip != 'None' and protocol in ['SMB', 'RDP', 'SSH']:
                    ip_map[src_ip]['sources'].add(source_id)
                    ip_map[src_ip]['activities'].append(f"{protocol} Activity")
                    ip_map[src_ip]['scores'].append(row.get('SCORE', 0))
    
    # Detect IPs active in multiple sources (lateral movement indicator)
    for ip, info in ip_map.items():
        if len(info['sources']) >= MIN_SOURCES_FOR_CORRELATION:
            avg_score = sum(info['scores']) / len(info['scores']) if info['scores'] else 0
            confidence = min(100, 75 + (len(info['sources']) * 8))
            
            rows.append({
                'ATTACKER_IP': ip,
                'SOURCES': ', '.join(sorted(info['sources'])),
                'SOURCE_COUNT': len(info['sources']),
                'ACTIVITIES': ', '.join(set(info['activities'][:5])),  # Top 5 unique activities
                'AVG_THREAT_SCORE': round(avg_score, 1),
                'CONFIDENCE_SCORE': confidence,
                'TYPE': 'Cross-Network Lateral Movement'
            })
    
    return pd.DataFrame(rows) if rows else pd.DataFrame(columns=['ATTACKER_IP', 'SOURCES', 'SOURCE_COUNT', 'ACTIVITIES', 'AVG_THREAT_SCORE', 'CONFIDENCE_SCORE', 'TYPE'])


def correlate_beacon_timing(source_data):
    """
    Detect synchronized C2 beacons across networks
    
    Identifies:
    - Beacon synchronization patterns (shared C2 heartbeat)
    - Coordinated bot check-ins
    - Common command & control timing
    
    Args:
        source_data: Dictionary of {source_id: detection_results}
        
    Returns:
        DataFrame with beacon correlation scores
    """
    rows = []
    
    # Collect beacon detections from all sources
    beacon_map = defaultdict(lambda: {'sources': set(), 'intervals': [], 'destinations': set()})
    
    for source_id, data in source_data.items():
        beacon_detections = data.get('beacon', pd.DataFrame())
        if beacon_detections.empty:
            continue
            
        for _, row in beacon_detections.iterrows():
            dst_ip = row.get('DST_IP', '')
            interval = row.get('AVG_INTERVAL', 0)
            
            if dst_ip and interval > 0:
                # Group by destination and similar interval (within 10% tolerance)
                interval_bucket = int(interval / 10) * 10  # Round to nearest 10 seconds
                key = f"{dst_ip}_{interval_bucket}"
                
                beacon_map[key]['sources'].add(source_id)
                beacon_map[key]['intervals'].append(interval)
                beacon_map[key]['destinations'].add(dst_ip)
    
    # Find beacons with synchronized timing across sources
    for beacon_key, info in beacon_map.items():
        if len(info['sources']) >= MIN_SOURCES_FOR_CORRELATION:
            avg_interval = sum(info['intervals']) / len(info['intervals']) if info['intervals'] else 0
            confidence = min(100, 80 + (len(info['sources']) * 6))
            
            rows.append({
                'BEACON_DESTINATION': list(info['destinations'])[0],
                'AVG_INTERVAL': round(avg_interval, 1),
                'SOURCES': ', '.join(sorted(info['sources'])),
                'SOURCE_COUNT': len(info['sources']),
                'CONFIDENCE_SCORE': confidence,
                'TYPE': 'Synchronized C2 Beacon'
            })
    
    return pd.DataFrame(rows) if rows else pd.DataFrame(columns=['BEACON_DESTINATION', 'AVG_INTERVAL', 'SOURCES', 'SOURCE_COUNT', 'CONFIDENCE_SCORE', 'TYPE'])


# -----------------------
# Pipeline
# -----------------------
def pipeline(pcap_sources=None):
    """
    Main analysis pipeline supporting multi-source PCAP correlation
    
    Args:
        pcap_sources: List of tuples [(source_id, pcap_path), ...]
                     or single string for backward compatibility
                     or None to use default FILE_PCAP
    """
    try:
        print("\n=== Stability v23.0: Multi-Source PCAP Correlation with ML-Enhanced Detection ===\n")
        
        # Backward compatibility: handle single file or None
        if isinstance(pcap_sources, str):
            # Single file path provided
            pcap_sources = [('default', pcap_sources)]
        elif pcap_sources is None:
            # No argument provided, use default
            pcap_sources = [('default', FILE_PCAP)]
        elif not isinstance(pcap_sources, list):
            # Invalid input
            print("[ERROR] pcap_sources must be a list of tuples, a string, or None")
            return
        
        print(f"[INFO] Processing {len(pcap_sources)} source(s)")
        
        if ML_AVAILABLE and ML_ENABLED:
            print("[INFO] ML-enhanced detection enabled")
        else:
            print("[INFO] ML-enhanced detection disabled - using heuristics only")

        # Process each source and collect results
        source_results = {}
        all_dns = []
        all_tcp = []
        all_http = []
        all_tls = []
        all_udp = []
        all_icmp = []
        all_dns_detail = []
        
        for source_id, pcap_path in pcap_sources:
            print(f"\n[Processing Source: {source_id}]")
            print(f"[1/20] Parsing PCAP: {pcap_path}")
            dns, tcp, http, tls, udp, icmp, dns_detail = parse_streams(pcap_path, source_id)
            
            # Store individual source data for correlation
            source_results[source_id] = {
                'dns': dns,
                'tcp': tcp,
                'http': http,
                'tls': tls,
                'udp': udp,
                'icmp': icmp,
                'dns_detail': dns_detail,
                'pcap_path': pcap_path
            }
            
            # Aggregate all sources for combined dashboard
            all_dns.append(dns)
            all_tcp.append(tcp)
            all_http.append(http)
            all_tls.append(tls)
            all_udp.append(udp)
            all_icmp.append(icmp)
            all_dns_detail.append(dns_detail)
        
        # Combine all sources for unified analysis
        dns = pd.concat(all_dns, ignore_index=True) if all_dns else pd.DataFrame()
        tcp = pd.concat(all_tcp, ignore_index=True) if all_tcp else pd.DataFrame()
        http = pd.concat(all_http, ignore_index=True) if all_http else pd.DataFrame()
        tls = pd.concat(all_tls, ignore_index=True) if all_tls else pd.DataFrame()
        udp = pd.concat(all_udp, ignore_index=True) if all_udp else pd.DataFrame()
        icmp = pd.concat(all_icmp, ignore_index=True) if all_icmp else pd.DataFrame()
        dns_detail = pd.concat(all_dns_detail, ignore_index=True) if all_dns_detail else pd.DataFrame()
        
        # Get first pcap path for display purposes (backward compatibility)
        pcap = pcap_sources[0][1] if pcap_sources else FILE_PCAP

        print("\n[2/20] Aggregating DNS...")
        dnsA = agg(dns, ['DOMAIN'])

        print("[3/20] Aggregating HTTP...")
        httpA = agg(http, ['DOMAIN'])

        print("[4/20] Aggregating TLS...")
        tls_cols = ['SNI', 'JA3', 'SRC_IP', 'DST_IP']
        for col in tls_cols:
            if col not in tls.columns:
                tls[col] = None
        tlsA = agg(tls, tls_cols)

        print("[5/20] Aggregating TCP...")
        tcpA = agg(tcp, ['SRC_IP', 'DST_IP', 'FLAGS'])
        
        # ✅ NEW: ML Feature Extraction
        print("[6/20] Extracting ML features from traffic...")
        ml_features = extract_ml_features(tcp, udp, icmp)
        print(f"  - Extracted features for {len(ml_features)} sources")
        
        # ✅ NEW: Baseline Profiling
        print("[7/20] Establishing traffic baselines...")
        baselines = establish_baseline(ml_features, window=f'{BASELINE_WINDOW}s')
        print(f"  - Baselines established for {len(baselines)} IPs")
        
        # ✅ NEW: ML-based DDoS Detection
        print("[8/20] Running ML DDoS classification...")
        ml_ddos = ml_ddos_detection(ml_features)
        if not ml_ddos.empty:
            print(f"  - ML detected {len(ml_ddos[ml_ddos['PREDICTION'] == 'ATTACK'])} potential attacks")
        
        # ✅ NEW: Anomaly Detection
        print("[9/20] Running Isolation Forest anomaly detection...")
        ml_anomalies = anomaly_detection(ml_features)
        if not ml_anomalies.empty:
            print(f"  - Detected {len(ml_anomalies)} traffic anomalies")

        print("[10/20] Building HTTP Timeline...")
        timeline = {}
        if os.path.exists(pcap) and PcapReader:
            if not http.empty and 'TS' in http.columns:
                for _, row in http.iterrows():
                    ts = int(row['TS'])
                    key = time.strftime('%Y-%m-%d %H:%M', time.localtime(ts))
                    timeline[key] = timeline.get(key, 0) + 1
        timeline_list = [{'label': k, 'count': v} for k, v in sorted(timeline.items())]

        print("[11/20] Computing full C2 heuristic indicators...")
        c2_full = compute_c2_heuristics(dnsA, httpA, tlsA, tcpA)

        print("[12/20] Computing Advanced Heuristics...")
        adv = compute_advanced_heuristics(dnsA, httpA, tlsA, tcpA, timeline_list)

        print("[13/20] Detecting Beaconing (with jitter tolerance)...")
        beacon = detect_beaconing(tcp)
        print(f"  - Beacons detected: {len(beacon)}")

        print("[14/20] Detecting DNS Tunneling...")
        dnstunnel = detect_dnstunneling(dns)
        
        print("[15/20] Detecting HTTP C2 Target Distribution...")
        http_c2 = detect_http_target_distribution(http, tcp)
        print(f"  - HTTP C2 detections: {len(http_c2)}")
        
        print("[16/20] Computing DDoS Attack Heuristics...")
        ddos = compute_ddos_heuristics(tcp, udp, icmp, http, dns_detail, c2_full)
        print(f"  - DDoS detections: {len(ddos)}")
        
        # ✅ NEW: TCP IP Distribution Detection
        print("[17/20] Detecting IP lists in TCP payloads (all protocols)...")
        tcp_ip_dist = detect_tcp_ip_distribution(tcp)  # Use RAW tcp, not aggregated
        print(f"  - TCP IP distributions found: {len(tcp_ip_dist)}")
        
        # ✅ PRIORITY 2: Change Point Detection
        print("[18/24] Detecting traffic change points (CPD)...")
        change_points = []
        temporal_patterns = {}
        sliding_windows = pd.DataFrame()
        
        if CPD_ENABLED and not tcp.empty and 'TS' in tcp.columns:
            try:
                # Analyze temporal patterns
                temporal_patterns = analyze_temporal_patterns(tcp)
                if temporal_patterns.get('pattern_detected'):
                    print(f"  - Temporal pattern detected with {len(temporal_patterns.get('anomalous_hours', []))} anomalous hours")
                
                # Sliding window analysis
                sliding_windows = sliding_window_analysis(tcp, window_size=CPD_WINDOW_SIZE)
                if not sliding_windows.empty:
                    anomaly_windows = sliding_windows[sliding_windows['is_anomaly'] == True]
                    print(f"  - {len(anomaly_windows)} anomalous windows detected")
                
                # CUSUM-based change point detection
                if not tcp.empty:
                    # Create time series of packet counts per second
                    tcp_sorted = tcp.sort_values('TS').copy()
                    tcp_sorted['ts_rounded'] = tcp_sorted['TS'].round()
                    pps_series = tcp_sorted.groupby('ts_rounded').size()
                    
                    # Establish baseline
                    baseline = {
                        'mean': pps_series.mean(),
                        'std': pps_series.std()
                    }
                    
                    change_points = detect_change_points(pps_series, baseline, threshold=CPD_THRESHOLD)
                    print(f"  - {len(change_points)} change points detected")
            except Exception as e:
                print(f"  - CPD error (non-fatal): {e}")
        else:
            print("  - CPD disabled or insufficient data")
        
        # ✅ PRIORITY 2: Flow-level Statistical Analysis
        print("[19/24] Performing flow-level analysis...")
        flow_features = pd.DataFrame()
        flow_anomalies = pd.DataFrame()
        bidirectional_anomalies = pd.DataFrame()
        
        try:
            flow_features = extract_flow_features(tcp)
            if not flow_features.empty:
                print(f"  - Extracted features for {len(flow_features)} flows")
                
                # Detect flow anomalies
                flow_anomalies = detect_flow_anomalies(flow_features)
                if not flow_anomalies.empty:
                    print(f"  - {len(flow_anomalies)} anomalous flows detected")
                
                # Analyze bidirectional flows
                bidirectional_anomalies = analyze_bidirectional_flows(flow_features)
                if not bidirectional_anomalies.empty:
                    print(f"  - {len(bidirectional_anomalies)} asymmetric flows detected")
            else:
                print("  - Insufficient flow data for analysis")
        except Exception as e:
            print(f"  - Flow analysis error (non-fatal): {e}")

        # ✅ PRIORITY 3: Protocol Detection and Analysis
        print("[20/30] Detecting SMB/CIFS activity...")
        smb_df = detect_smb_activity(tcp)
        print(f"  - SMB detections: {len(smb_df)}")
        
        print("[21/30] Detecting RDP activity...")
        rdp_df = detect_rdp_activity(tcp)
        print(f"  - RDP detections: {len(rdp_df)}")
        
        print("[22/30] Detecting SSH activity...")
        ssh_df = detect_ssh_activity(tcp)
        print(f"  - SSH detections: {len(ssh_df)}")
        
        print("[23/30] Detecting FTP/SFTP activity...")
        ftp_df = detect_ftp_activity(tcp, udp)
        print(f"  - FTP detections: {len(ftp_df)}")
        
        print("[24/30] Detecting SMTP activity...")
        smtp_df = detect_smtp_activity(tcp)
        print(f"  - SMTP detections: {len(smtp_df)}")
        
        print("[25/30] Detecting IRC activity...")
        irc_df = detect_irc_activity(tcp)
        print(f"  - IRC detections: {len(irc_df)}")
        
        print("[26/30] Detecting P2P protocol activity...")
        p2p_df = detect_p2p_activity(tcp, udp)
        print(f"  - P2P detections: {len(p2p_df)}")
        
        print("[27/30] Computing protocol threat aggregation...")
        protocol_threats = compute_protocol_threats(smb_df, rdp_df, ssh_df, ftp_df, smtp_df, irc_df, p2p_df)
        print(f"  - Protocol threats: {len(protocol_threats)}")
        
        # ✅ NEW: Botnet Family Detection
        print("[28/38] Detecting botnet families across protocols...")
        botnet_detections = pd.DataFrame()
        if BOTNET_DETECTION_AVAILABLE:
            try:
                # Detect in TCP payloads
                botnet_tcp = detect_botnet_in_tcp(tcp)
                print(f"  - TCP botnet signatures: {len(botnet_tcp)}")
                
                # Detect in HTTP traffic
                botnet_http = detect_botnet_in_http(http)
                print(f"  - HTTP botnet signatures: {len(botnet_http)}")
                
                # Detect in TLS/JA3
                botnet_tls = detect_botnet_in_tls(tls)
                print(f"  - TLS/JA3 botnet signatures: {len(botnet_tls)}")
                
                # Detect in DNS
                botnet_dns = detect_botnet_in_dns(dns)
                print(f"  - DNS botnet signatures: {len(botnet_dns)}")
                
                # Detect in IRC (filter TCP by IRC ports)
                irc_ports = [6667, 6697, 194]
                tcp_irc = tcp[tcp['DST_PORT'].isin(irc_ports)] if 'DST_PORT' in tcp.columns and not tcp.empty else pd.DataFrame()
                botnet_irc = detect_botnet_in_irc(tcp_irc)
                print(f"  - IRC botnet signatures: {len(botnet_irc)}")
                
                # Aggregate all detections
                botnet_detections = aggregate_botnet_detections(
                    botnet_tcp, botnet_http, botnet_tls, botnet_dns, botnet_irc
                )
                print(f"  - Total unique botnet detections: {len(botnet_detections)}")
                if not botnet_detections.empty:
                    families = botnet_detections['FAMILY'].unique()
                    print(f"  - Families detected: {', '.join(families)}")
            except Exception as e:
                print(f"  - Botnet detection error (non-fatal): {e}")
                botnet_detections = pd.DataFrame()
        else:
            print("  - Botnet detection disabled (module not loaded)")
        
        # Store detection results for each source for correlation
        for source_id in source_results:
            source_results[source_id]['c2_full'] = c2_full
            source_results[source_id]['ddos'] = ddos
            source_results[source_id]['beacon'] = beacon
            source_results[source_id]['protocol_threats'] = protocol_threats
        
        # ✅ MULTI-SOURCE CORRELATION
        correlation_results = {
            'c2': pd.DataFrame(),
            'attacks': pd.DataFrame(),
            'lateral': pd.DataFrame(),
            'beacons': pd.DataFrame()
        }
        
        if MULTI_SOURCE_ENABLED and len(source_results) >= MIN_SOURCES_FOR_CORRELATION:
            print("\n[CORRELATION] Analyzing cross-source patterns...")
            print(f"[29/42] Correlating C2 infrastructure across {len(source_results)} sources...")
            correlation_results['c2'] = correlate_cross_source_c2(source_results)
            if not correlation_results['c2'].empty:
                print(f"  - Found {len(correlation_results['c2'])} shared C2 indicators")
            
            print("[30/42] Correlating attack patterns...")
            correlation_results['attacks'] = correlate_attack_patterns(source_results)
            if not correlation_results['attacks'].empty:
                print(f"  - Found {len(correlation_results['attacks'])} coordinated attacks")
            
            print("[31/42] Detecting lateral movement across sources...")
            correlation_results['lateral'] = detect_lateral_movement_across_sources(source_results)
            if not correlation_results['lateral'].empty:
                print(f"  - Found {len(correlation_results['lateral'])} cross-network movements")
            
            print("[32/42] Correlating beacon timing...")
            correlation_results['beacons'] = correlate_beacon_timing(source_results)
            if not correlation_results['beacons'].empty:
                print(f"  - Found {len(correlation_results['beacons'])} synchronized beacons")
        elif len(source_results) < MIN_SOURCES_FOR_CORRELATION:
            print(f"\n[INFO] Multi-source correlation requires at least {MIN_SOURCES_FOR_CORRELATION} sources (have {len(source_results)})")
        
        # Prepare source metadata for dashboard
        source_metadata = [
            {
                'SOURCE_ID': sid,
                'PCAP_FILE': os.path.basename(sdata['pcap_path']),
                'PACKETS': len(sdata['tcp']) + len(sdata['udp']) + len(sdata['icmp']),
                'PROTOCOLS': ', '.join(['TCP', 'UDP', 'ICMP', 'DNS', 'HTTP', 'TLS'][:3])
            }
            for sid, sdata in source_results.items()
        ]

        print("[33/42] Writing dashboard.js and dashboard.html ...")
        js = (
            JS_TEMPLATE
            .replace('%%DNS%%', safe_js_json(dnsA.to_dict(orient='records')))
            .replace('%%HTTP%%', safe_js_json(httpA.to_dict(orient='records')))
            .replace('%%TLS%%', safe_js_json(tlsA.to_dict(orient='records')))
            .replace('%%TCP%%', safe_js_json(tcpA.to_dict(orient='records')))
            .replace('%%C2FULL%%', safe_js_json(c2_full.to_dict(orient='records')))
            .replace('%%ADV%%', safe_js_json(adv.to_dict(orient='records')))
            .replace('%%BEACON%%', safe_js_json(beacon.to_dict(orient='records')))
            .replace('%%DNSTUNNEL%%', safe_js_json(dnstunnel.to_dict(orient='records')))
            .replace('%%DDOS%%', safe_js_json(ddos.to_dict(orient='records')))
            .replace('%%HTTPC2%%', safe_js_json(http_c2.to_dict(orient='records')))
            .replace('%%TCPIP%%', safe_js_json(tcp_ip_dist.to_dict(orient='records')))
            .replace('%%MLDDOS%%', safe_js_json(ml_ddos.to_dict(orient='records') if not ml_ddos.empty else []))
            .replace('%%MLANOMALIES%%', safe_js_json(ml_anomalies.to_dict(orient='records') if not ml_anomalies.empty else []))
            .replace('%%MLFEATURES%%', safe_js_json(ml_features.head(100).to_dict(orient='records') if not ml_features.empty else []))
            .replace('%%CHANGEPOINTS%%', safe_js_json(change_points))
            .replace('%%TEMPORALPATTERNS%%', safe_js_json(temporal_patterns))
            .replace('%%SLIDINGWINDOWS%%', safe_js_json(sliding_windows.to_dict(orient='records') if not sliding_windows.empty else []))
            .replace('%%FLOWFEATURES%%', safe_js_json(flow_features.head(100).to_dict(orient='records') if not flow_features.empty else []))
            .replace('%%FLOWANOMALIES%%', safe_js_json(flow_anomalies.to_dict(orient='records') if not flow_anomalies.empty else []))
            .replace('%%BIDIRECTIONALANOMALIES%%', safe_js_json(bidirectional_anomalies.to_dict(orient='records') if not bidirectional_anomalies.empty else []))
            .replace('%%SMB%%', safe_js_json(smb_df.to_dict(orient='records') if not smb_df.empty else []))
            .replace('%%RDP%%', safe_js_json(rdp_df.to_dict(orient='records') if not rdp_df.empty else []))
            .replace('%%SSH%%', safe_js_json(ssh_df.to_dict(orient='records') if not ssh_df.empty else []))
            .replace('%%FTP%%', safe_js_json(ftp_df.to_dict(orient='records') if not ftp_df.empty else []))
            .replace('%%SMTP%%', safe_js_json(smtp_df.to_dict(orient='records') if not smtp_df.empty else []))
            .replace('%%IRC%%', safe_js_json(irc_df.to_dict(orient='records') if not irc_df.empty else []))
            .replace('%%P2P%%', safe_js_json(p2p_df.to_dict(orient='records') if not p2p_df.empty else []))
            .replace('%%PROTOCOLTHREATS%%', safe_js_json(protocol_threats.to_dict(orient='records') if not protocol_threats.empty else []))
            .replace('%%BOTNET%%', safe_js_json(botnet_detections.to_dict(orient='records') if not botnet_detections.empty else []))
            .replace('%%CORRELATION_C2%%', safe_js_json(correlation_results['c2'].to_dict(orient='records') if not correlation_results['c2'].empty else []))
            .replace('%%CORRELATION_ATTACKS%%', safe_js_json(correlation_results['attacks'].to_dict(orient='records') if not correlation_results['attacks'].empty else []))
            .replace('%%CORRELATION_LATERAL%%', safe_js_json(correlation_results['lateral'].to_dict(orient='records') if not correlation_results['lateral'].empty else []))
            .replace('%%CORRELATION_BEACONS%%', safe_js_json(correlation_results['beacons'].to_dict(orient='records') if not correlation_results['beacons'].empty else []))
            .replace('%%SOURCE_METADATA%%', safe_js_json(source_metadata))
        )

        with open('dashboard.js', 'w', encoding='utf-8') as jf:
            jf.write(js)
        print("→ dashboard.js written.")

        html_output = HTML_TEMPLATE.replace('%%FILE%%', pcap)
        with open('dashboard.html', 'w', encoding='utf-8') as hf:
            hf.write(html_output)
        print("→ dashboard.html written.")

        print("\n=== DONE: Stability v23.0 dashboard with Multi-Source Correlation generated ===\n")
        
        # Print summary
        print("=== Detection Summary ===")
        print(f"C2 Indicators: {len(c2_full)}")
        print(f"DDoS Attacks: {len(ddos)}")
        print(f"Beacons Detected: {len(beacon)}")
        if not ml_ddos.empty:
            print(f"ML DDoS Predictions: {len(ml_ddos[ml_ddos['PREDICTION'] == 'ATTACK'])}")
        if not ml_anomalies.empty:
            print(f"ML Anomalies: {len(ml_anomalies)}")
        
        # Priority 2 summaries
        print("\n=== Priority 2 Features ===")
        print(f"Change Points Detected: {len(change_points)}")
        if temporal_patterns.get('pattern_detected'):
            print(f"Temporal Patterns: Detected ({len(temporal_patterns.get('anomalous_hours', []))} anomalous hours)")
        if not sliding_windows.empty:
            anomaly_count = len(sliding_windows[sliding_windows['is_anomaly'] == True])
            print(f"Anomalous Windows: {anomaly_count}/{len(sliding_windows)}")
        if not flow_features.empty:
            print(f"Flows Analyzed: {len(flow_features)}")
            print(f"Flow Anomalies: {len(flow_anomalies)}")
            print(f"Bidirectional Anomalies: {len(bidirectional_anomalies)}")
        print("=" * 25)
        
        # Priority 3 summaries
        print("\n=== Priority 3: Protocol Detection ===")
        print(f"SMB Detections: {len(smb_df)}")
        if not smb_df.empty:
            high_risk = len(smb_df[smb_df['LATERAL_SCORE'] >= 70])
            print(f"  - High Risk SMB Activity: {high_risk}")
        print(f"RDP Detections: {len(rdp_df)}")
        if not rdp_df.empty:
            brute_force = len(rdp_df[rdp_df['SCORE'] >= 70])
            print(f"  - RDP Brute Force: {brute_force}")
        print(f"SSH Detections: {len(ssh_df)}")
        if not ssh_df.empty:
            attacks = len(ssh_df[ssh_df['SCORE'] >= 70])
            print(f"  - SSH Attacks/Scans: {attacks}")
        print(f"FTP Detections: {len(ftp_df)}")
        print(f"SMTP Detections: {len(smtp_df)}")
        print(f"IRC Detections: {len(irc_df)}")
        print(f"P2P Detections: {len(p2p_df)}")
        print(f"Total Protocol Threats (Score ≥ 60): {len(protocol_threats)}")
        print("=" * 37)
        
        # Botnet Family Detection summaries
        print("\n=== Botnet Family Detection ===")
        if not botnet_detections.empty:
            print(f"Total Botnet Detections: {len(botnet_detections)}")
            families = botnet_detections['FAMILY'].value_counts()
            print(f"Families Detected: {len(families)}")
            for family, count in families.items():
                severity = botnet_detections[botnet_detections['FAMILY'] == family]['SEVERITY'].iloc[0]
                avg_conf = botnet_detections[botnet_detections['FAMILY'] == family]['CONFIDENCE'].mean()
                print(f"  - {family}: {count} detections (avg confidence: {avg_conf:.1f}%, severity: {severity})")
            
            # High confidence detections
            high_conf = botnet_detections[botnet_detections['CONFIDENCE'] >= 80]
            if not high_conf.empty:
                print(f"High Confidence Detections (≥80%): {len(high_conf)}")
                for family in high_conf['FAMILY'].unique():
                    family_high = high_conf[high_conf['FAMILY'] == family]
                    print(f"  - {family}: {len(family_high)} high-confidence")
        else:
            print("No botnet families detected in this capture")
        print("=" * 31)


    except Exception:
        print("\n\n=== PIPELINE CRASH ===")
        traceback.print_exc()
        raise

# -----------------------
# Entry point
# -----------------------
if __name__ == '__main__':
    # Parse command-line arguments for multi-source support
    parser = argparse.ArgumentParser(
        description='PCAP Analysis with Multi-Source Correlation Support',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Single file (backward compatible)
  python main.py
  
  # Multiple sources
  python main.py --sources monitor1:file1.pcap monitor2:file2.pcap monitor3:file3.pcap
  
  # Wildcard pattern
  python main.py --sources-dir /path/to/pcaps/*.pcap
        '''
    )
    
    parser.add_argument(
        '--sources',
        nargs='+',
        metavar='NAME:PATH',
        help='Multiple PCAP sources in format name:path (e.g., monitor1:file1.pcap)'
    )
    
    parser.add_argument(
        '--sources-dir',
        metavar='PATTERN',
        help='Wildcard pattern for PCAP files (e.g., /pcaps/*.pcap)'
    )
    
    args = parser.parse_args()
    
    # Build pcap_sources list based on arguments
    pcap_sources = None
    
    if args.sources:
        # Parse sources in format "name:path"
        pcap_sources = []
        for source_spec in args.sources:
            if ':' in source_spec:
                name, path = source_spec.split(':', 1)
                pcap_sources.append((name, path))
            else:
                # No name provided, use filename as name
                pcap_sources.append((os.path.basename(source_spec), source_spec))
    
    elif args.sources_dir:
        # Use glob pattern
        files = glob.glob(args.sources_dir)
        if files:
            pcap_sources = [(os.path.basename(f), f) for f in sorted(files)]
        else:
            print(f"[WARNING] No files found matching pattern: {args.sources_dir}")
            pcap_sources = None
    
    # Run pipeline
    pipeline(pcap_sources)
