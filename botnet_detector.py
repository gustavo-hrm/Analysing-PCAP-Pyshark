#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Botnet Family Detection Module
===============================

This module provides detection functions for identifying botnet families in network traffic.
It scans payloads, ports, JA3 fingerprints, HTTP endpoints, and DNS patterns against
known botnet signatures.

"""

import re
import pandas as pd
from botnet_signatures import (
    BOTNET_SIGNATURES,
    DETECTION_WEIGHTS,
    MIN_DETECTION_SCORE,
    MULTI_MATCH_BONUS,
    get_all_ja3_fingerprints,
    get_all_ports,
)


# -----------------------
# Helper Functions
# -----------------------

def _truncate_evidence(evidence_str, max_length=200):
    """
    Truncate evidence string to maximum length for dashboard readability
    
    Args:
        evidence_str: Evidence string to truncate
        max_length: Maximum length (default: 200)
        
    Returns:
        Truncated string with ellipsis if needed
    """
    if len(evidence_str) <= max_length:
        return evidence_str
    return evidence_str[:max_length-3] + "..."


# -----------------------
# Core Detection Functions
# -----------------------

def detect_botnet_in_payload(payload, src_ip, dst_ip, dst_port, ja3=None):
    """
    Scan a single payload for botnet signatures
    
    Args:
        payload: Raw payload bytes or string
        src_ip: Source IP address
        dst_ip: Destination IP address
        dst_port: Destination port
        ja3: JA3 fingerprint (optional)
        
    Returns:
        list: List of detection dictionaries with family, confidence, evidence
    """
    detections = []
    
    if not payload:
        return detections
    
    # Convert payload to bytes if string
    if isinstance(payload, str):
        payload_bytes = payload.encode('latin-1', errors='ignore')
    else:
        payload_bytes = payload
    
    # Convert to lowercase once for performance
    payload_str = payload_bytes.decode('latin-1', errors='ignore').lower()
    payload_bytes_lower = payload_bytes.lower()
    
    # Check each botnet family
    for family, sig in BOTNET_SIGNATURES.items():
        score = 0
        evidence = []
        matches = 0
        
        # Check JA3 fingerprint
        if ja3 and ja3 in sig.get("ja3_fingerprints", []):
            score += DETECTION_WEIGHTS["ja3_match"]
            evidence.append(f"JA3:{ja3}")
            matches += 1
        
        # Check destination port
        if dst_port and dst_port in sig.get("ports", []):
            score += DETECTION_WEIGHTS["port_match"]
            evidence.append(f"Port:{dst_port}")
            matches += 1
        
        # Check payload patterns (optimized)
        for pattern in sig.get("payload_patterns", []):
            if isinstance(pattern, bytes):
                if pattern.lower() in payload_bytes_lower:
                    score += DETECTION_WEIGHTS["payload_pattern"]
                    evidence.append(f"Payload:'{pattern.decode('latin-1', errors='ignore')}'")
                    matches += 1
                    break  # Only count once per family
        
        # Check HTTP endpoints in payload
        for endpoint in sig.get("http_endpoints", []):
            if endpoint.lower() in payload_str:
                score += DETECTION_WEIGHTS["http_endpoint"]
                evidence.append(f"HTTP:'{endpoint}'")
                matches += 1
                break
        
        # Check User-Agent patterns
        for ua in sig.get("http_user_agents", []):
            if ua.lower() in payload_str:
                score += DETECTION_WEIGHTS["user_agent"]
                evidence.append(f"UA:'{ua[:30]}'")
                matches += 1
                break
        
        # Check magic bytes
        for magic in sig.get("magic_bytes", []):
            if payload_bytes.startswith(magic):
                score += DETECTION_WEIGHTS["magic_bytes"]
                evidence.append(f"Magic:{magic.hex()}")
                matches += 1
                break
        
        # Apply base confidence and multi-match bonus
        if score > 0:
            base_confidence = sig.get("confidence_base", 70)
            if matches > 1:
                score += MULTI_MATCH_BONUS * (matches - 1)
            
            # Calculate final confidence (0-100)
            confidence = min(100, base_confidence + score - 50)
            
            # Only report if meets minimum threshold
            if confidence >= MIN_DETECTION_SCORE:
                detections.append({
                    "FAMILY": family,
                    "CATEGORY": sig.get("category", "Unknown"),
                    "SEVERITY": sig.get("severity", "MEDIUM"),
                    "CONFIDENCE": confidence,
                    "SCORE": score,
                    "EVIDENCE": " | ".join(evidence),
                    "MATCHES": matches,
                    "SRC_IP": src_ip,
                    "DST_IP": dst_ip,
                    "DST_PORT": dst_port,
                    "JA3": ja3 or "",
                    "PAYLOAD_SAMPLE": payload_str[:200],  # First 200 chars
                })
    
    return detections


def detect_botnet_in_tcp(tcp_df):
    """
    Scan TCP flows for botnet signatures
    
    Args:
        tcp_df: DataFrame with TCP packets (must have SRC_IP, DST_IP, DST_PORT, PAYLOAD columns)
        
    Returns:
        DataFrame with botnet detections
    """
    detections = []
    
    if tcp_df.empty or 'PAYLOAD' not in tcp_df.columns:
        return pd.DataFrame(columns=[
            'FAMILY', 'CATEGORY', 'SEVERITY', 'CONFIDENCE', 'SCORE', 
            'EVIDENCE', 'MATCHES', 'SRC_IP', 'DST_IP', 'DST_PORT', 
            'JA3', 'PAYLOAD_SAMPLE', 'PROTOCOL'
        ])
    
    # Process each TCP packet
    for _, row in tcp_df.iterrows():
        payload = row.get('PAYLOAD', '')
        if not payload or len(payload) < 10:  # Skip very short payloads
            continue
        
        src_ip = row.get('SRC_IP', '')
        dst_ip = row.get('DST_IP', '')
        dst_port = row.get('DST_PORT', 0)
        
        results = detect_botnet_in_payload(payload, src_ip, dst_ip, dst_port)
        for det in results:
            det['PROTOCOL'] = 'TCP'
            detections.append(det)
    
    return pd.DataFrame(detections) if detections else pd.DataFrame(columns=[
        'FAMILY', 'CATEGORY', 'SEVERITY', 'CONFIDENCE', 'SCORE', 
        'EVIDENCE', 'MATCHES', 'SRC_IP', 'DST_IP', 'DST_PORT', 
        'JA3', 'PAYLOAD_SAMPLE', 'PROTOCOL'
    ])


def detect_botnet_in_http(http_df):
    """
    Scan HTTP traffic for botnet signatures
    
    Args:
        http_df: DataFrame with HTTP requests (must have DOMAIN, REQUEST, PAYLOAD columns)
        
    Returns:
        DataFrame with botnet detections
    """
    detections = []
    
    if http_df.empty or 'PAYLOAD' not in http_df.columns:
        return pd.DataFrame(columns=[
            'FAMILY', 'CATEGORY', 'SEVERITY', 'CONFIDENCE', 'SCORE', 
            'EVIDENCE', 'MATCHES', 'SRC_IP', 'DST_IP', 'DST_PORT', 
            'JA3', 'PAYLOAD_SAMPLE', 'PROTOCOL'
        ])
    
    # Process each HTTP request
    for _, row in http_df.iterrows():
        payload = row.get('PAYLOAD', '')
        if not payload or len(payload) < 10:
            continue
        
        src_ip = row.get('SRC_IP', '')
        dst_ip = row.get('DST_IP', '')
        domain = row.get('DOMAIN', '')
        
        # Try to extract port from request or default to 80
        dst_port = 80
        if '443' in payload.lower() or 'https' in payload.lower():
            dst_port = 443
        
        results = detect_botnet_in_payload(payload, src_ip, dst_ip, dst_port)
        for det in results:
            det['PROTOCOL'] = 'HTTP'
            det['DOMAIN'] = domain
            detections.append(det)
    
    return pd.DataFrame(detections) if detections else pd.DataFrame(columns=[
        'FAMILY', 'CATEGORY', 'SEVERITY', 'CONFIDENCE', 'SCORE', 
        'EVIDENCE', 'MATCHES', 'SRC_IP', 'DST_IP', 'DST_PORT', 
        'JA3', 'PAYLOAD_SAMPLE', 'PROTOCOL', 'DOMAIN'
    ])


def detect_botnet_in_tls(tls_df):
    """
    Scan TLS traffic for botnet signatures using JA3 fingerprints
    
    Args:
        tls_df: DataFrame with TLS connections (must have SNI, JA3, SRC_IP, DST_IP columns)
        
    Returns:
        DataFrame with botnet detections
    """
    detections = []
    
    if tls_df.empty or 'JA3' not in tls_df.columns:
        return pd.DataFrame(columns=[
            'FAMILY', 'CATEGORY', 'SEVERITY', 'CONFIDENCE', 'SCORE', 
            'EVIDENCE', 'MATCHES', 'SRC_IP', 'DST_IP', 'DST_PORT', 
            'JA3', 'PAYLOAD_SAMPLE', 'PROTOCOL'
        ])
    
    # Build JA3 lookup map
    ja3_map = get_all_ja3_fingerprints()
    
    # Process each TLS connection
    for _, row in tls_df.iterrows():
        ja3 = row.get('JA3', '')
        if not ja3 or ja3 not in ja3_map:
            continue
        
        src_ip = row.get('SRC_IP', '')
        dst_ip = row.get('DST_IP', '')
        sni = row.get('SNI', '')
        
        # Get families matching this JA3
        families = ja3_map.get(ja3, [])
        
        for family in families:
            sig = BOTNET_SIGNATURES.get(family, {})
            base_confidence = sig.get("confidence_base", 70)
            
            # JA3 match gives high confidence
            confidence = min(100, base_confidence + DETECTION_WEIGHTS["ja3_match"])
            
            detections.append({
                'FAMILY': family,
                'CATEGORY': sig.get('category', 'Unknown'),
                'SEVERITY': sig.get('severity', 'MEDIUM'),
                'CONFIDENCE': confidence,
                'SCORE': DETECTION_WEIGHTS["ja3_match"],
                'EVIDENCE': f"JA3:{ja3} | SNI:{sni}",
                'MATCHES': 1,
                'SRC_IP': src_ip,
                'DST_IP': dst_ip,
                'DST_PORT': 443,  # TLS default
                'JA3': ja3,
                'PAYLOAD_SAMPLE': f"SNI: {sni}",
                'PROTOCOL': 'TLS',
            })
    
    return pd.DataFrame(detections) if detections else pd.DataFrame(columns=[
        'FAMILY', 'CATEGORY', 'SEVERITY', 'CONFIDENCE', 'SCORE', 
        'EVIDENCE', 'MATCHES', 'SRC_IP', 'DST_IP', 'DST_PORT', 
        'JA3', 'PAYLOAD_SAMPLE', 'PROTOCOL'
    ])


def detect_botnet_in_dns(dns_df):
    """
    Scan DNS queries for botnet C2 domains
    
    Args:
        dns_df: DataFrame with DNS queries (must have DOMAIN column)
        
    Returns:
        DataFrame with botnet detections
    """
    detections = []
    
    if dns_df.empty or 'DOMAIN' not in dns_df.columns:
        return pd.DataFrame(columns=[
            'FAMILY', 'CATEGORY', 'SEVERITY', 'CONFIDENCE', 'SCORE', 
            'EVIDENCE', 'MATCHES', 'SRC_IP', 'DST_IP', 'DST_PORT', 
            'JA3', 'PAYLOAD_SAMPLE', 'PROTOCOL'
        ])
    
    # Process each DNS query
    for _, row in dns_df.iterrows():
        domain = row.get('DOMAIN', '')
        if not domain or len(domain) < 5:
            continue
        
        # Check domain patterns for each botnet family
        for family, sig in BOTNET_SIGNATURES.items():
            dns_patterns = sig.get("dns_patterns", [])
            if not dns_patterns:
                continue
            
            # Check if domain matches any pattern
            for pattern in dns_patterns:
                try:
                    if re.search(pattern, domain, re.IGNORECASE):
                        base_confidence = sig.get("confidence_base", 70)
                        confidence = min(100, base_confidence + DETECTION_WEIGHTS["dns_pattern"])
                        
                        detections.append({
                            'FAMILY': family,
                            'CATEGORY': sig.get('category', 'Unknown'),
                            'SEVERITY': sig.get('severity', 'MEDIUM'),
                            'CONFIDENCE': confidence,
                            'SCORE': DETECTION_WEIGHTS["dns_pattern"],
                            'EVIDENCE': f"DNS:{domain}",
                            'MATCHES': 1,
                            'SRC_IP': '',
                            'DST_IP': '',
                            'DST_PORT': 53,
                            'JA3': '',
                            'PAYLOAD_SAMPLE': f"Domain: {domain}",
                            'PROTOCOL': 'DNS',
                        })
                        break  # Only match once per family
                except re.error:
                    continue
    
    return pd.DataFrame(detections) if detections else pd.DataFrame(columns=[
        'FAMILY', 'CATEGORY', 'SEVERITY', 'CONFIDENCE', 'SCORE', 
        'EVIDENCE', 'MATCHES', 'SRC_IP', 'DST_IP', 'DST_PORT', 
        'JA3', 'PAYLOAD_SAMPLE', 'PROTOCOL'
    ])


def detect_botnet_in_irc(tcp_df):
    """
    Scan IRC traffic for botnet C2 channels
    
    Args:
        tcp_df: DataFrame with TCP packets filtered to IRC ports
        
    Returns:
        DataFrame with botnet detections
    """
    detections = []
    
    if tcp_df.empty or 'PAYLOAD' not in tcp_df.columns:
        return pd.DataFrame(columns=[
            'FAMILY', 'CATEGORY', 'SEVERITY', 'CONFIDENCE', 'SCORE', 
            'EVIDENCE', 'MATCHES', 'SRC_IP', 'DST_IP', 'DST_PORT', 
            'JA3', 'PAYLOAD_SAMPLE', 'PROTOCOL'
        ])
    
    # IRC-specific pattern matching
    irc_bot_patterns = [
        b"JOIN #",
        b"PRIVMSG",
        b"NICK bot",
        b"bot_",
    ]
    
    # Process IRC traffic
    for _, row in tcp_df.iterrows():
        payload = row.get('PAYLOAD', '')
        if not payload or len(payload) < 10:
            continue
        
        payload_bytes = payload.encode('latin-1', errors='ignore') if isinstance(payload, str) else payload
        
        # Check for IRC bot patterns
        has_irc_pattern = any(pattern in payload_bytes for pattern in irc_bot_patterns)
        
        if has_irc_pattern:
            src_ip = row.get('SRC_IP', '')
            dst_ip = row.get('DST_IP', '')
            dst_port = row.get('DST_PORT', 0)
            
            # Generic botnet detection for IRC
            detections.append({
                'FAMILY': 'Unknown_Botnet',
                'CATEGORY': 'Botnet/IRC',
                'SEVERITY': 'MEDIUM',
                'CONFIDENCE': 65,
                'SCORE': 30,
                'EVIDENCE': f"IRC_Bot_Pattern | Port:{dst_port}",
                'MATCHES': 1,
                'SRC_IP': src_ip,
                'DST_IP': dst_ip,
                'DST_PORT': dst_port,
                'JA3': '',
                'PAYLOAD_SAMPLE': payload[:200],
                'PROTOCOL': 'IRC',
            })
    
    return pd.DataFrame(detections) if detections else pd.DataFrame(columns=[
        'FAMILY', 'CATEGORY', 'SEVERITY', 'CONFIDENCE', 'SCORE', 
        'EVIDENCE', 'MATCHES', 'SRC_IP', 'DST_IP', 'DST_PORT', 
        'JA3', 'PAYLOAD_SAMPLE', 'PROTOCOL'
    ])


def aggregate_botnet_detections(tcp_det, http_det, tls_det, dns_det, irc_det):
    """
    Aggregate and deduplicate botnet detections from all protocols
    
    Args:
        tcp_det: TCP detections DataFrame
        http_det: HTTP detections DataFrame
        tls_det: TLS detections DataFrame
        dns_det: DNS detections DataFrame
        irc_det: IRC detections DataFrame
        
    Returns:
        DataFrame with aggregated detections, sorted by confidence
    """
    # Combine all detections
    all_detections = pd.concat([tcp_det, http_det, tls_det, dns_det, irc_det], ignore_index=True)
    
    if all_detections.empty:
        return pd.DataFrame(columns=[
            'FAMILY', 'CATEGORY', 'SEVERITY', 'CONFIDENCE', 'SCORE', 
            'EVIDENCE', 'MATCHES', 'SRC_IP', 'DST_IP', 'DST_PORT', 
            'JA3', 'PAYLOAD_SAMPLE', 'PROTOCOL', 'COUNT'
        ])
    
    # Deduplicate and aggregate by family + source IP + dest IP
    grouped = all_detections.groupby(['FAMILY', 'SRC_IP', 'DST_IP'], as_index=False).agg({
        'CATEGORY': 'first',
        'SEVERITY': 'first',
        'CONFIDENCE': 'max',  # Highest confidence
        'SCORE': 'sum',       # Sum scores for multiple matches
        'EVIDENCE': lambda x: _truncate_evidence(' & '.join(set(x)), max_length=200),  # Combine and truncate evidence
        'MATCHES': 'sum',
        'DST_PORT': 'first',
        'JA3': 'first',
        'PAYLOAD_SAMPLE': 'first',
        'PROTOCOL': lambda x: ','.join(set(x)),  # List all protocols
    })
    
    # Add count column
    grouped['COUNT'] = all_detections.groupby(['FAMILY', 'SRC_IP', 'DST_IP']).size().values
    
    # Recalculate confidence with aggregated data
    grouped['CONFIDENCE'] = grouped.apply(
        lambda row: min(100, row['CONFIDENCE'] + (row['COUNT'] - 1) * 5),  # Bonus for multiple detections
        axis=1
    )
    
    # Sort by confidence (highest first)
    grouped = grouped.sort_values('CONFIDENCE', ascending=False)
    
    return grouped


if __name__ == "__main__":
    # Test/debug
    print("=== Botnet Detection Module ===")
    print("Available detection functions:")
    print("  - detect_botnet_in_tcp(tcp_df)")
    print("  - detect_botnet_in_http(http_df)")
    print("  - detect_botnet_in_tls(tls_df)")
    print("  - detect_botnet_in_dns(dns_df)")
    print("  - detect_botnet_in_irc(tcp_df)")
    print("  - aggregate_botnet_detections(...)")
    
    # Test payload detection
    test_payload = "GET /gate.php HTTP/1.1\r\nHost: evil-c2.com\r\n"
    test_results = detect_botnet_in_payload(test_payload, "192.168.1.100", "10.0.0.1", 80)
    print(f"\nTest detection results: {len(test_results)} matches")
    for det in test_results:
        print(f"  - {det['FAMILY']}: {det['CONFIDENCE']}% ({det['EVIDENCE']})")
