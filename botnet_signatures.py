#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Botnet Family Signature Database
=================================

This module contains signatures for detecting various botnet families and malware C2 communications.
Each signature includes multiple detection criteria such as ports, JA3 fingerprints, payload patterns,
HTTP endpoints, and magic bytes.

To add a new botnet family:
1. Add a new entry to BOTNET_SIGNATURES dictionary
2. Include all known indicators (ports, JA3, payload_patterns, etc.)
3. Set appropriate confidence scoring rules
4. Document known variants and IOCs

"""

# -----------------------
# Botnet Signature Database
# -----------------------

BOTNET_SIGNATURES = {
    # Emotet - Banking trojan and malware loader
    "Emotet": {
        "description": "Banking trojan and malware loader (2014-2021, resurfaced 2022)",
        "family": "Emotet",
        "category": "Trojan/Loader",
        "ports": [80, 443, 8080, 7080, 8443],  # Common C2 ports
        "ja3_fingerprints": [
            "3ca48e8aa725c3091f31146e55f883a1",  # Known Emotet JA3
            "e7d705a3286e19ea42f587b344ee6865",  # Variant
        ],
        "payload_patterns": [
            b"emotet",  # String in payload
            b"EmoCheck",  # Detection tool name sometimes in samples
        ],
        "http_endpoints": [
            "/msa/",
            "/api/v1/",
            "/wp-admin/",
            "/wp-content/",
        ],
        "http_user_agents": [
            "Mozilla/5.0 (Windows NT 6.1; Trident/7.0; rv:11.0)",
        ],
        "magic_bytes": [
            b"\x4d\x5a",  # MZ header (PE file)
        ],
        "confidence_base": 85,
        "severity": "HIGH",
    },
    
    # TrickBot - Banking trojan and post-exploitation toolkit
    "TrickBot": {
        "description": "Banking trojan with lateral movement and credential theft (2016-present)",
        "family": "TrickBot",
        "category": "Trojan/Banker",
        "ports": [443, 447, 449, 451],  # Common TrickBot ports
        "ja3_fingerprints": [
            "7d56f4c1d5b56a54a27f35e8afc6d2ba",  # Known TrickBot JA3
            "51c64c77e60f3980eea90869b68c58a8",  # Variant
        ],
        "payload_patterns": [
            b"<mcconf>",  # TrickBot config marker
            b"<autorun>",
            b"<moduleconfig>",
        ],
        "http_endpoints": [
            "/api/v2/",
            "/images/",
            "/content/",
        ],
        "dns_patterns": [
            r".*\.top$",  # Common TLD
            r".*\.pw$",
        ],
        "confidence_base": 85,
        "severity": "HIGH",
    },
    
    # Mirai - IoT botnet
    "Mirai": {
        "description": "IoT botnet for DDoS attacks (2016-present)",
        "family": "Mirai",
        "category": "Botnet/DDoS",
        "ports": [23, 2323, 48101, 7547, 5555, 8080],  # Telnet and common IoT ports
        "ja3_fingerprints": [],  # Mirai typically doesn't use TLS
        "payload_patterns": [
            b"busybox",  # Common in Mirai payloads
            b"ECCHI",  # Mirai variant
            b"/bin/sh",
            b"tftp",
            b"killer",  # Mirai process killer
        ],
        "http_endpoints": [
            "/bins/",
            "/arm",
            "/mips",
            "/x86",
        ],
        "telnet_patterns": [
            b"root",
            b"admin",
            b"shell",
        ],
        "confidence_base": 80,
        "severity": "CRITICAL",
    },
    
    # Cobalt Strike - Post-exploitation framework
    "Cobalt Strike": {
        "description": "Commercial adversary simulation software (often abused by threat actors)",
        "family": "Cobalt Strike",
        "category": "C2/Post-Exploitation",
        "ports": [80, 443, 8080, 50050],  # Default beacon ports
        "ja3_fingerprints": [
            "72a589da586844d7f0818ce684948eea",  # Known Cobalt Strike JA3
            "a0e9f5d64349fb13191bc781f81f42e1",  # Variant
        ],
        "payload_patterns": [
            b"beacon",  # Beacon payload
            b"upload",
            b"download",
            b"powershell",
        ],
        "http_endpoints": [
            "/jquery",
            "/activity",
            "/login",
            "/__utm.gif",
            "/pixel.gif",
            "/ga.js",
            "/submit.php",
        ],
        "http_user_agents": [
            "Mozilla/5.0 (compatible; MSIE",
        ],
        "beacon_intervals": [60, 120, 300],  # Common beacon intervals in seconds
        "confidence_base": 90,
        "severity": "CRITICAL",
    },
    
    # Sliver - Open-source C2 framework
    "Sliver": {
        "description": "Open-source C2 framework (2019-present)",
        "family": "Sliver",
        "category": "C2/Post-Exploitation",
        "ports": [443, 80, 8443, 31337],  # Common Sliver ports
        "ja3_fingerprints": [
            "3e1f1f1f4ec4cc1d83bb7eaf8cf68e39",  # Known Sliver JA3
        ],
        "payload_patterns": [
            b"sliver",
            b"sessions",
            b"implant",
        ],
        "http_endpoints": [
            "/api/",
            "/messages",
            "/rpc",
        ],
        "mtls_patterns": True,  # Sliver uses mutual TLS
        "confidence_base": 88,
        "severity": "HIGH",
    },
    
    # Qakbot (QBot) - Banking trojan
    "Qakbot": {
        "description": "Banking trojan with worm capabilities (2007-present)",
        "family": "Qakbot",
        "category": "Trojan/Banker",
        "ports": [443, 995, 465, 2222],  # HTTPS and email ports
        "ja3_fingerprints": [
            "51c64c77e60f3980eea90869b68c58a8",  # Known Qakbot JA3
        ],
        "payload_patterns": [
            b"qakbot",
            b"qbot",
        ],
        "http_endpoints": [
            "/t1",
            "/t2",
            "/t3",
            "/t4",
            "/t5",
        ],
        "smtp_patterns": True,  # Uses SMTP for C2
        "confidence_base": 85,
        "severity": "HIGH",
    },
    
    # AsyncRAT - Remote Access Trojan
    "AsyncRAT": {
        "description": "Open-source remote access trojan (2019-present)",
        "family": "AsyncRAT",
        "category": "RAT",
        "ports": [6606, 7707, 8808, 8081],  # Common AsyncRAT ports
        "ja3_fingerprints": [
            "5e2c33d3cd42a4e9f4a0f4d344f1e2d0",  # Known AsyncRAT JA3
        ],
        "payload_patterns": [
            b"AsyncRAT",
            b"Pastebin",  # Often downloads from Pastebin
            b"Discord",   # Uses Discord webhooks
        ],
        "http_endpoints": [
            "/api/webhooks/",  # Discord webhooks
        ],
        "base64_config": True,  # Config often base64 encoded
        "confidence_base": 82,
        "severity": "HIGH",
    },
    
    # Meterpreter - Metasploit payload
    "Meterpreter": {
        "description": "Metasploit Framework payload (post-exploitation)",
        "family": "Meterpreter",
        "category": "Exploit/Post-Exploitation",
        "ports": [4444, 4445, 8443, 8080],  # Common Meterpreter ports
        "ja3_fingerprints": [
            "6734f37431670b3ab4292b8f60f29984",  # Known Meterpreter JA3
        ],
        "payload_patterns": [
            b"meterpreter",
            b"stdapi",
            b"priv",
            b"metsrv",
        ],
        "http_endpoints": [
            "/INITJM",
            "/INITM",
        ],
        "reverse_shell": True,
        "confidence_base": 88,
        "severity": "CRITICAL",
    },
    
    # Generic placeholder for unknown/emerging families
    "Unknown_Botnet": {
        "description": "Generic detection for unknown botnet families based on suspicious patterns",
        "family": "Unknown_Botnet",
        "category": "Generic",
        "ports": [],  # No specific ports
        "ja3_fingerprints": [],  # No specific JA3
        "payload_patterns": [
            b"bot",
            b"c2",
            b"command",
            b"control",
            b"backdoor",
        ],
        "http_endpoints": [
            "/gate.php",
            "/panel",
            "/bot",
            "/cmd",
        ],
        "confidence_base": 60,  # Lower confidence for generic detection
        "severity": "MEDIUM",
    },
}


# -----------------------
# Detection Scoring Rules
# -----------------------

DETECTION_WEIGHTS = {
    "ja3_match": 40,           # Strong indicator
    "port_match": 15,          # Weak indicator (many false positives)
    "payload_pattern": 30,     # Strong if specific pattern
    "http_endpoint": 25,       # Medium indicator
    "beacon_interval": 20,     # Medium indicator
    "dns_pattern": 15,         # Weak-medium indicator
    "user_agent": 10,          # Weak indicator
    "magic_bytes": 20,         # Medium indicator
}

# Minimum score to report detection
MIN_DETECTION_SCORE = 50

# Multiple matches bonus (stacking evidence)
MULTI_MATCH_BONUS = 10


# -----------------------
# Helper Functions
# -----------------------

def get_all_families():
    """Return list of all botnet family names"""
    return list(BOTNET_SIGNATURES.keys())


def get_family_signature(family_name):
    """Get signature for a specific botnet family"""
    return BOTNET_SIGNATURES.get(family_name, None)


def get_all_ja3_fingerprints():
    """Return dictionary mapping JA3 hashes to family names"""
    ja3_map = {}
    for family, sig in BOTNET_SIGNATURES.items():
        for ja3 in sig.get("ja3_fingerprints", []):
            if ja3 not in ja3_map:
                ja3_map[ja3] = []
            ja3_map[ja3].append(family)
    return ja3_map


def get_all_ports():
    """Return dictionary mapping ports to family names"""
    port_map = {}
    for family, sig in BOTNET_SIGNATURES.items():
        for port in sig.get("ports", []):
            if port not in port_map:
                port_map[port] = []
            port_map[port].append(family)
    return port_map


# -----------------------
# Threat Intelligence Feed Integration (TODO)
# -----------------------

# TODO: Add integration with open-source threat intelligence feeds
# Suggested feeds:
# - abuse.ch URLhaus (https://urlhaus.abuse.ch/)
# - abuse.ch Feodo Tracker (https://feodotracker.abuse.ch/)
# - Malware Bazaar (https://bazaar.abuse.ch/)
# - AlienVault OTX (https://otx.alienvault.com/)
# - Emerging Threats (https://rules.emergingthreats.net/)
#
# Implementation approach:
# 1. Create download_threat_intel() function
# 2. Parse feeds into signature format
# 3. Cache locally with TTL
# 4. Merge with static signatures
# 5. Schedule periodic updates

def download_threat_intel_feeds():
    """
    TODO: Download and parse threat intelligence feeds
    
    This function should:
    1. Fetch latest IOCs from configured feeds
    2. Parse into botnet signature format
    3. Update BOTNET_SIGNATURES dynamically
    4. Cache results locally
    
    Returns:
        dict: Updated signatures merged with feed data
    """
    # Placeholder for future implementation
    print("[TODO] Threat intelligence feed integration not yet implemented")
    print("[TODO] Consider integrating: URLhaus, Feodo Tracker, AlienVault OTX")
    return BOTNET_SIGNATURES


if __name__ == "__main__":
    # Test/debug output
    print("=== Botnet Signature Database ===")
    print(f"Total families: {len(BOTNET_SIGNATURES)}")
    print(f"\nConfigured families:")
    for family, sig in BOTNET_SIGNATURES.items():
        print(f"  - {family}: {sig['description']}")
        print(f"    Category: {sig['category']}, Severity: {sig['severity']}")
        print(f"    JA3 signatures: {len(sig.get('ja3_fingerprints', []))}")
        print(f"    Ports: {sig.get('ports', [])[:5]}")  # Show first 5 ports
    
    print(f"\n=== JA3 Fingerprint Index ===")
    ja3_map = get_all_ja3_fingerprints()
    print(f"Total unique JA3 hashes: {len(ja3_map)}")
    
    print(f"\n=== Port Index ===")
    port_map = get_all_ports()
    print(f"Total unique ports: {len(port_map)}")
    print(f"Most monitored ports: {sorted(port_map.keys())[:10]}")
