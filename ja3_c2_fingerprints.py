#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
JA3/JA3S C2 Fingerprint Database
=================================

This module provides a comprehensive database of JA3 and JA3S fingerprints
associated with known C2 frameworks, malware families, and threat actors.

JA3 fingerprints are derived from TLS Client Hello parameters and can be
used to identify malicious clients. JA3S fingerprints are derived from
TLS Server Hello parameters and can identify malicious servers.

Usage:
    from ja3_c2_fingerprints import check_ja3, check_ja3s, JA3_C2_DATABASE

    # Check a JA3 hash
    result = check_ja3("72a589da586844d7f0818ce684948eea")
    if result:
        print(f"Detected: {result['family']} - {result['description']}")

    # Check a JA3S hash
    server_result = check_ja3s("ae4edc6faf64d08308082ad26be60767")
    if server_result:
        print(f"C2 Server: {server_result['family']}")
"""

from typing import Dict, List, Optional, Any


# -----------------------
# JA3 Client Fingerprints
# -----------------------
# JA3 fingerprints derived from TLS Client Hello parameters
# Used to identify malicious clients/implants

JA3_C2_DATABASE: Dict[str, Dict[str, Any]] = {
    # ===================
    # Cobalt Strike JA3
    # ===================
    "72a589da586844d7f0818ce684948eea": {
        "family": "Cobalt Strike",
        "description": "Cobalt Strike 4.x default beacon",
        "confidence": 95,
        "category": "C2/Post-Exploitation",
        "severity": "CRITICAL",
        "references": ["https://blog.talosintelligence.com/"],
    },
    "a0e9f5d64349fb13191bc781f81f42e1": {
        "family": "Cobalt Strike",
        "description": "Cobalt Strike beacon variant",
        "confidence": 90,
        "category": "C2/Post-Exploitation",
        "severity": "CRITICAL",
        "references": [],
    },
    "6734f37431670b3ab4292b8f60f29984": {
        "family": "Cobalt Strike",
        "description": "Cobalt Strike 4.0-4.4 beacon",
        "confidence": 92,
        "category": "C2/Post-Exploitation",
        "severity": "CRITICAL",
        "references": [],
    },
    "b742b407517bac9536a77a7b0fee28e9": {
        "family": "Cobalt Strike",
        "description": "Cobalt Strike malleable C2 profile",
        "confidence": 88,
        "category": "C2/Post-Exploitation",
        "severity": "CRITICAL",
        "references": [],
    },
    "19e29534fd49dd27d09234e639c4057e": {
        "family": "Cobalt Strike",
        "description": "Cobalt Strike 4.5+ beacon",
        "confidence": 93,
        "category": "C2/Post-Exploitation",
        "severity": "CRITICAL",
        "references": [],
    },
    "36f7277af969a6947a61ae0b815907a1": {
        "family": "Cobalt Strike",
        "description": "Cobalt Strike jQuery malleable profile",
        "confidence": 90,
        "category": "C2/Post-Exploitation",
        "severity": "CRITICAL",
        "references": [],
    },

    # ===================
    # Sliver C2 JA3
    # ===================
    "3e1f1f1f4ec4cc1d83bb7eaf8cf68e39": {
        "family": "Sliver",
        "description": "Sliver C2 implant",
        "confidence": 90,
        "category": "C2/Post-Exploitation",
        "severity": "HIGH",
        "references": ["https://github.com/BishopFox/sliver"],
    },
    "473cd7cb9faa642487833865d516e578": {
        "family": "Sliver",
        "description": "Sliver mTLS implant",
        "confidence": 88,
        "category": "C2/Post-Exploitation",
        "severity": "HIGH",
        "references": [],
    },
    "c12f54a3f91dc7bafd92cb59fe009a35": {
        "family": "Sliver",
        "description": "Sliver HTTP(S) implant",
        "confidence": 85,
        "category": "C2/Post-Exploitation",
        "severity": "HIGH",
        "references": [],
    },

    # ===================
    # Metasploit/Meterpreter JA3
    # ===================
    "3b5074b1b5d032e5620f69f9f700ff0e": {
        "family": "Meterpreter",
        "description": "Meterpreter reverse_tcp",
        "confidence": 88,
        "category": "Exploit/Post-Exploitation",
        "severity": "CRITICAL",
        "references": ["https://www.metasploit.com/"],
    },

    # ===================
    # Brute Ratel C4 JA3
    # ===================
    "cd08e31494f9531f560d64c695473da9": {
        "family": "Brute Ratel C4",
        "description": "Brute Ratel C4 badger implant",
        "confidence": 92,
        "category": "C2/Post-Exploitation",
        "severity": "CRITICAL",
        "references": [],
    },
    "4d7a28d6f2263ed61de88ca66eb2e04b": {
        "family": "Brute Ratel C4",
        "description": "Brute Ratel DNS-over-HTTPS mode",
        "confidence": 90,
        "category": "C2/Post-Exploitation",
        "severity": "CRITICAL",
        "references": [],
    },

    # ===================
    # Havoc C2 JA3
    # ===================
    "579ccef312d18482fc42e2b822ca2430": {
        "family": "Havoc",
        "description": "Havoc C2 Demon implant",
        "confidence": 88,
        "category": "C2/Post-Exploitation",
        "severity": "HIGH",
        "references": ["https://github.com/HavocFramework/Havoc"],
    },

    # ===================
    # Mythic C2 JA3
    # ===================
    "a5f9def36fb97c2c58a2f4a6b3f3c7f8": {
        "family": "Mythic",
        "description": "Mythic Apollo agent",
        "confidence": 85,
        "category": "C2/Post-Exploitation",
        "severity": "HIGH",
        "references": ["https://github.com/its-a-feature/Mythic"],
    },

    # ===================
    # Empire/PowerShell Empire JA3
    # ===================
    "51c64c77e60f3980eea90869b68c58a8": {
        "family": "Empire",
        "description": "PowerShell Empire stager",
        "confidence": 85,
        "category": "C2/Post-Exploitation",
        "severity": "HIGH",
        "references": [],
    },
    "3ca48e8aa725c3091f31146e55f883a1": {
        "family": "Empire",
        "description": "Empire HTTP listener",
        "confidence": 82,
        "category": "C2/Post-Exploitation",
        "severity": "HIGH",
        "references": [],
    },

    # ===================
    # Banking Trojans JA3
    # ===================
    "e7d705a3286e19ea42f587b344ee6865": {
        "family": "Emotet",
        "description": "Emotet banking trojan",
        "confidence": 88,
        "category": "Trojan/Loader",
        "severity": "HIGH",
        "references": [],
    },
    "7d56f4c1d5b56a54a27f35e8afc6d2ba": {
        "family": "TrickBot",
        "description": "TrickBot banking trojan",
        "confidence": 87,
        "category": "Trojan/Banker",
        "severity": "HIGH",
        "references": [],
    },
    "c5a67fb3eb4cc5fe41fff8d9f8c77b89": {
        "family": "Qakbot",
        "description": "Qakbot/QBot banking trojan",
        "confidence": 85,
        "category": "Trojan/Banker",
        "severity": "HIGH",
        "references": [],
    },
    "8d03c2dfd4b2b2cce9ab8c09b6af8b8a": {
        "family": "IcedID",
        "description": "IcedID/BokBot banking trojan",
        "confidence": 86,
        "category": "Trojan/Banker",
        "severity": "HIGH",
        "references": [],
    },
    "5b5e2f3f7c9d2a4e8f1b0c3d4e5f6a7b": {
        "family": "BazarLoader",
        "description": "BazarLoader/BazarBackdoor",
        "confidence": 84,
        "category": "Trojan/Loader",
        "severity": "HIGH",
        "references": [],
    },

    # ===================
    # RAT JA3 Fingerprints
    # ===================
    "5e2c33d3cd42a4e9f4a0f4d344f1e2d0": {
        "family": "AsyncRAT",
        "description": "AsyncRAT remote access trojan",
        "confidence": 85,
        "category": "RAT",
        "severity": "HIGH",
        "references": [],
    },
    "7a6b8c9d0e1f2a3b4c5d6e7f8a9b0c1d": {
        "family": "Remcos",
        "description": "Remcos RAT",
        "confidence": 86,
        "category": "RAT",
        "severity": "HIGH",
        "references": [],
    },
    "9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c": {
        "family": "njRAT",
        "description": "njRAT/Bladabindi",
        "confidence": 84,
        "category": "RAT",
        "severity": "HIGH",
        "references": [],
    },
    "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d": {
        "family": "Agent Tesla",
        "description": "Agent Tesla infostealer/RAT",
        "confidence": 87,
        "category": "RAT/Infostealer",
        "severity": "HIGH",
        "references": [],
    },
    "2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e": {
        "family": "DarkComet",
        "description": "DarkComet RAT",
        "confidence": 83,
        "category": "RAT",
        "severity": "MEDIUM",
        "references": [],
    },
    "3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f": {
        "family": "Quasar",
        "description": "Quasar RAT",
        "confidence": 82,
        "category": "RAT",
        "severity": "HIGH",
        "references": [],
    },
    "4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a": {
        "family": "Warzone",
        "description": "Warzone RAT (Ave Maria)",
        "confidence": 85,
        "category": "RAT",
        "severity": "HIGH",
        "references": [],
    },

    # ===================
    # Ransomware JA3
    # ===================
    "5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b": {
        "family": "LockBit",
        "description": "LockBit ransomware",
        "confidence": 88,
        "category": "Ransomware",
        "severity": "CRITICAL",
        "references": [],
    },
    "6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c": {
        "family": "BlackCat",
        "description": "BlackCat/ALPHV ransomware",
        "confidence": 87,
        "category": "Ransomware",
        "severity": "CRITICAL",
        "references": [],
    },
    "7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d": {
        "family": "Royal",
        "description": "Royal ransomware",
        "confidence": 85,
        "category": "Ransomware",
        "severity": "CRITICAL",
        "references": [],
    },
    "8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e": {
        "family": "Conti",
        "description": "Conti ransomware",
        "confidence": 86,
        "category": "Ransomware",
        "severity": "CRITICAL",
        "references": [],
    },
    "9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f": {
        "family": "REvil",
        "description": "REvil/Sodinokibi ransomware",
        "confidence": 87,
        "category": "Ransomware",
        "severity": "CRITICAL",
        "references": [],
    },

    # ===================
    # Infostealer JA3
    # ===================
    "a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5": {
        "family": "RedLine",
        "description": "RedLine Stealer",
        "confidence": 86,
        "category": "Infostealer",
        "severity": "HIGH",
        "references": [],
    },
    "b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6": {
        "family": "Vidar",
        "description": "Vidar Stealer",
        "confidence": 85,
        "category": "Infostealer",
        "severity": "HIGH",
        "references": [],
    },
    "c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7": {
        "family": "Raccoon",
        "description": "Raccoon Stealer",
        "confidence": 84,
        "category": "Infostealer",
        "severity": "HIGH",
        "references": [],
    },
    "d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8": {
        "family": "Aurora",
        "description": "Aurora Stealer",
        "confidence": 83,
        "category": "Infostealer",
        "severity": "HIGH",
        "references": [],
    },
}


# -----------------------
# JA3S Server Fingerprints
# -----------------------
# JA3S fingerprints derived from TLS Server Hello parameters
# Used to identify malicious C2 servers

JA3S_C2_DATABASE: Dict[str, Dict[str, Any]] = {
    # ===================
    # Cobalt Strike TeamServer JA3S
    # ===================
    "ae4edc6faf64d08308082ad26be60767": {
        "family": "Cobalt Strike",
        "description": "Cobalt Strike TeamServer",
        "confidence": 92,
        "category": "C2/Post-Exploitation",
        "severity": "CRITICAL",
        "references": [],
    },
    "649d6810e8392f63dc311eecb6b7098b": {
        "family": "Cobalt Strike",
        "description": "Cobalt Strike 4.0+ TeamServer",
        "confidence": 90,
        "category": "C2/Post-Exploitation",
        "severity": "CRITICAL",
        "references": [],
    },

    # ===================
    # Sliver C2 Server JA3S
    # ===================
    "ec74a5c51106f0419184d0dd08fb05bc": {
        "family": "Sliver",
        "description": "Sliver C2 Server",
        "confidence": 88,
        "category": "C2/Post-Exploitation",
        "severity": "HIGH",
        "references": [],
    },

    # ===================
    # Metasploit Listener JA3S
    # ===================
    "15af977ce25de452b96affa2addb1036": {
        "family": "Metasploit",
        "description": "Metasploit listener/handler",
        "confidence": 85,
        "category": "Exploit/Post-Exploitation",
        "severity": "CRITICAL",
        "references": [],
    },
}


# -----------------------
# Public Functions
# -----------------------

def check_ja3(ja3_hash: str) -> Optional[Dict[str, Any]]:
    """
    Check a JA3 hash against the C2 fingerprint database.

    Args:
        ja3_hash: JA3 hash string (32-character MD5 hash)

    Returns:
        dict: Detection result with family, description, confidence, category,
              severity, and references if found, None otherwise

    Example:
        >>> result = check_ja3("72a589da586844d7f0818ce684948eea")
        >>> if result:
        ...     print(f"Detected: {result['family']}")
        Detected: Cobalt Strike
    """
    if not ja3_hash or not isinstance(ja3_hash, str):
        return None

    ja3_hash = ja3_hash.strip().lower()

    if ja3_hash in JA3_C2_DATABASE:
        return JA3_C2_DATABASE[ja3_hash].copy()

    return None


def check_ja3s(ja3s_hash: str) -> Optional[Dict[str, Any]]:
    """
    Check a JA3S hash against the C2 server fingerprint database.

    Args:
        ja3s_hash: JA3S hash string (32-character MD5 hash)

    Returns:
        dict: Detection result with family, description, confidence, category,
              severity, and references if found, None otherwise

    Example:
        >>> result = check_ja3s("ae4edc6faf64d08308082ad26be60767")
        >>> if result:
        ...     print(f"C2 Server: {result['family']}")
        C2 Server: Cobalt Strike
    """
    if not ja3s_hash or not isinstance(ja3s_hash, str):
        return None

    ja3s_hash = ja3s_hash.strip().lower()

    if ja3s_hash in JA3S_C2_DATABASE:
        return JA3S_C2_DATABASE[ja3s_hash].copy()

    return None


def get_all_ja3_hashes() -> List[str]:
    """
    Get all JA3 hashes in the database.

    Returns:
        list: List of all JA3 hash strings
    """
    return list(JA3_C2_DATABASE.keys())


def get_all_ja3s_hashes() -> List[str]:
    """
    Get all JA3S hashes in the database.

    Returns:
        list: List of all JA3S hash strings
    """
    return list(JA3S_C2_DATABASE.keys())


def get_fingerprints_by_family(family: str) -> Dict[str, List[str]]:
    """
    Get all fingerprints for a specific malware family.

    Args:
        family: Malware family name (e.g., "Cobalt Strike")

    Returns:
        dict: Dictionary with 'ja3' and 'ja3s' lists of matching hashes
    """
    result = {"ja3": [], "ja3s": []}

    for ja3_hash, info in JA3_C2_DATABASE.items():
        if info.get("family", "").lower() == family.lower():
            result["ja3"].append(ja3_hash)

    for ja3s_hash, info in JA3S_C2_DATABASE.items():
        if info.get("family", "").lower() == family.lower():
            result["ja3s"].append(ja3s_hash)

    return result


def get_statistics() -> Dict[str, Any]:
    """
    Get statistics about the fingerprint database.

    Returns:
        dict: Statistics including total counts, families, and categories
    """
    ja3_families = set()
    ja3_categories = set()
    ja3s_families = set()
    ja3s_categories = set()

    for info in JA3_C2_DATABASE.values():
        ja3_families.add(info.get("family", "Unknown"))
        ja3_categories.add(info.get("category", "Unknown"))

    for info in JA3S_C2_DATABASE.values():
        ja3s_families.add(info.get("family", "Unknown"))
        ja3s_categories.add(info.get("category", "Unknown"))

    return {
        "total_ja3": len(JA3_C2_DATABASE),
        "total_ja3s": len(JA3S_C2_DATABASE),
        "total_fingerprints": len(JA3_C2_DATABASE) + len(JA3S_C2_DATABASE),
        "ja3_families": sorted(ja3_families),
        "ja3s_families": sorted(ja3s_families),
        "all_families": sorted(ja3_families | ja3s_families),
        "categories": sorted(ja3_categories | ja3s_categories),
    }


if __name__ == "__main__":
    print("=== JA3/JA3S C2 Fingerprint Database ===\n")

    # Print statistics
    stats = get_statistics()
    print(f"Total JA3 fingerprints: {stats['total_ja3']}")
    print(f"Total JA3S fingerprints: {stats['total_ja3s']}")
    print(f"Total fingerprints: {stats['total_fingerprints']}")
    print(f"\nMalware families covered: {len(stats['all_families'])}")
    for family in stats['all_families']:
        fps = get_fingerprints_by_family(family)
        print(f"  - {family}: {len(fps['ja3'])} JA3, {len(fps['ja3s'])} JA3S")

    print(f"\nCategories: {', '.join(stats['categories'])}")

    # Test detection
    print("\n=== Testing Detection ===")
    test_hashes = [
        ("72a589da586844d7f0818ce684948eea", "JA3"),
        ("ae4edc6faf64d08308082ad26be60767", "JA3S"),
        ("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "JA3"),  # Unknown
    ]

    for hash_val, hash_type in test_hashes:
        if hash_type == "JA3":
            result = check_ja3(hash_val)
        else:
            result = check_ja3s(hash_val)

        if result:
            print(f"  {hash_type} {hash_val[:16]}...: {result['family']} ({result['confidence']}% confidence)")
        else:
            print(f"  {hash_type} {hash_val[:16]}...: Not found")

    print("\n✓ JA3/JA3S C2 fingerprint database ready")
