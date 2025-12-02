#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DNS-Based C2 Detection Module
==============================

This module provides detection capabilities for DNS-based C2 communication,
including DGA (Domain Generation Algorithm) detection, DNS tunneling detection,
and suspicious domain analysis.

Features:
- DGA detection using entropy analysis, vowel/digit ratios, and pattern matching
- DNS tunneling detection via subdomain analysis and query patterns
- Encoding detection (base64, hex, base32) in domain names
- Suspicious TLD monitoring

Usage:
    from dns_c2_detector import DNSC2Detector, analyze_dns_traffic

    # Create detector and analyze domains
    detector = DNSC2Detector()
    result = detector.analyze_domain("abc123def456.suspicious.tk", "A", 50)
    print(result)

    # Analyze DNS DataFrame
    results = analyze_dns_traffic(dns_df)
"""

import math
import re
from collections import defaultdict
from typing import Dict, List, Optional, Any, Set


# -----------------------
# Suspicious TLDs
# -----------------------
# TLDs commonly associated with malware and abuse

SUSPICIOUS_TLDS: Set[str] = {
    ".tk", ".ml", ".ga", ".cf", ".gq",  # Free TLDs often abused
    ".top", ".xyz", ".pw", ".cc",       # Cheap TLDs with high abuse
    ".su", ".ru", ".cn",                # Historically high abuse regions
    ".ws", ".to", ".biz",               # Other commonly abused
    ".work", ".click", ".link",         # Generic TLDs with abuse
    ".icu", ".buzz", ".monster",        # New TLDs with high abuse rates
    ".live", ".life", ".online",        # More new TLDs
    ".space", ".site", ".fun",          # Additional abused TLDs
}


# -----------------------
# DGA Detection Patterns
# -----------------------
# Regex patterns for common DGA families

DGA_PATTERNS: Dict[str, str] = {
    "cryptolocker": r"^[a-z]{12,20}\.(?:com|net|org|biz|info)$",
    "necurs": r"^[a-z]{4,10}[a-z0-9]{4,10}\.(?:top|xyz|pw)$",
    "conficker": r"^[bcdfghjklmnpqrstvwxz]{2,}[aeiou][bcdfghjklmnpqrstvwxz]{2,}\.(?:ws|cc|cn)$",
    "qakbot": r"^[a-z]{10,15}\.(?:com|net|org)$",
    "suppobox": r"^[a-z]{12,20}\.(?:com|net)$",
}


class DNSC2Detector:
    """
    DNS-based C2 Detection Class.

    Analyzes DNS queries and responses for indicators of C2 communication,
    including DGA domains, DNS tunneling, and encoding patterns.
    """

    def __init__(self):
        """Initialize the DNS C2 detector."""
        # Track query frequency: {domain: [timestamps]}
        self.domain_queries: Dict[str, List[float]] = defaultdict(list)
        # Store analysis results
        self.suspicious_domains: Dict[str, Dict[str, Any]] = {}

    def analyze_domain(
        self,
        domain: str,
        query_type: str = "A",
        response_size: int = 0,
        timestamp: float = 0.0
    ) -> Dict[str, Any]:
        """
        Analyze a single DNS query for C2 indicators.

        Args:
            domain: Domain name being queried
            query_type: DNS query type (A, AAAA, TXT, MX, etc.)
            response_size: Size of DNS response in bytes
            timestamp: Unix timestamp of the query

        Returns:
            dict: Analysis results with suspicion indicators
        """
        if not domain or not isinstance(domain, str):
            return {"suspicious": False, "indicators": []}

        domain = domain.strip().lower()
        indicators = []
        suspicion_score = 0

        # Track query for frequency analysis
        if timestamp:
            self.domain_queries[domain].append(timestamp)

        # Check for suspicious TLD
        for tld in SUSPICIOUS_TLDS:
            if domain.endswith(tld):
                indicators.append({
                    "type": "suspicious_tld",
                    "value": tld,
                    "description": f"Domain uses suspicious TLD: {tld}",
                })
                suspicion_score += 15
                break

        # Check for DGA patterns
        dga_result = self._check_dga(domain)
        if dga_result["is_dga"]:
            indicators.append({
                "type": "dga_detected",
                "pattern": dga_result.get("pattern"),
                "entropy": dga_result.get("entropy"),
                "description": dga_result.get("reason", "DGA-like domain detected"),
            })
            suspicion_score += dga_result.get("score", 30)

        # Check for DNS tunneling
        tunneling_result = self._check_dns_tunneling(domain, query_type, response_size)
        if tunneling_result["is_tunneling"]:
            indicators.extend(tunneling_result.get("indicators", []))
            suspicion_score += tunneling_result.get("score", 25)

        # Check for encoding patterns
        encoding_result = self._check_encoding_patterns(domain)
        if encoding_result["has_encoding"]:
            indicators.append({
                "type": "encoded_subdomain",
                "encoding": encoding_result.get("encoding"),
                "description": f"Possible {encoding_result.get('encoding')} encoded data in subdomain",
            })
            suspicion_score += 20

        # Determine overall suspicion level
        if suspicion_score >= 50:
            classification = "HIGH"
        elif suspicion_score >= 30:
            classification = "MEDIUM"
        elif suspicion_score > 0:
            classification = "LOW"
        else:
            classification = "NONE"

        result = {
            "domain": domain,
            "suspicious": suspicion_score > 0,
            "suspicion_score": suspicion_score,
            "classification": classification,
            "indicators": indicators,
            "query_type": query_type,
            "response_size": response_size,
        }

        # Store if suspicious
        if suspicion_score > 0:
            self.suspicious_domains[domain] = result

        return result

    def _check_dga(self, domain: str) -> Dict[str, Any]:
        """
        Check if domain appears to be generated by a DGA.

        Uses multiple heuristics:
        - Shannon entropy calculation
        - Vowel ratio analysis
        - Digit ratio analysis
        - Consonant cluster detection
        - Known DGA pattern matching

        Args:
            domain: Domain name to analyze

        Returns:
            dict: DGA detection results
        """
        result = {
            "is_dga": False,
            "score": 0,
            "reason": None,
            "entropy": 0.0,
            "pattern": None,
        }

        # Extract the main domain (second-level domain)
        parts = domain.split(".")
        if len(parts) < 2:
            return result

        # For subdomains, analyze the most suspicious part
        if len(parts) > 2:
            # Check if subdomain is suspiciously long/random
            subdomain = ".".join(parts[:-2])
            if len(subdomain) > 20:
                sld = subdomain
            else:
                sld = parts[-2]
        else:
            sld = parts[-2]

        if len(sld) < 4:
            return result

        # Calculate Shannon entropy
        entropy = self._calculate_entropy(sld)
        result["entropy"] = round(entropy, 2)

        # High entropy indicates randomness (DGA)
        if entropy >= 4.0:
            result["is_dga"] = True
            result["score"] = 35
            result["reason"] = f"High entropy domain ({entropy:.2f} >= 4.0)"
            return result

        # Check vowel ratio (DGA domains often lack vowels)
        vowels = sum(1 for c in sld.lower() if c in "aeiou")
        vowel_ratio = vowels / len(sld) if sld else 0

        if len(sld) >= 10 and vowel_ratio < 0.15:
            result["is_dga"] = True
            result["score"] = 30
            result["reason"] = f"Low vowel ratio ({vowel_ratio:.1%} < 15%)"
            return result

        # Check digit ratio (high digit ratio can indicate DGA)
        digits = sum(1 for c in sld if c.isdigit())
        digit_ratio = digits / len(sld) if sld else 0

        if len(sld) >= 10 and digit_ratio > 0.40:
            result["is_dga"] = True
            result["score"] = 28
            result["reason"] = f"High digit ratio ({digit_ratio:.1%} > 40%)"
            return result

        # Check for consonant clusters (4+ consecutive consonants)
        consonant_cluster = re.search(r'[bcdfghjklmnpqrstvwxyz]{4,}', sld.lower())
        if consonant_cluster:
            result["is_dga"] = True
            result["score"] = 25
            result["reason"] = f"Consonant cluster detected: '{consonant_cluster.group()}'"
            return result

        # Check against known DGA patterns
        for dga_name, pattern in DGA_PATTERNS.items():
            if re.match(pattern, domain, re.IGNORECASE):
                result["is_dga"] = True
                result["score"] = 40
                result["reason"] = f"Matches {dga_name} DGA pattern"
                result["pattern"] = dga_name
                return result

        return result

    def _calculate_entropy(self, text: str) -> float:
        """
        Calculate Shannon entropy of a string.

        Args:
            text: Input string

        Returns:
            float: Shannon entropy value
        """
        if not text:
            return 0.0

        # Count character frequencies
        freq = defaultdict(int)
        for char in text.lower():
            freq[char] += 1

        # Calculate entropy
        length = len(text)
        entropy = 0.0

        for count in freq.values():
            if count > 0:
                prob = count / length
                entropy -= prob * math.log2(prob)

        return entropy

    def _check_dns_tunneling(
        self,
        domain: str,
        query_type: str,
        response_size: int
    ) -> Dict[str, Any]:
        """
        Check for DNS tunneling indicators.

        Args:
            domain: Domain name
            query_type: DNS query type
            response_size: Response size in bytes

        Returns:
            dict: Tunneling detection results
        """
        result = {
            "is_tunneling": False,
            "score": 0,
            "indicators": [],
        }

        parts = domain.split(".")
        if len(parts) <= 2:
            return result

        # Get subdomain part
        subdomain = ".".join(parts[:-2])

        # Check subdomain length (>50 chars is suspicious)
        if len(subdomain) > 50:
            result["is_tunneling"] = True
            result["score"] += 25
            result["indicators"].append({
                "type": "long_subdomain",
                "length": len(subdomain),
                "description": f"Subdomain length ({len(subdomain)}) exceeds 50 characters",
            })

        # Check subdomain entropy
        if subdomain:
            entropy = self._calculate_entropy(subdomain)
            if entropy >= 4.0:
                result["is_tunneling"] = True
                result["score"] += 20
                result["indicators"].append({
                    "type": "high_subdomain_entropy",
                    "entropy": round(entropy, 2),
                    "description": f"High subdomain entropy ({entropy:.2f})",
                })

        # Check for large TXT record responses (tunneling often uses TXT)
        if query_type.upper() == "TXT" and response_size > 200:
            result["is_tunneling"] = True
            result["score"] += 30
            result["indicators"].append({
                "type": "large_txt_response",
                "size": response_size,
                "description": f"Large TXT response ({response_size} bytes)",
            })

        # Check query frequency (requires timestamp data)
        base_domain = ".".join(parts[-2:])
        if base_domain in self.domain_queries:
            timestamps = self.domain_queries[base_domain]
            if len(timestamps) >= 2:
                # Check if > 100 queries per minute
                time_span = max(timestamps) - min(timestamps)
                if time_span > 0:
                    queries_per_min = len(timestamps) / (time_span / 60)
                    if queries_per_min > 100:
                        result["is_tunneling"] = True
                        result["score"] += 35
                        result["indicators"].append({
                            "type": "high_query_frequency",
                            "rate": round(queries_per_min, 1),
                            "description": f"High query rate ({queries_per_min:.1f} queries/min)",
                        })

        return result

    def _check_encoding_patterns(self, domain: str) -> Dict[str, Any]:
        """
        Detect encoding patterns (hex, base32, base64) in subdomains.

        Args:
            domain: Domain name to analyze

        Returns:
            dict: Encoding detection results
        """
        result = {
            "has_encoding": False,
            "encoding": None,
        }

        parts = domain.split(".")
        if len(parts) <= 2:
            return result

        subdomain = parts[0].lower()

        if len(subdomain) < 8:
            return result

        # Check for hex encoding (only hex chars, even length)
        if re.match(r'^[0-9a-f]+$', subdomain) and len(subdomain) % 2 == 0:
            if len(subdomain) >= 16:  # At least 8 bytes of data
                result["has_encoding"] = True
                result["encoding"] = "hex"
                return result

        # Check for base32 encoding (A-Z, 2-7, = padding)
        if re.match(r'^[a-z2-7]+={0,6}$', subdomain):
            if len(subdomain) >= 16:
                result["has_encoding"] = True
                result["encoding"] = "base32"
                return result

        # Check for base64-like encoding (high variety, specific chars)
        if re.match(r'^[a-zA-Z0-9+/\-_]+={0,2}$', subdomain):
            # Check if it has base64-like characteristics
            has_upper = any(c.isupper() for c in subdomain)
            has_lower = any(c.islower() for c in subdomain)
            has_digit = any(c.isdigit() for c in subdomain)

            if has_upper and has_lower and has_digit and len(subdomain) >= 20:
                result["has_encoding"] = True
                result["encoding"] = "base64"
                return result

        return result

    def get_suspicious_domains_summary(self) -> Dict[str, Any]:
        """
        Get summary of all suspicious domains analyzed.

        Returns:
            dict: Summary with counts, top domains, and patterns
        """
        if not self.suspicious_domains:
            return {
                "total_suspicious": 0,
                "high_risk": 0,
                "medium_risk": 0,
                "low_risk": 0,
                "top_domains": [],
                "indicator_types": {},
            }

        high_risk = sum(1 for d in self.suspicious_domains.values() if d["classification"] == "HIGH")
        medium_risk = sum(1 for d in self.suspicious_domains.values() if d["classification"] == "MEDIUM")
        low_risk = sum(1 for d in self.suspicious_domains.values() if d["classification"] == "LOW")

        # Count indicator types
        indicator_types: Dict[str, int] = defaultdict(int)
        for domain_info in self.suspicious_domains.values():
            for indicator in domain_info.get("indicators", []):
                indicator_types[indicator["type"]] += 1

        # Get top suspicious domains by score
        sorted_domains = sorted(
            self.suspicious_domains.items(),
            key=lambda x: x[1]["suspicion_score"],
            reverse=True
        )

        top_domains = [
            {"domain": domain, "score": info["suspicion_score"], "classification": info["classification"]}
            for domain, info in sorted_domains[:10]
        ]

        return {
            "total_suspicious": len(self.suspicious_domains),
            "high_risk": high_risk,
            "medium_risk": medium_risk,
            "low_risk": low_risk,
            "top_domains": top_domains,
            "indicator_types": dict(indicator_types),
        }

    def clear(self) -> None:
        """Clear all stored data."""
        self.domain_queries.clear()
        self.suspicious_domains.clear()


def analyze_dns_traffic(
    dns_df,
    domain_column: str = "DOMAIN",
    query_type_column: str = "TYPE",
    response_size_column: str = "RESPONSE_SIZE"
) -> List[Dict[str, Any]]:
    """
    Convenience function to analyze a DNS DataFrame for C2 indicators.

    Args:
        dns_df: pandas DataFrame with DNS query data
        domain_column: Column name for domain names
        query_type_column: Column name for query types
        response_size_column: Column name for response sizes

    Returns:
        list: Analysis results for each suspicious domain
    """
    detector = DNSC2Detector()
    results = []

    if dns_df is None or dns_df.empty:
        return results

    if domain_column not in dns_df.columns:
        print(f"[DNSC2Detector] Warning: Column '{domain_column}' not found")
        return results

    for idx, row in dns_df.iterrows():
        domain = str(row.get(domain_column, ""))
        query_type = str(row.get(query_type_column, "A"))

        try:
            response_size = int(row.get(response_size_column, 0))
        except (ValueError, TypeError):
            response_size = 0

        result = detector.analyze_domain(domain, query_type, response_size)

        if result["suspicious"]:
            results.append(result)

    return results


if __name__ == "__main__":
    print("=== DNS C2 Detection Module ===\n")

    detector = DNSC2Detector()

    # Test domains
    test_domains = [
        ("google.com", "A", 50),
        ("abc123def456ghi789.suspicious.tk", "A", 50),
        ("xnvkdfjslkjfd2847sjdf.evil.xyz", "A", 50),
        ("bxdfghjklmnpqrs.malware.pw", "A", 50),
        ("aGVsbG8gd29ybGQ.tunnel.com", "TXT", 300),
        ("4142434445464748.exfil.net", "A", 50),
        ("legit-business-site.com", "A", 50),
        ("c2-server.ru", "A", 50),
    ]

    print("Testing domain analysis:\n")

    for domain, qtype, size in test_domains:
        result = detector.analyze_domain(domain, qtype, size)
        status = "⚠️ " if result["suspicious"] else "✓ "
        print(f"{status}{domain}")
        if result["suspicious"]:
            print(f"   Score: {result['suspicion_score']} ({result['classification']})")
            for indicator in result["indicators"]:
                print(f"   - {indicator['type']}: {indicator['description']}")
        print()

    # Print summary
    summary = detector.get_suspicious_domains_summary()
    print("=== Summary ===")
    print(f"Total suspicious: {summary['total_suspicious']}")
    print(f"  High risk: {summary['high_risk']}")
    print(f"  Medium risk: {summary['medium_risk']}")
    print(f"  Low risk: {summary['low_risk']}")
    print(f"\nIndicator types: {summary['indicator_types']}")

    print("\n=== Suspicious TLDs Monitored ===")
    print(", ".join(sorted(SUSPICIOUS_TLDS)))

    print("\n✓ DNS C2 detection module ready")
