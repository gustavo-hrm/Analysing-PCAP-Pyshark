#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HTTP C2 Pattern Detection Module
=================================

This module provides detection capabilities for HTTP-based C2 communication,
including endpoint pattern matching, User-Agent analysis, and payload detection.

Features:
- C2 endpoint pattern detection for known frameworks
- Suspicious User-Agent identification
- Payload pattern matching (TrickBot, PowerShell, etc.)
- Encoded data detection in URIs
- Response code analysis

Usage:
    from http_c2_detector import HTTPC2Detector, analyze_http_traffic

    # Create detector and analyze request
    detector = HTTPC2Detector()
    result = detector.analyze_http_request(
        method="GET",
        uri="/jquery-3.3.1.min.js",
        host="suspicious.com",
        user_agent="Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)",
        body="",
        src_ip="192.168.1.100",
        dst_ip="10.0.0.1",
        response_code=200
    )
"""

import math
import re
from collections import defaultdict
from typing import Dict, List, Optional, Any, Tuple


# -----------------------
# C2 Endpoint Patterns
# -----------------------
# Known C2 framework endpoints and their characteristics

C2_ENDPOINT_PATTERNS: Dict[str, Dict[str, Any]] = {
    # Cobalt Strike endpoints
    "/jquery-3.3.1.min.js": {
        "family": "Cobalt Strike",
        "description": "Cobalt Strike jQuery malleable profile",
        "confidence": 85,
    },
    "/__utm.gif": {
        "family": "Cobalt Strike",
        "description": "Cobalt Strike UTM beacon",
        "confidence": 90,
    },
    "/pixel.gif": {
        "family": "Cobalt Strike",
        "description": "Cobalt Strike pixel beacon",
        "confidence": 75,
    },
    "/activity": {
        "family": "Cobalt Strike",
        "description": "Cobalt Strike activity endpoint",
        "confidence": 70,
    },
    "/fwlink": {
        "family": "Cobalt Strike",
        "description": "Cobalt Strike fwlink profile",
        "confidence": 75,
    },
    "/submit.php": {
        "family": "Cobalt Strike",
        "description": "Cobalt Strike submit endpoint",
        "confidence": 65,
    },
    "/ga.js": {
        "family": "Cobalt Strike",
        "description": "Cobalt Strike Google Analytics profile",
        "confidence": 70,
    },
    "/ca": {
        "family": "Cobalt Strike",
        "description": "Cobalt Strike CA endpoint",
        "confidence": 60,
    },
    "/push": {
        "family": "Cobalt Strike",
        "description": "Cobalt Strike push endpoint",
        "confidence": 55,
    },

    # Meterpreter endpoints
    "/INITJM": {
        "family": "Meterpreter",
        "description": "Meterpreter Java staged payload",
        "confidence": 95,
    },
    "/INITM": {
        "family": "Meterpreter",
        "description": "Meterpreter staged payload",
        "confidence": 95,
    },

    # Generic C2 endpoints
    "/gate.php": {
        "family": "Generic C2",
        "description": "Common malware gate script",
        "confidence": 80,
    },
    "/panel.php": {
        "family": "Generic C2",
        "description": "C2 panel endpoint",
        "confidence": 75,
    },
    "/command.php": {
        "family": "Generic C2",
        "description": "C2 command endpoint",
        "confidence": 80,
    },
    "/config.php": {
        "family": "Generic C2",
        "description": "C2 configuration endpoint",
        "confidence": 60,
    },
    "/task.php": {
        "family": "Generic C2",
        "description": "C2 task endpoint",
        "confidence": 70,
    },
    "/beacon": {
        "family": "Generic C2",
        "description": "Beacon check-in endpoint",
        "confidence": 75,
    },
    "/bot.php": {
        "family": "Generic C2",
        "description": "Bot check-in endpoint",
        "confidence": 80,
    },
    "/cmd.php": {
        "family": "Generic C2",
        "description": "Command execution endpoint",
        "confidence": 75,
    },

    # RAT endpoints
    "/rat/": {
        "family": "RAT",
        "description": "RAT command endpoint",
        "confidence": 85,
    },
    "/connect.php": {
        "family": "RAT",
        "description": "RAT connection handler",
        "confidence": 70,
    },

    # Loader endpoints
    "/loader": {
        "family": "Loader",
        "description": "Payload loader endpoint",
        "confidence": 70,
    },
    "/download.php": {
        "family": "Loader",
        "description": "Payload download endpoint",
        "confidence": 60,
    },
    "/update.php": {
        "family": "Loader",
        "description": "Malware update endpoint",
        "confidence": 55,
    },
    "/get.php": {
        "family": "Loader",
        "description": "Payload retrieval endpoint",
        "confidence": 55,
    },

    # Webshell patterns
    "/shell.php": {
        "family": "Webshell",
        "description": "Web shell endpoint",
        "confidence": 90,
    },
    "/cmd": {
        "family": "Webshell",
        "description": "Command execution endpoint",
        "confidence": 65,
    },
    "/exec": {
        "family": "Webshell",
        "description": "Execution endpoint",
        "confidence": 65,
    },
}


# -----------------------
# Suspicious User-Agents
# -----------------------
# Known malware User-Agent patterns

SUSPICIOUS_USER_AGENTS: List[Dict[str, Any]] = [
    {
        "pattern": r"MSIE\s*9\.0.*Trident/5\.0",
        "family": "Cobalt Strike",
        "description": "Cobalt Strike default MSIE 9.0 User-Agent",
        "confidence": 85,
    },
    {
        "pattern": r"Trident/7\.0.*rv:11\.0",
        "family": "Emotet/TrickBot",
        "description": "Emotet/TrickBot common User-Agent",
        "confidence": 70,
    },
    {
        "pattern": r"MSIE\s*7\.0.*Windows\s*NT\s*5\.1",
        "family": "Legacy Malware",
        "description": "Outdated IE 7.0 on XP - suspicious",
        "confidence": 60,
    },
    {
        "pattern": r"Mozilla/4\.0.*MSIE\s*6\.0",
        "family": "Legacy Malware",
        "description": "Very outdated IE 6.0 - highly suspicious",
        "confidence": 75,
    },
    {
        "pattern": r"^python-requests/",
        "family": "Script/Bot",
        "description": "Python requests library - automated tool",
        "confidence": 40,
    },
    {
        "pattern": r"^curl/",
        "family": "Script/Bot",
        "description": "curl - automated tool",
        "confidence": 35,
    },
    {
        "pattern": r"^wget/",
        "family": "Script/Bot",
        "description": "wget - automated tool",
        "confidence": 35,
    },
    {
        "pattern": r"^Go-http-client/",
        "family": "Script/Bot",
        "description": "Go HTTP client - possibly C2 implant",
        "confidence": 45,
    },
    {
        "pattern": r"Windows-Update-Agent",
        "family": "Potential Evasion",
        "description": "Windows Update Agent spoofing",
        "confidence": 50,
    },
    {
        "pattern": r"^$",  # Empty User-Agent
        "family": "Suspicious",
        "description": "Empty User-Agent - suspicious",
        "confidence": 60,
    },
]


# -----------------------
# Payload Patterns
# -----------------------
# Regex patterns for detecting malicious payloads

PAYLOAD_PATTERNS: List[Dict[str, Any]] = [
    {
        "pattern": r"<mcconf>",
        "family": "TrickBot",
        "description": "TrickBot configuration marker",
        "confidence": 95,
    },
    {
        "pattern": r"<moduleconfig>",
        "family": "TrickBot",
        "description": "TrickBot module configuration",
        "confidence": 95,
    },
    {
        "pattern": r"<autorun>",
        "family": "TrickBot",
        "description": "TrickBot autorun marker",
        "confidence": 90,
    },
    {
        "pattern": r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}",
        "family": "Generic C2",
        "description": "GUID pattern - possible bot ID",
        "confidence": 40,
    },
    {
        "pattern": r"HWID=[A-Z0-9]{16,32}",
        "family": "RAT/Stealer",
        "description": "Hardware ID pattern",
        "confidence": 75,
    },
    {
        "pattern": r"beacon_id=[a-zA-Z0-9]+",
        "family": "Generic C2",
        "description": "Beacon ID pattern",
        "confidence": 70,
    },
    {
        "pattern": r"powershell.*-enc\s+[a-zA-Z0-9+/=]+",
        "family": "PowerShell",
        "description": "Encoded PowerShell command",
        "confidence": 90,
    },
    {
        "pattern": r"IEX\s*\(",
        "family": "PowerShell",
        "description": "PowerShell Invoke-Expression",
        "confidence": 80,
    },
    {
        "pattern": r"FromBase64String",
        "family": "PowerShell",
        "description": "PowerShell base64 decode",
        "confidence": 70,
    },
    {
        "pattern": r"DownloadString\s*\(",
        "family": "PowerShell",
        "description": "PowerShell download cradle",
        "confidence": 85,
    },
    {
        "pattern": r"cmd\.exe\s*/c",
        "family": "Command Execution",
        "description": "Command shell execution",
        "confidence": 60,
    },
    {
        "pattern": r"wscript\.exe|cscript\.exe",
        "family": "Script Execution",
        "description": "Windows script host execution",
        "confidence": 65,
    },
    {
        "pattern": r"mshta\.exe",
        "family": "LOLBIN",
        "description": "MSHTA execution - common evasion",
        "confidence": 75,
    },
    {
        "pattern": r"regsvr32\.exe.*scrobj\.dll",
        "family": "LOLBIN",
        "description": "Regsvr32 COM scriptlet execution",
        "confidence": 85,
    },
]


class HTTPC2Detector:
    """
    HTTP C2 Pattern Detection Class.

    Analyzes HTTP requests and responses for indicators of C2 communication.
    """

    def __init__(self):
        """Initialize the HTTP C2 detector."""
        # Track request patterns: {(src_ip, dst_ip): [request_info]}
        self.requests: Dict[Tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)
        # Store detections
        self.detections: List[Dict[str, Any]] = []

    def analyze_http_request(
        self,
        method: str,
        uri: str,
        host: str,
        user_agent: str,
        body: str = "",
        src_ip: str = "",
        dst_ip: str = "",
        response_code: int = 0
    ) -> Dict[str, Any]:
        """
        Analyze an HTTP request for C2 indicators.

        Args:
            method: HTTP method (GET, POST, etc.)
            uri: Request URI/path
            host: Host header value
            user_agent: User-Agent header value
            body: Request/response body
            src_ip: Source IP address
            dst_ip: Destination IP address
            response_code: HTTP response code

        Returns:
            dict: Analysis results with detected indicators
        """
        indicators = []
        suspicion_score = 0
        families_detected = set()

        # Normalize inputs
        uri = uri.lower() if uri else ""
        user_agent = user_agent or ""
        body = body or ""
        method = method.upper() if method else "GET"

        # Check URI against known C2 endpoints
        for endpoint, info in C2_ENDPOINT_PATTERNS.items():
            if endpoint.lower() in uri:
                families_detected.add(info["family"])
                indicators.append({
                    "type": "c2_endpoint",
                    "endpoint": endpoint,
                    "family": info["family"],
                    "description": info["description"],
                    "confidence": info["confidence"],
                })
                suspicion_score += info["confidence"] // 2

        # Check User-Agent patterns
        for ua_pattern in SUSPICIOUS_USER_AGENTS:
            if re.search(ua_pattern["pattern"], user_agent, re.IGNORECASE):
                families_detected.add(ua_pattern["family"])
                indicators.append({
                    "type": "suspicious_user_agent",
                    "user_agent": user_agent[:100],
                    "family": ua_pattern["family"],
                    "description": ua_pattern["description"],
                    "confidence": ua_pattern["confidence"],
                })
                suspicion_score += ua_pattern["confidence"] // 3
                break  # Only match first pattern

        # Check for payload patterns in body
        for payload_pattern in PAYLOAD_PATTERNS:
            if re.search(payload_pattern["pattern"], body, re.IGNORECASE):
                families_detected.add(payload_pattern["family"])
                indicators.append({
                    "type": "payload_pattern",
                    "family": payload_pattern["family"],
                    "description": payload_pattern["description"],
                    "confidence": payload_pattern["confidence"],
                })
                suspicion_score += payload_pattern["confidence"] // 2

        # Check for encoded data in URI
        encoding_result = self._detect_encoded_uri(uri)
        if encoding_result["detected"]:
            indicators.append({
                "type": "encoded_uri",
                "encoding": encoding_result["encoding"],
                "description": f"Possible {encoding_result['encoding']} encoded data in URI",
                "entropy": encoding_result.get("entropy", 0),
            })
            suspicion_score += 20

        # Check for suspicious POST with small response
        if method == "POST" and response_code == 200:
            # Could indicate C2 check-in
            if len(body) > 0 and len(body) < 100:
                indicators.append({
                    "type": "suspicious_post",
                    "description": "POST request with small body - possible C2 check-in",
                    "confidence": 40,
                })
                suspicion_score += 15

        # Determine classification
        if suspicion_score >= 60:
            classification = "HIGH"
        elif suspicion_score >= 35:
            classification = "MEDIUM"
        elif suspicion_score > 0:
            classification = "LOW"
        else:
            classification = "NONE"

        result = {
            "method": method,
            "uri": uri,
            "host": host,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "response_code": response_code,
            "suspicious": suspicion_score > 0,
            "suspicion_score": suspicion_score,
            "classification": classification,
            "families_detected": list(families_detected),
            "indicators": indicators,
        }

        # Store detection if suspicious
        if suspicion_score > 0:
            self.detections.append(result)
            self.requests[(src_ip, dst_ip)].append(result)

        return result

    def _detect_encoded_uri(self, uri: str) -> Dict[str, Any]:
        """
        Detect encoded data patterns in URI.

        Args:
            uri: Request URI

        Returns:
            dict: Detection results with encoding type and entropy
        """
        result = {
            "detected": False,
            "encoding": None,
            "entropy": 0.0,
        }

        if not uri or len(uri) < 20:
            return result

        # Extract query string or path parameters
        if "?" in uri:
            query_part = uri.split("?", 1)[1]
        else:
            query_part = uri.split("/")[-1]

        if not query_part or len(query_part) < 16:
            return result

        # Calculate entropy
        entropy = self._calculate_entropy(query_part)
        result["entropy"] = round(entropy, 2)

        # High entropy suggests encoded data
        if entropy >= 4.5:
            result["detected"] = True
            result["encoding"] = "high_entropy"

            # Try to identify specific encoding
            if re.match(r'^[0-9a-fA-F]+$', query_part):
                result["encoding"] = "hex"
            elif re.match(r'^[A-Za-z0-9+/=]+$', query_part) and len(query_part) % 4 == 0:
                result["encoding"] = "base64"

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

        freq = defaultdict(int)
        for char in text:
            freq[char] += 1

        length = len(text)
        entropy = 0.0

        for count in freq.values():
            if count > 0:
                prob = count / length
                entropy -= prob * math.log2(prob)

        return entropy

    def get_detections_summary(self) -> Dict[str, Any]:
        """
        Get summary of all HTTP C2 detections.

        Returns:
            dict: Summary with counts, families, and top endpoints
        """
        if not self.detections:
            return {
                "total_detections": 0,
                "high_risk": 0,
                "medium_risk": 0,
                "low_risk": 0,
                "families": [],
                "top_endpoints": [],
            }

        high_risk = sum(1 for d in self.detections if d["classification"] == "HIGH")
        medium_risk = sum(1 for d in self.detections if d["classification"] == "MEDIUM")
        low_risk = sum(1 for d in self.detections if d["classification"] == "LOW")

        # Count families
        family_counts: Dict[str, int] = defaultdict(int)
        endpoint_counts: Dict[str, int] = defaultdict(int)

        for detection in self.detections:
            for family in detection.get("families_detected", []):
                family_counts[family] += 1

            for indicator in detection.get("indicators", []):
                if indicator["type"] == "c2_endpoint":
                    endpoint_counts[indicator["endpoint"]] += 1

        return {
            "total_detections": len(self.detections),
            "high_risk": high_risk,
            "medium_risk": medium_risk,
            "low_risk": low_risk,
            "families": sorted(family_counts.items(), key=lambda x: x[1], reverse=True),
            "top_endpoints": sorted(endpoint_counts.items(), key=lambda x: x[1], reverse=True)[:10],
        }

    def clear(self) -> None:
        """Clear all stored data."""
        self.requests.clear()
        self.detections.clear()


def analyze_http_traffic(
    http_df,
    method_column: str = "METHOD",
    uri_column: str = "URI",
    host_column: str = "HOST",
    ua_column: str = "USER_AGENT",
    body_column: str = "BODY",
    src_column: str = "SRC_IP",
    dst_column: str = "DST_IP",
    code_column: str = "RESPONSE_CODE"
) -> List[Dict[str, Any]]:
    """
    Convenience function to analyze an HTTP DataFrame for C2 indicators.

    Args:
        http_df: pandas DataFrame with HTTP traffic data
        method_column: Column name for HTTP method
        uri_column: Column name for request URI
        host_column: Column name for Host header
        ua_column: Column name for User-Agent
        body_column: Column name for request/response body
        src_column: Column name for source IP
        dst_column: Column name for destination IP
        code_column: Column name for response code

    Returns:
        list: Analysis results for each suspicious request
    """
    detector = HTTPC2Detector()
    results = []

    if http_df is None or http_df.empty:
        return results

    for _, row in http_df.iterrows():
        method = str(row.get(method_column, "GET"))
        uri = str(row.get(uri_column, ""))
        host = str(row.get(host_column, ""))
        user_agent = str(row.get(ua_column, ""))
        body = str(row.get(body_column, ""))
        src_ip = str(row.get(src_column, ""))
        dst_ip = str(row.get(dst_column, ""))

        try:
            response_code = int(row.get(code_column, 0))
        except (ValueError, TypeError):
            response_code = 0

        result = detector.analyze_http_request(
            method=method,
            uri=uri,
            host=host,
            user_agent=user_agent,
            body=body,
            src_ip=src_ip,
            dst_ip=dst_ip,
            response_code=response_code
        )

        if result["suspicious"]:
            results.append(result)

    return results


if __name__ == "__main__":
    print("=== HTTP C2 Detection Module ===\n")

    detector = HTTPC2Detector()

    # Test HTTP requests
    test_requests = [
        {
            "method": "GET",
            "uri": "/jquery-3.3.1.min.js",
            "host": "suspicious.com",
            "user_agent": "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)",
            "body": "",
        },
        {
            "method": "POST",
            "uri": "/gate.php",
            "host": "evil-c2.net",
            "user_agent": "Mozilla/5.0",
            "body": "botid=12345&cmd=checkin",
        },
        {
            "method": "GET",
            "uri": "/INITJM",
            "host": "msf-server.com",
            "user_agent": "Java/1.8.0_201",
            "body": "",
        },
        {
            "method": "GET",
            "uri": "/index.html",
            "host": "legitimate-site.com",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0",
            "body": "",
        },
        {
            "method": "POST",
            "uri": "/api/data",
            "host": "data-server.com",
            "user_agent": "python-requests/2.25.1",
            "body": "<mcconf>malware_config_here</mcconf>",
        },
        {
            "method": "GET",
            "uri": "/loader?data=SGVsbG8gV29ybGQhIQ==",
            "host": "payload-server.net",
            "user_agent": "Mozilla/5.0",
            "body": "",
        },
    ]

    print("Testing HTTP request analysis:\n")

    for req in test_requests:
        result = detector.analyze_http_request(
            method=req["method"],
            uri=req["uri"],
            host=req["host"],
            user_agent=req["user_agent"],
            body=req["body"],
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1"
        )

        status = "⚠️ " if result["suspicious"] else "✓ "
        print(f"{status}{req['method']} {req['host']}{req['uri'][:40]}")

        if result["suspicious"]:
            print(f"   Score: {result['suspicion_score']} ({result['classification']})")
            print(f"   Families: {', '.join(result['families_detected'])}")
            for indicator in result["indicators"]:
                print(f"   - {indicator['type']}: {indicator.get('description', '')}")
        print()

    # Print summary
    summary = detector.get_detections_summary()
    print("=== Summary ===")
    print(f"Total detections: {summary['total_detections']}")
    print(f"  High risk: {summary['high_risk']}")
    print(f"  Medium risk: {summary['medium_risk']}")
    print(f"  Low risk: {summary['low_risk']}")
    print(f"\nFamilies detected: {dict(summary['families'])}")
    print(f"Top endpoints: {dict(summary['top_endpoints'])}")

    print("\n=== Known C2 Endpoints ===")
    for endpoint, info in list(C2_ENDPOINT_PATTERNS.items())[:10]:
        print(f"  {endpoint}: {info['family']} ({info['confidence']}%)")
    print(f"  ... and {len(C2_ENDPOINT_PATTERNS) - 10} more")

    print("\n✓ HTTP C2 detection module ready")
