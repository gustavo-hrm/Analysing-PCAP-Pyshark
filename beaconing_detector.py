#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
C2 Beaconing Detection Module
==============================

This module provides statistical analysis for detecting C2 beaconing patterns
in network traffic. It analyzes connection intervals to identify regular
communication patterns that may indicate command and control activity.

Features:
- Time-series analysis of connection intervals
- Jitter calculation and classification
- Known C2 framework timing pattern detection
- Statistical regularity scoring

Usage:
    from beaconing_detector import BeaconingDetector, analyze_traffic_for_beaconing

    # Create detector and add connections
    detector = BeaconingDetector()
    detector.add_connection("192.168.1.100", "10.0.0.1", 443, 1609459200.0)
    detector.add_connection("192.168.1.100", "10.0.0.1", 443, 1609459260.0)
    
    # Analyze for beaconing
    results = detector.analyze_beaconing()
    for result in results:
        print(f"{result['src_ip']} -> {result['dst_ip']}: {result['classification']}")
"""

import math
from collections import defaultdict
from typing import Dict, List, Optional, Any, Tuple


# -----------------------
# Known Beacon Intervals
# -----------------------
# Common beacon intervals (in seconds) used by various C2 frameworks

KNOWN_BEACON_INTERVALS: Dict[int, Dict[str, Any]] = {
    60: {
        "frameworks": ["Cobalt Strike default", "Generic malware"],
        "description": "1-minute beacon interval",
        "suspicion": "HIGH",
    },
    300: {
        "frameworks": ["Cobalt Strike 5-min", "Empire default"],
        "description": "5-minute beacon interval",
        "suspicion": "HIGH",
    },
    600: {
        "frameworks": ["Sliver default", "Low-and-slow C2"],
        "description": "10-minute beacon interval",
        "suspicion": "MEDIUM",
    },
    900: {
        "frameworks": ["Mythic default"],
        "description": "15-minute beacon interval",
        "suspicion": "MEDIUM",
    },
    1800: {
        "frameworks": ["Stealth C2"],
        "description": "30-minute beacon interval",
        "suspicion": "MEDIUM",
    },
    3600: {
        "frameworks": ["Very slow beacon"],
        "description": "1-hour beacon interval",
        "suspicion": "LOW",
    },
}


# -----------------------
# Jitter Thresholds
# -----------------------
# Jitter coefficient thresholds for classification

JITTER_THRESHOLDS: Dict[str, Dict[str, Any]] = {
    "perfect": {
        "max_jitter": 0.02,  # <2% jitter
        "suspicion": "CRITICAL",
        "description": "Nearly perfect timing - very suspicious, likely automated",
    },
    "low": {
        "max_jitter": 0.10,  # <10% jitter
        "suspicion": "HIGH",
        "description": "Low jitter - suspicious, likely C2 beacon",
    },
    "medium": {
        "max_jitter": 0.25,  # <25% jitter
        "suspicion": "MEDIUM",
        "description": "Medium jitter - possibly suspicious, could be C2 with jitter",
    },
    "high": {
        "max_jitter": 0.50,  # <50% jitter
        "suspicion": "LOW",
        "description": "High jitter - less suspicious, may be legitimate",
    },
}


class BeaconingDetector:
    """
    C2 Beaconing Detection Class.

    Collects connection data and performs statistical analysis to detect
    regular beaconing patterns indicative of C2 communication.
    """

    def __init__(self):
        """Initialize the beaconing detector."""
        # Store connections: {(src_ip, dst_ip, dst_port): [timestamps]}
        self.connections: Dict[Tuple[str, str, int], List[float]] = defaultdict(list)

    def add_connection(
        self,
        src_ip: str,
        dst_ip: str,
        dst_port: int,
        timestamp: float
    ) -> None:
        """
        Record a connection for beaconing analysis.

        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address
            dst_port: Destination port
            timestamp: Unix timestamp of the connection
        """
        key = (src_ip, dst_ip, dst_port)
        self.connections[key].append(timestamp)

    def analyze_beaconing(self, min_connections: int = 5) -> List[Dict[str, Any]]:
        """
        Analyze all recorded connections for beaconing patterns.

        Args:
            min_connections: Minimum number of connections required for analysis

        Returns:
            list: List of detection results for each connection tuple
        """
        results = []

        for (src_ip, dst_ip, dst_port), timestamps in self.connections.items():
            if len(timestamps) < min_connections:
                continue

            # Sort timestamps
            sorted_timestamps = sorted(timestamps)

            # Analyze intervals
            interval_analysis = self._analyze_intervals(sorted_timestamps)

            if interval_analysis:
                # Detect sleep patterns
                sleep_patterns = self.detect_sleep_patterns(sorted_timestamps)

                result = {
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "connection_count": len(timestamps),
                    "time_span_seconds": sorted_timestamps[-1] - sorted_timestamps[0],
                    **interval_analysis,
                    "sleep_patterns": sleep_patterns,
                }
                results.append(result)

        # Sort by suspicion level (most suspicious first)
        suspicion_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        results.sort(key=lambda x: suspicion_order.get(x.get("jitter_classification", "LOW"), 4))

        return results

    def _analyze_intervals(
        self,
        timestamps: List[float]
    ) -> Optional[Dict[str, Any]]:
        """
        Perform statistical analysis on connection intervals.

        Args:
            timestamps: Sorted list of connection timestamps

        Returns:
            dict: Analysis results including mean, stddev, jitter, etc.
        """
        if len(timestamps) < 2:
            return None

        # Calculate intervals
        intervals = []
        for i in range(1, len(timestamps)):
            interval = timestamps[i] - timestamps[i - 1]
            if interval > 0:
                intervals.append(interval)

        if not intervals:
            return None

        # Calculate statistics
        n = len(intervals)
        mean_interval = sum(intervals) / n

        if mean_interval == 0:
            return None

        # Standard deviation
        variance = sum((x - mean_interval) ** 2 for x in intervals) / n
        std_dev = math.sqrt(variance)

        # Jitter coefficient (coefficient of variation)
        jitter_coefficient = std_dev / mean_interval if mean_interval > 0 else float('inf')

        # Regularity score (higher = more regular)
        regularity_score = self._calculate_regularity_score(intervals)

        # Classify jitter level
        jitter_classification = "high"
        jitter_suspicion = "LOW"
        jitter_description = "High jitter - likely legitimate"

        for level, thresholds in sorted(
            JITTER_THRESHOLDS.items(),
            key=lambda x: x[1]["max_jitter"]
        ):
            if jitter_coefficient <= thresholds["max_jitter"]:
                jitter_classification = level
                jitter_suspicion = thresholds["suspicion"]
                jitter_description = thresholds["description"]
                break

        # Check for known beacon intervals
        matched_interval = None
        for known_interval, info in KNOWN_BEACON_INTERVALS.items():
            # Allow 10% tolerance
            if abs(mean_interval - known_interval) <= known_interval * 0.1:
                matched_interval = {
                    "interval": known_interval,
                    "frameworks": info["frameworks"],
                    "description": info["description"],
                }
                break

        return {
            "mean_interval": round(mean_interval, 2),
            "std_deviation": round(std_dev, 2),
            "jitter_coefficient": round(jitter_coefficient, 4),
            "jitter_classification": jitter_classification,
            "jitter_suspicion": jitter_suspicion,
            "jitter_description": jitter_description,
            "regularity_score": round(regularity_score, 2),
            "matched_beacon_interval": matched_interval,
            "interval_count": n,
            "min_interval": round(min(intervals), 2),
            "max_interval": round(max(intervals), 2),
        }

    def _calculate_regularity_score(self, intervals: List[float]) -> float:
        """
        Calculate regularity score using autocorrelation-like analysis.

        A higher score indicates more regular timing patterns.

        Args:
            intervals: List of connection intervals

        Returns:
            float: Regularity score (0-100)
        """
        if len(intervals) < 3:
            return 0.0

        n = len(intervals)
        mean_interval = sum(intervals) / n

        if mean_interval == 0:
            return 0.0

        # Calculate coefficient of variation
        variance = sum((x - mean_interval) ** 2 for x in intervals) / n
        std_dev = math.sqrt(variance)
        cv = std_dev / mean_interval if mean_interval > 0 else float('inf')

        # Convert CV to regularity score (inverse relationship)
        # Perfect regularity (cv=0) -> score=100
        # High variation (cv>=1) -> score approaches 0
        if cv >= 1:
            score = 0.0
        else:
            score = (1 - cv) * 100

        return max(0.0, min(100.0, score))

    def detect_sleep_patterns(
        self,
        timestamps: List[float]
    ) -> Dict[str, Any]:
        """
        Detect C2 sleep/jitter patterns in connection timing.

        Identifies patterns like:
        - Regular sleep with random jitter
        - Multiple sleep intervals (e.g., fast during day, slow at night)
        - Burst patterns followed by silence

        Args:
            timestamps: Sorted list of connection timestamps

        Returns:
            dict: Detected sleep patterns and analysis
        """
        if len(timestamps) < 3:
            return {"detected": False, "patterns": []}

        intervals = []
        for i in range(1, len(timestamps)):
            intervals.append(timestamps[i] - timestamps[i - 1])

        if not intervals:
            return {"detected": False, "patterns": []}

        patterns = []

        # Check for consistent sleep interval
        mean_interval = sum(intervals) / len(intervals)
        if mean_interval > 10:  # At least 10 seconds
            consistent_count = sum(
                1 for i in intervals
                if abs(i - mean_interval) <= mean_interval * 0.3
            )
            consistency_ratio = consistent_count / len(intervals)

            if consistency_ratio >= 0.7:
                patterns.append({
                    "type": "consistent_sleep",
                    "interval": round(mean_interval, 2),
                    "consistency": round(consistency_ratio * 100, 1),
                })

        # Check for burst pattern (multiple connections in short time, then gap)
        bursts = []
        current_burst = []

        for i, ts in enumerate(timestamps):
            if not current_burst:
                current_burst = [ts]
            elif ts - current_burst[-1] <= 5:  # Within 5 seconds = same burst
                current_burst.append(ts)
            else:
                if len(current_burst) >= 3:
                    bursts.append(current_burst)
                current_burst = [ts]

        if len(current_burst) >= 3:
            bursts.append(current_burst)

        if len(bursts) >= 2:
            patterns.append({
                "type": "burst_pattern",
                "burst_count": len(bursts),
                "avg_burst_size": round(sum(len(b) for b in bursts) / len(bursts), 1),
            })

        # Check for long gaps (possibly indicating sleep periods)
        long_gaps = [i for i in intervals if i > 600]  # > 10 minutes
        if long_gaps:
            patterns.append({
                "type": "long_gaps",
                "count": len(long_gaps),
                "max_gap": round(max(long_gaps), 2),
                "avg_gap": round(sum(long_gaps) / len(long_gaps), 2),
            })

        return {
            "detected": len(patterns) > 0,
            "patterns": patterns,
        }

    def clear(self) -> None:
        """Clear all recorded connections."""
        self.connections.clear()


def analyze_traffic_for_beaconing(
    tcp_df,
    min_connections: int = 5,
    time_column: str = "TIMESTAMP",
    src_column: str = "SRC_IP",
    dst_column: str = "DST_IP",
    port_column: str = "DST_PORT"
) -> List[Dict[str, Any]]:
    """
    Convenience function to analyze a TCP DataFrame for beaconing.

    Args:
        tcp_df: pandas DataFrame with TCP connection data
        min_connections: Minimum connections required for analysis
        time_column: Column name for timestamps
        src_column: Column name for source IP
        dst_column: Column name for destination IP
        port_column: Column name for destination port

    Returns:
        list: Beaconing detection results
    """
    detector = BeaconingDetector()

    if tcp_df is None or tcp_df.empty:
        return []

    # Check for required columns
    required_cols = [src_column, dst_column, port_column]
    missing_cols = [c for c in required_cols if c not in tcp_df.columns]
    if missing_cols:
        print(f"[BeaconingDetector] Warning: Missing columns: {missing_cols}")
        return []

    # Add connections
    for _, row in tcp_df.iterrows():
        src_ip = str(row.get(src_column, ""))
        dst_ip = str(row.get(dst_column, ""))

        try:
            dst_port = int(row.get(port_column, 0))
        except (ValueError, TypeError):
            dst_port = 0

        # Get timestamp (use index or dedicated column)
        if time_column in tcp_df.columns:
            try:
                timestamp = float(row.get(time_column, 0))
            except (ValueError, TypeError):
                timestamp = float(row.name) if hasattr(row, 'name') else 0
        else:
            timestamp = float(row.name) if hasattr(row, 'name') else 0

        if src_ip and dst_ip:
            detector.add_connection(src_ip, dst_ip, dst_port, timestamp)

    return detector.analyze_beaconing(min_connections=min_connections)


if __name__ == "__main__":
    print("=== C2 Beaconing Detection Module ===\n")

    # Test with synthetic data
    print("Testing with synthetic beacon data...")

    detector = BeaconingDetector()

    # Simulate Cobalt Strike-like beacon (60 second interval with small jitter)
    import time
    base_time = time.time()

    # Add 10 connections with ~60 second intervals
    for i in range(10):
        jitter = (i % 3) * 2 - 2  # -2, 0, +2 seconds jitter
        detector.add_connection(
            "192.168.1.100",
            "10.0.0.1",
            443,
            base_time + (i * 60) + jitter
        )

    # Add some random traffic (high jitter)
    import random
    for i in range(15):
        detector.add_connection(
            "192.168.1.100",
            "8.8.8.8",
            53,
            base_time + random.uniform(0, 900)
        )

    # Analyze
    results = detector.analyze_beaconing(min_connections=5)

    print(f"\nFound {len(results)} connection patterns:\n")

    for result in results:
        print(f"  {result['src_ip']} -> {result['dst_ip']}:{result['dst_port']}")
        print(f"    Connections: {result['connection_count']}")
        print(f"    Mean interval: {result['mean_interval']:.1f}s")
        print(f"    Jitter: {result['jitter_coefficient']:.2%} ({result['jitter_classification']})")
        print(f"    Suspicion: {result['jitter_suspicion']}")
        print(f"    Regularity score: {result['regularity_score']:.1f}/100")

        if result.get("matched_beacon_interval"):
            matched = result["matched_beacon_interval"]
            print(f"    ⚠️  Matched known interval: {matched['interval']}s")
            print(f"       Frameworks: {', '.join(matched['frameworks'])}")

        if result["sleep_patterns"]["detected"]:
            print(f"    Sleep patterns: {result['sleep_patterns']['patterns']}")

        print()

    # Print known intervals
    print("=== Known Beacon Intervals ===")
    for interval, info in sorted(KNOWN_BEACON_INTERVALS.items()):
        print(f"  {interval}s: {', '.join(info['frameworks'])} ({info['suspicion']})")

    print("\n✓ Beaconing detection module ready")
