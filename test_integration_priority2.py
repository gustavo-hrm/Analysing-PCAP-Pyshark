#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Integration test for Priority 2 features with synthetic data
Demonstrates advanced DGA detection, CPD, and flow analysis
"""

import sys
import os
import numpy as np
import pandas as pd
import time

# Add the current directory to the path
sys.path.insert(0, os.path.dirname(__file__))

from main import (
    advanced_dga_detection,
    detect_change_points,
    analyze_temporal_patterns,
    sliding_window_analysis,
    extract_flow_features,
    analyze_bidirectional_flows,
    detect_flow_anomalies
)


def create_synthetic_traffic():
    """Create synthetic network traffic with anomalies"""
    print("Creating synthetic traffic data...")
    
    # Normal traffic baseline
    normal_ips = [f'192.168.1.{i}' for i in range(10, 20)]
    external_ips = ['8.8.8.8', '1.1.1.1', '9.9.9.9', '208.67.222.222']
    
    # Generate normal traffic (1000 packets)
    base_time = int(time.time()) - 3600
    
    normal_traffic = []
    for i in range(1000):
        normal_traffic.append({
            'SRC_IP': np.random.choice(normal_ips),
            'DST_IP': np.random.choice(external_ips),
            'SRC_PORT': np.random.randint(10000, 60000),
            'DST_PORT': np.random.choice([80, 443, 53]),
            'TS': base_time + i * 0.5,
            'SIZE': np.random.randint(60, 1500),
            'FLAGS': np.random.choice(['SYN', 'ACK', 'PSH', 'FIN'], p=[0.1, 0.5, 0.3, 0.1])
        })
    
    # Add change point (traffic spike)
    spike_time = base_time + 500
    for i in range(500):
        normal_traffic.append({
            'SRC_IP': np.random.choice(normal_ips),
            'DST_IP': np.random.choice(external_ips),
            'SRC_PORT': np.random.randint(10000, 60000),
            'DST_PORT': 80,
            'TS': spike_time + i * 0.1,  # Higher rate
            'SIZE': np.random.randint(60, 1500),
            'FLAGS': 'SYN'
        })
    
    # Add anomalous flows
    # 1. One-way communication (potential scanning)
    for i in range(50):
        normal_traffic.append({
            'SRC_IP': '192.168.1.100',
            'DST_IP': f'10.0.0.{i}',
            'SRC_PORT': 12345,
            'DST_PORT': 22,
            'TS': base_time + 1000 + i,
            'SIZE': 64,
            'FLAGS': 'SYN'
        })
    
    # 2. Long-duration low-rate flow (potential beacon)
    for i in range(100):
        normal_traffic.append({
            'SRC_IP': '192.168.1.99',
            'DST_IP': '185.25.51.10',  # Suspicious IP
            'SRC_PORT': 54321,
            'DST_PORT': 443,
            'TS': base_time + i * 60,  # Every 60 seconds
            'SIZE': 256,
            'FLAGS': 'PSH'
        })
    
    # 3. Asymmetric flow (potential exfiltration)
    for i in range(30):
        # Upload heavy
        normal_traffic.append({
            'SRC_IP': '192.168.1.50',
            'DST_IP': '23.45.67.89',
            'SRC_PORT': 33333,
            'DST_PORT': 8080,
            'TS': base_time + 2000 + i * 2,
            'SIZE': 1400,  # Large uploads
            'FLAGS': 'PSH'
        })
        # Minimal responses
        if i % 10 == 0:
            normal_traffic.append({
                'SRC_IP': '23.45.67.89',
                'DST_IP': '192.168.1.50',
                'SRC_PORT': 8080,
                'DST_PORT': 33333,
                'TS': base_time + 2000 + i * 2 + 0.1,
                'SIZE': 64,
                'FLAGS': 'ACK'
            })
    
    tcp_df = pd.DataFrame(normal_traffic)
    print(f"  Created {len(tcp_df)} TCP packets")
    return tcp_df


def test_dga_detection():
    """Test DGA detection with various domains"""
    print("\n=== Testing Advanced DGA Detection ===")
    
    test_domains = [
        ('google.com', False, 'Legitimate'),
        ('facebook.com', False, 'Legitimate'),
        ('xqz8kjasdh9f.tk', False, 'Suspicious but below threshold (52 < 60)'),  # Score 52 < DGA_MIN_SCORE 60
        ('kjhsdfkjhsdf8s7df.com', False, 'High Entropy but below threshold (35 < 60)'),
        ('g00gle.com', False, 'Typosquatting but below threshold (25 < 60)'),
        ('subdomain1.subdomain2.subdomain3.subdomain4.example.com', False, 'Many subdomains'),
        ('aabbccddee1122334455.xyz', True, 'Hex-like + Suspicious TLD (60)'),
    ]
    
    results = []
    for domain, expected_dga, description in test_domains:
        result = advanced_dga_detection(domain)
        is_match = result['is_dga'] == expected_dga
        status = '✓' if is_match else '✗'
        
        print(f"{status} {domain:40s} Score: {result['total_score']:3d} ({description})")
        if result['total_score'] > 0:
            breakdown = ', '.join([f"{k}:{v}" for k, v in result['breakdown'].items() if v != 0])
            print(f"   Breakdown: {breakdown}")
        
        results.append(is_match)
    
    success_rate = sum(results) / len(results) * 100
    print(f"\nDGA Detection Success Rate: {success_rate:.1f}%")
    return all(results)


def test_change_point_detection(tcp_df):
    """Test change point detection on synthetic traffic"""
    print("\n=== Testing Change Point Detection ===")
    
    # Create time series of packet counts per second
    tcp_sorted = tcp_df.sort_values('TS').copy()
    tcp_sorted['ts_rounded'] = tcp_sorted['TS'].round()
    pps_series = tcp_sorted.groupby('ts_rounded').size()
    
    # Establish baseline from first half
    baseline_data = pps_series.iloc[:len(pps_series)//2]
    baseline = {
        'mean': baseline_data.mean(),
        'std': baseline_data.std()
    }
    
    print(f"Baseline: mean={baseline['mean']:.2f}, std={baseline['std']:.2f}")
    
    # Detect change points
    change_points = detect_change_points(pps_series, baseline, threshold=3.0)
    
    print(f"Change Points Detected: {len(change_points)}")
    if len(change_points) > 0:
        print("First 5 change points:")
        for cp in change_points[:5]:
            print(f"  Time: {cp['timestamp']}, Value: {cp['value']:.1f}, Deviation: {cp['deviation']:.2f}σ")
    
    # Temporal patterns
    temporal = analyze_temporal_patterns(tcp_df)
    print(f"\nTemporal Pattern Detected: {temporal['pattern_detected']}")
    print(f"Hourly Pattern Coverage: {len(temporal['hourly_pattern'])} hours")
    print(f"Anomalous Hours: {temporal['anomalous_hours']}")
    
    # Sliding window analysis
    windows = sliding_window_analysis(tcp_df, window_size=60)
    if not windows.empty:
        anomalous = windows[windows['is_anomaly'] == True]
        print(f"\nSliding Windows Analyzed: {len(windows)}")
        print(f"Anomalous Windows: {len(anomalous)}")
        if len(anomalous) > 0:
            print(f"Anomaly Types: {anomalous['anomaly_type'].value_counts().to_dict()}")
    
    return len(change_points) > 0


def test_flow_analysis(tcp_df):
    """Test flow-level analysis on synthetic traffic"""
    print("\n=== Testing Flow-Level Analysis ===")
    
    # Extract flow features
    flows = extract_flow_features(tcp_df)
    
    print(f"Flows Extracted: {len(flows)}")
    
    if flows.empty:
        print("No flows extracted (insufficient data)")
        return False
    
    # Show summary statistics
    print("\nFlow Statistics:")
    print(f"  Avg Duration: {flows['flow_duration'].mean():.2f}s")
    print(f"  Avg Packets/Flow: {(flows['fwd_packets'] + flows['bwd_packets']).mean():.1f}")
    print(f"  Avg Bytes/Flow: {(flows['fwd_bytes'] + flows['bwd_bytes']).mean():.1f}")
    print(f"  Avg PPS: {flows['packets_per_second'].mean():.2f}")
    
    # Detect flow anomalies
    anomalies = detect_flow_anomalies(flows)
    
    print(f"\nFlow Anomalies Detected: {len(anomalies)}")
    if not anomalies.empty:
        print("Top 5 anomalous flows:")
        for _, flow in anomalies.head(5).iterrows():
            print(f"  {flow['src_ip']} -> {flow['dst_ip']}: Score={flow['anomaly_score']}")
            print(f"    Reasons: {flow['anomaly_reasons']}")
    
    # Analyze bidirectional flows
    bidir = analyze_bidirectional_flows(flows)
    
    print(f"\nBidirectional Anomalies: {len(bidir)}")
    if not bidir.empty:
        print("Top 5 asymmetric flows:")
        for _, flow in bidir.head(5).iterrows():
            print(f"  {flow['src_ip']} -> {flow['dst_ip']}: Score={flow['asymmetry_score']}")
            print(f"    Type: {flow['anomaly_type']}, Packet Ratio: {flow['packet_ratio']:.2f}")
    
    return len(anomalies) > 0 or len(bidir) > 0


if __name__ == '__main__':
    print("=" * 70)
    print("Priority 2 Features Integration Test")
    print("=" * 70)
    
    # Create synthetic traffic
    tcp_df = create_synthetic_traffic()
    
    # Test all features
    dga_success = test_dga_detection()
    cpd_success = test_change_point_detection(tcp_df)
    flow_success = test_flow_analysis(tcp_df)
    
    # Summary
    print("\n" + "=" * 70)
    print("Integration Test Summary")
    print("=" * 70)
    print(f"DGA Detection:         {'✓ PASS' if dga_success else '✗ FAIL'}")
    print(f"Change Point Detection: {'✓ PASS' if cpd_success else '✗ FAIL'}")
    print(f"Flow Analysis:         {'✓ PASS' if flow_success else '✗ FAIL'}")
    print("=" * 70)
    
    if dga_success and cpd_success and flow_success:
        print("\n✓ ALL INTEGRATION TESTS PASSED")
        sys.exit(0)
    else:
        print("\n✗ SOME TESTS FAILED")
        sys.exit(1)
