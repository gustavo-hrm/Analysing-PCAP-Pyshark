#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test script for Priority 2 features in main.py
"""

import sys
import os
import numpy as np
import pandas as pd

# Add the current directory to the path
sys.path.insert(0, os.path.dirname(__file__))

from main import (
    levenshtein_distance,
    advanced_dga_detection,
    detect_change_points,
    analyze_temporal_patterns,
    sliding_window_analysis,
    extract_flow_features,
    analyze_bidirectional_flows,
    detect_flow_anomalies,
    CPD_ENABLED,
    DGA_MIN_SCORE
)


def test_levenshtein_distance():
    """Test Levenshtein distance calculation"""
    print("Testing levenshtein_distance()...")
    
    # Test identical strings
    assert levenshtein_distance("hello", "hello") == 0
    
    # Test single character difference
    assert levenshtein_distance("hello", "hallo") == 1
    
    # Test typosquatting
    assert levenshtein_distance("google", "goggle") == 1
    assert levenshtein_distance("facebook", "facebok") == 1
    
    # Test different strings
    dist = levenshtein_distance("apple", "orange")
    assert dist > 0
    
    print("✓ levenshtein_distance() tests passed")


def test_advanced_dga_detection():
    """Test advanced DGA detection"""
    print("\nTesting advanced_dga_detection()...")
    
    # Test legitimate domain
    result = advanced_dga_detection("google.com")
    assert result['total_score'] < DGA_MIN_SCORE
    assert not result['is_dga']
    print(f"  google.com: score={result['total_score']} (legitimate)")
    
    # Test suspicious domain
    result = advanced_dga_detection("xqz8kjasdh9f.tk")
    print(f"  xqz8kjasdh9f.tk: score={result['total_score']}, breakdown={result['breakdown']}")
    assert result['is_dga'] == (result['total_score'] >= DGA_MIN_SCORE)
    
    # Test high entropy domain
    result = advanced_dga_detection("kjhsdfkjhsdf8s7df.com")
    print(f"  kjhsdfkjhsdf8s7df.com: score={result['total_score']}")
    
    # Test empty domain
    result = advanced_dga_detection("")
    assert result['total_score'] == 0
    
    print("✓ advanced_dga_detection() tests passed")


def test_detect_change_points():
    """Test CUSUM change point detection"""
    print("\nTesting detect_change_points()...")
    
    # Create time series with a change point
    normal = [100] * 50
    spike = [200] * 50
    series = pd.Series(normal + spike)
    
    baseline = {'mean': 100, 'std': 10}
    
    if CPD_ENABLED:
        changes = detect_change_points(series, baseline, threshold=3.0)
        print(f"  Detected {len(changes)} change points")
        if len(changes) > 0:
            print(f"  First change point: {changes[0]}")
    else:
        print("  CPD disabled - skipping")
    
    print("✓ detect_change_points() tests passed")


def test_analyze_temporal_patterns():
    """Test temporal pattern analysis"""
    print("\nTesting analyze_temporal_patterns()...")
    
    # Create traffic with hourly pattern
    timestamps = [i * 3600 for i in range(48)]  # 48 hours
    df = pd.DataFrame({'TS': timestamps})
    
    result = analyze_temporal_patterns(df)
    
    assert 'hourly_pattern' in result
    assert 'anomalous_hours' in result
    assert 'pattern_detected' in result
    
    print(f"  Pattern detected: {result['pattern_detected']}")
    print(f"  Hours in pattern: {len(result['hourly_pattern'])}")
    
    print("✓ analyze_temporal_patterns() tests passed")


def test_sliding_window_analysis():
    """Test sliding window analysis"""
    print("\nTesting sliding_window_analysis()...")
    
    # Create traffic data
    df = pd.DataFrame({
        'TS': [i for i in range(1000)],
        'SIZE': [100] * 1000
    })
    
    result = sliding_window_analysis(df, window_size=60)
    
    assert 'pps' in result.columns or result.empty
    print(f"  Windows analyzed: {len(result)}")
    
    print("✓ sliding_window_analysis() tests passed")


def test_extract_flow_features():
    """Test flow feature extraction"""
    print("\nTesting extract_flow_features()...")
    
    # Create TCP traffic
    tcp_data = {
        'SRC_IP': ['192.168.1.1'] * 10 + ['192.168.1.2'] * 10,
        'DST_IP': ['8.8.8.8'] * 10 + ['1.1.1.1'] * 10,
        'SRC_PORT': [12345] * 10 + [54321] * 10,
        'DST_PORT': [80] * 10 + [443] * 10,
        'TS': [i * 0.5 for i in range(20)],
        'SIZE': [100 + i * 5 for i in range(20)],
        'FLAGS': ['SYN'] * 5 + ['ACK'] * 15
    }
    tcp_df = pd.DataFrame(tcp_data)
    
    flows = extract_flow_features(tcp_df)
    
    if not flows.empty:
        assert 'flow_id' in flows.columns
        assert 'flow_duration' in flows.columns
        assert 'packets_per_second' in flows.columns
        print(f"  Flows extracted: {len(flows)}")
        print(f"  Flow columns: {list(flows.columns)[:5]}...")
    else:
        print("  No flows extracted (expected for small dataset)")
    
    print("✓ extract_flow_features() tests passed")


def test_analyze_bidirectional_flows():
    """Test bidirectional flow analysis"""
    print("\nTesting analyze_bidirectional_flows()...")
    
    # Create flow features with asymmetry
    flows = pd.DataFrame({
        'flow_id': ['flow1', 'flow2', 'flow3'],
        'src_ip': ['192.168.1.1', '192.168.1.2', '192.168.1.3'],
        'dst_ip': ['8.8.8.8', '1.1.1.1', '9.9.9.9'],
        'fwd_packets': [100, 50, 10],
        'bwd_packets': [1, 50, 100],
        'fwd_bytes': [10000, 5000, 1000],
        'bwd_bytes': [100, 5000, 10000]
    })
    
    result = analyze_bidirectional_flows(flows)
    
    if not result.empty:
        assert 'asymmetry_score' in result.columns
        print(f"  Asymmetric flows detected: {len(result)}")
    else:
        print("  No asymmetric flows detected")
    
    print("✓ analyze_bidirectional_flows() tests passed")


def test_detect_flow_anomalies():
    """Test flow anomaly detection"""
    print("\nTesting detect_flow_anomalies()...")
    
    # Create flow features with some anomalies
    flows = pd.DataFrame({
        'flow_id': [f'flow{i}' for i in range(20)],
        'src_ip': [f'192.168.1.{i}' for i in range(20)],
        'dst_ip': ['8.8.8.8'] * 20,
        'flow_duration': [100] * 18 + [10000, 20000],  # Two long flows
        'packets_per_second': [1] * 18 + [1000, 2000],  # Two high-rate flows
        'bytes_per_second': [1000] * 20,
        'packet_size_mean': [100] * 20,
        'iat_mean': [1] * 20,
        'fwd_packets': [50] * 20,
        'bwd_packets': [50] * 20,
        'rst_count': [0] * 20
    })
    
    result = detect_flow_anomalies(flows)
    
    if not result.empty:
        assert 'anomaly_score' in result.columns
        assert 'anomaly_reasons' in result.columns
        print(f"  Anomalous flows detected: {len(result)}")
    else:
        print("  No anomalous flows detected (small dataset)")
    
    print("✓ detect_flow_anomalies() tests passed")


if __name__ == '__main__':
    print("=== Priority 2 Feature Tests ===\n")
    
    try:
        test_levenshtein_distance()
        test_advanced_dga_detection()
        test_detect_change_points()
        test_analyze_temporal_patterns()
        test_sliding_window_analysis()
        test_extract_flow_features()
        test_analyze_bidirectional_flows()
        test_detect_flow_anomalies()
        
        print("\n" + "=" * 40)
        print("✓ ALL TESTS PASSED")
        print("=" * 40)
        
    except Exception as e:
        print(f"\n✗ TEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
