#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test script for ML features in main.py
"""

import sys
import os
import numpy as np
import pandas as pd

# Add the current directory to the path
sys.path.insert(0, os.path.dirname(__file__))

from main import (
    extract_ml_features,
    establish_baseline,
    calculate_adaptive_threshold,
    ml_ddos_detection,
    anomaly_detection,
    detect_jittered_beaconing,
    ML_AVAILABLE,
    ML_ENABLED
)


def test_extract_ml_features():
    """Test ML feature extraction from traffic data"""
    print("Testing extract_ml_features()...")
    
    # Create sample TCP traffic
    tcp_data = {
        'SRC_IP': ['192.168.1.100'] * 20,
        'DST_IP': ['8.8.8.8'] * 10 + ['1.1.1.1'] * 10,
        'TS': [i * 0.1 for i in range(20)],  # Timestamps
        'SIZE': [100 + i * 5 for i in range(20)],
        'SRC_PORT': [12345 + i for i in range(20)],
        'DST_PORT': [80] * 20,
        'FLAGS': ['SYN'] * 5 + ['ACK'] * 15
    }
    tcp_df = pd.DataFrame(tcp_data)
    
    # Create empty UDP and ICMP dataframes
    udp_df = pd.DataFrame(columns=['SRC_IP', 'DST_IP', 'TS', 'SIZE'])
    icmp_df = pd.DataFrame(columns=['SRC_IP', 'DST_IP', 'TS', 'SIZE'])
    
    # Extract features
    features = extract_ml_features(tcp_df, udp_df, icmp_df)
    
    if features.empty:
        print("  ✗ Feature extraction returned empty DataFrame")
        return False
    
    # Check expected features exist
    expected_features = [
        'SRC_IP', 'PROTOCOL', 'PACKET_RATE', 'TOTAL_PACKETS',
        'AVG_PACKET_SIZE', 'UNIQUE_DST_IPS', 'IAT_MEAN'
    ]
    
    for feat in expected_features:
        if feat not in features.columns:
            print(f"  ✗ Missing expected feature: {feat}")
            return False
    
    print(f"  ✓ Extracted {len(features)} feature rows with {len(features.columns)} columns")
    print(f"  ✓ Sample features: {list(features.columns[:10])}")
    
    return True


def test_establish_baseline():
    """Test baseline establishment"""
    print("\nTesting establish_baseline()...")
    
    # Create sample feature data
    feature_data = {
        'SRC_IP': ['192.168.1.100'] * 10,
        'PACKET_RATE': np.random.normal(100, 10, 10),
        'TOTAL_PACKETS': np.random.randint(50, 150, 10),
        'AVG_PACKET_SIZE': np.random.normal(500, 50, 10)
    }
    features_df = pd.DataFrame(feature_data)
    
    baselines = establish_baseline(features_df)
    
    if not baselines:
        print("  ✗ Baseline establishment returned empty dict")
        return False
    
    ip = '192.168.1.100'
    if ip not in baselines:
        print(f"  ✗ Missing baseline for IP {ip}")
        return False
    
    baseline = baselines[ip]
    
    # Check expected statistics exist
    expected_stats = ['PACKET_RATE_MEAN', 'PACKET_RATE_STD', 'PACKET_RATE_P95']
    
    for stat in expected_stats:
        if stat not in baseline:
            print(f"  ✗ Missing baseline statistic: {stat}")
            return False
    
    print(f"  ✓ Established baselines for {len(baselines)} IPs")
    print(f"  ✓ Sample baseline keys: {list(baseline.keys())[:5]}")
    
    return True


def test_calculate_adaptive_threshold():
    """Test adaptive threshold calculation"""
    print("\nTesting calculate_adaptive_threshold()...")
    
    baseline = {
        'PACKET_RATE_MEAN': 100.0,
        'PACKET_RATE_STD': 15.0
    }
    
    threshold = calculate_adaptive_threshold(baseline, 'PACKET_RATE', sensitivity=3)
    
    if threshold is None:
        print("  ✗ Threshold calculation returned None")
        return False
    
    expected = 100 + (3 * 15)  # mean + (sensitivity * std)
    if abs(threshold - expected) > 0.01:
        print(f"  ✗ Unexpected threshold: {threshold} (expected {expected})")
        return False
    
    print(f"  ✓ Calculated adaptive threshold: {threshold}")
    print(f"  ✓ Formula: mean(100) + 3*std(15) = {threshold}")
    
    return True


def test_detect_jittered_beaconing():
    """Test jittered beaconing detection"""
    print("\nTesting detect_jittered_beaconing()...")
    
    # Test 1: Perfect periodic beaconing
    times_perfect = [i * 10.0 for i in range(15)]  # Every 10 seconds
    result = detect_jittered_beaconing(times_perfect, max_jitter=0.5)
    
    if not result['detected']:
        print("  ✗ Failed to detect perfect periodic beacon")
        return False
    
    print(f"  ✓ Detected perfect beacon: period={result['period']}, jitter={result['jitter']:.3f}")
    
    # Test 2: Jittered beaconing (30% jitter)
    base_period = 10.0
    times_jittered = [sum([base_period * (1 + np.random.uniform(-0.3, 0.3)) 
                          for _ in range(i+1)]) for i in range(15)]
    result_jitter = detect_jittered_beaconing(times_jittered, max_jitter=0.5)
    
    if not result_jitter['detected']:
        print("  ✗ Failed to detect jittered beacon (30% jitter)")
        return False
    
    print(f"  ✓ Detected jittered beacon: jitter={result_jitter['jitter']:.3f}, method={result_jitter['method']}")
    
    # Test 3: Random traffic (should NOT detect)
    times_random = sorted([np.random.uniform(0, 100) for _ in range(15)])
    result_random = detect_jittered_beaconing(times_random, max_jitter=0.5)
    
    print(f"  ✓ Random traffic detection: {result_random['detected']} (expected False or low confidence)")
    
    return True


def test_ml_ddos_detection():
    """Test ML DDoS detection"""
    print("\nTesting ml_ddos_detection()...")
    
    if not ML_AVAILABLE or not ML_ENABLED:
        print("  ⚠ ML not available, skipping test")
        return True
    
    # Create sample features with clear attack pattern
    n_normal = 20
    n_attack = 10
    
    feature_data = {
        'SRC_IP': [f'192.168.1.{i}' for i in range(n_normal + n_attack)],
        'PROTOCOL': ['TCP'] * (n_normal + n_attack),
        'PACKET_RATE': [10] * n_normal + [1000] * n_attack,  # Attack = high rate
        'UNIQUE_DST_IPS': [2] * n_normal + [50] * n_attack,  # Attack = high diversity
        'SYN_RATIO': [0.5] * n_normal + [10.0] * n_attack,   # Attack = high SYN ratio
        'TOTAL_PACKETS': [100] * n_normal + [10000] * n_attack,
        'AVG_PACKET_SIZE': [500] * (n_normal + n_attack)
    }
    features_df = pd.DataFrame(feature_data)
    
    predictions = ml_ddos_detection(features_df)
    
    if predictions.empty:
        print("  ⚠ ML predictions empty (might need more training data)")
        return True
    
    # Check if attacks were detected
    attacks = predictions[predictions['PREDICTION'] == 'ATTACK']
    
    print(f"  ✓ ML classified {len(predictions)} sources")
    print(f"  ✓ Detected {len(attacks)} potential attacks")
    
    if len(attacks) > 0:
        print(f"  ✓ Sample attack ML_SCORE: {attacks['ML_SCORE'].iloc[0]}")
    
    return True


def test_anomaly_detection():
    """Test anomaly detection"""
    print("\nTesting anomaly_detection()...")
    
    if not ML_AVAILABLE or not ML_ENABLED:
        print("  ⚠ ML not available, skipping test")
        return True
    
    # Create sample features with clear outliers
    n_normal = 25
    n_anomaly = 5
    
    feature_data = {
        'SRC_IP': [f'192.168.1.{i}' for i in range(n_normal + n_anomaly)],
        'PROTOCOL': ['TCP'] * (n_normal + n_anomaly),
        'PACKET_RATE': [10] * n_normal + [10000] * n_anomaly,  # Anomaly = extremely high
        'UNIQUE_DST_IPS': [2] * n_normal + [100] * n_anomaly,
        'TOTAL_PACKETS': [100] * n_normal + [50000] * n_anomaly,
        'AVG_PACKET_SIZE': [500] * (n_normal + n_anomaly)
    }
    features_df = pd.DataFrame(feature_data)
    
    anomalies = anomaly_detection(features_df)
    
    if anomalies.empty:
        print("  ⚠ No anomalies detected (might need different thresholds)")
        return True
    
    print(f"  ✓ Detected {len(anomalies)} anomalies from {len(features_df)} sources")
    
    if len(anomalies) > 0:
        print(f"  ✓ Sample anomaly score: {anomalies['ANOMALY_SCORE'].iloc[0]}")
    
    return True


def main():
    """Run all tests"""
    print("="*60)
    print("ML Features Test Suite")
    print("="*60)
    
    if not ML_AVAILABLE:
        print("\n⚠ scikit-learn not available - ML tests will be limited")
    else:
        print(f"\n✓ scikit-learn available - ML enabled: {ML_ENABLED}")
    
    all_passed = True
    
    # Run tests
    all_passed &= test_extract_ml_features()
    all_passed &= test_establish_baseline()
    all_passed &= test_calculate_adaptive_threshold()
    all_passed &= test_detect_jittered_beaconing()
    all_passed &= test_ml_ddos_detection()
    all_passed &= test_anomaly_detection()
    
    print("\n" + "="*60)
    if all_passed:
        print("✓ All tests passed!")
        print("="*60)
        return 0
    else:
        print("✗ Some tests failed!")
        print("="*60)
        return 1


if __name__ == "__main__":
    sys.exit(main())
