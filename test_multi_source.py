#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test script for multi-source PCAP correlation features in main.py
"""

import sys
import os
import pandas as pd
import numpy as np

# Add the current directory to the path
sys.path.insert(0, os.path.dirname(__file__))

from main import (
    correlate_cross_source_c2,
    correlate_attack_patterns,
    detect_lateral_movement_across_sources,
    correlate_beacon_timing,
    parse_streams,
    MIN_SOURCES_FOR_CORRELATION,
    CORRELATION_TIME_WINDOW
)


def test_correlate_cross_source_c2():
    """Test cross-source C2 infrastructure correlation"""
    print("Testing correlate_cross_source_c2()...")
    
    # Create test data with shared C2 indicators across sources
    source_data = {
        'source1': {
            'c2_full': pd.DataFrame([
                {'INDICATOR': 'malicious.example.com', 'TYPE': 'C2 Domain', 'SCORE': 85, 'COUNT': 10},
                {'INDICATOR': '192.168.1.100', 'TYPE': 'C2 IP', 'SCORE': 90, 'COUNT': 5},
            ])
        },
        'source2': {
            'c2_full': pd.DataFrame([
                {'INDICATOR': 'malicious.example.com', 'TYPE': 'C2 Domain', 'SCORE': 80, 'COUNT': 8},
                {'INDICATOR': '10.0.0.50', 'TYPE': 'C2 IP', 'SCORE': 75, 'COUNT': 3},
            ])
        },
        'source3': {
            'c2_full': pd.DataFrame([
                {'INDICATOR': 'malicious.example.com', 'TYPE': 'C2 Domain', 'SCORE': 88, 'COUNT': 12},
            ])
        }
    }
    
    result = correlate_cross_source_c2(source_data)
    
    # Verify results
    assert isinstance(result, pd.DataFrame), "Result should be a DataFrame"
    assert not result.empty, "Result should not be empty with shared indicators"
    assert 'C2_INDICATOR' in result.columns, "Result should have C2_INDICATOR column"
    assert 'SOURCES' in result.columns, "Result should have SOURCES column"
    assert 'SOURCE_COUNT' in result.columns, "Result should have SOURCE_COUNT column"
    assert 'CONFIDENCE_SCORE' in result.columns, "Result should have CONFIDENCE_SCORE column"
    
    # Check that shared indicator is detected
    shared_indicators = result[result['C2_INDICATOR'] == 'malicious.example.com']
    assert len(shared_indicators) == 1, "Shared C2 indicator should be detected"
    assert shared_indicators.iloc[0]['SOURCE_COUNT'] == 3, "Should detect indicator in 3 sources"
    
    # Check confidence score increases with source count
    confidence = shared_indicators.iloc[0]['CONFIDENCE_SCORE']
    assert confidence >= 80, f"Confidence should be high for 3 sources, got {confidence}"
    
    print(f"  Detected {len(result)} shared C2 indicators")
    print("✓ correlate_cross_source_c2() tests passed")


def test_correlate_cross_source_c2_empty():
    """Test cross-source C2 correlation with empty data"""
    print("Testing correlate_cross_source_c2() with empty data...")
    
    source_data = {
        'source1': {'c2_full': pd.DataFrame()},
        'source2': {'c2_full': pd.DataFrame()},
    }
    
    result = correlate_cross_source_c2(source_data)
    
    assert isinstance(result, pd.DataFrame), "Result should be a DataFrame"
    assert result.empty or len(result) == 0, "Result should be empty with no C2 indicators"
    
    print("✓ correlate_cross_source_c2() empty data tests passed")


def test_correlate_attack_patterns():
    """Test coordinated attack pattern correlation"""
    print("Testing correlate_attack_patterns()...")
    
    # Create test data with coordinated DDoS attacks
    import time
    base_time = time.time()
    
    source_data = {
        'source1': {
            'ddos': pd.DataFrame([
                {
                    'ATTACK_TYPE': 'SYN_FLOOD',
                    'TARGET': '10.0.0.1',
                    'FIRST_SEEN': base_time,
                    'SCORE': 90
                }
            ])
        },
        'source2': {
            'ddos': pd.DataFrame([
                {
                    'ATTACK_TYPE': 'SYN_FLOOD',
                    'TARGET': '10.0.0.1',
                    'FIRST_SEEN': base_time + 60,  # Within 5 minute window
                    'SCORE': 85
                }
            ])
        },
        'source3': {
            'ddos': pd.DataFrame([
                {
                    'ATTACK_TYPE': 'SYN_FLOOD',
                    'TARGET': '10.0.0.1',
                    'FIRST_SEEN': base_time + 120,  # Within 5 minute window
                    'SCORE': 88
                }
            ])
        }
    }
    
    result = correlate_attack_patterns(source_data)
    
    # Verify results
    assert isinstance(result, pd.DataFrame), "Result should be a DataFrame"
    assert not result.empty, "Result should detect coordinated attack"
    assert 'ATTACK_PATTERN' in result.columns, "Result should have ATTACK_PATTERN column"
    assert 'SOURCE_COUNT' in result.columns, "Result should have SOURCE_COUNT column"
    assert 'TIME_SPREAD' in result.columns, "Result should have TIME_SPREAD column"
    
    # Verify coordinated attack is detected
    assert len(result) >= 1, "Should detect at least one coordinated attack"
    coordinated = result.iloc[0]
    assert coordinated['SOURCE_COUNT'] == 3, "Should detect attack in 3 sources"
    assert coordinated['TIME_SPREAD'] <= CORRELATION_TIME_WINDOW, "Time spread should be within window"
    
    print(f"  Detected {len(result)} coordinated attack patterns")
    print("✓ correlate_attack_patterns() tests passed")


def test_detect_lateral_movement():
    """Test lateral movement detection across sources"""
    print("Testing detect_lateral_movement_across_sources()...")
    
    # Create test data with same attacker IP in multiple sources
    source_data = {
        'source1': {
            'c2_full': pd.DataFrame([
                {'INDICATOR': 'attacker.com', 'TYPE': 'C2', 'SCORE': 85, 'SRC_IP': '192.168.1.50', 'DST_IP': '10.0.0.1'}
            ]),
            'protocol_threats': pd.DataFrame([
                {'INDICATOR': 'SMB Lateral', 'PROTOCOL': 'SMB', 'SCORE': 90, 'SRC_IP': '192.168.1.50', 'DST_IP': '10.0.0.2'}
            ])
        },
        'source2': {
            'c2_full': pd.DataFrame([
                {'INDICATOR': 'attacker2.com', 'TYPE': 'C2', 'SCORE': 80, 'SRC_IP': '192.168.1.50', 'DST_IP': '172.16.0.1'}
            ]),
            'protocol_threats': pd.DataFrame([
                {'INDICATOR': 'RDP Brute', 'PROTOCOL': 'RDP', 'SCORE': 85, 'SRC_IP': '192.168.1.50', 'DST_IP': '172.16.0.2'}
            ])
        },
        'source3': {
            'c2_full': pd.DataFrame(),
            'protocol_threats': pd.DataFrame([
                {'INDICATOR': 'SSH Scan', 'PROTOCOL': 'SSH', 'SCORE': 75, 'SRC_IP': '192.168.1.50', 'DST_IP': '192.168.0.1'}
            ])
        }
    }
    
    result = detect_lateral_movement_across_sources(source_data)
    
    # Verify results
    assert isinstance(result, pd.DataFrame), "Result should be a DataFrame"
    assert not result.empty, "Result should detect lateral movement"
    assert 'ATTACKER_IP' in result.columns, "Result should have ATTACKER_IP column"
    assert 'SOURCE_COUNT' in result.columns, "Result should have SOURCE_COUNT column"
    assert 'ACTIVITIES' in result.columns, "Result should have ACTIVITIES column"
    
    # Verify lateral movement is detected
    lateral = result[result['ATTACKER_IP'] == '192.168.1.50']
    assert len(lateral) == 1, "Should detect lateral movement for IP across 3 sources"
    assert lateral.iloc[0]['SOURCE_COUNT'] == 3, "Should track IP in 3 sources"
    
    print(f"  Detected {len(result)} lateral movement patterns")
    print("✓ detect_lateral_movement_across_sources() tests passed")


def test_correlate_beacon_timing():
    """Test beacon timing correlation"""
    print("Testing correlate_beacon_timing()...")
    
    # Create test data with synchronized beacons (all bucket to 60)
    source_data = {
        'source1': {
            'beacon': pd.DataFrame([
                {'DST_IP': '203.0.113.10', 'AVG_INTERVAL': 60.0, 'COUNT': 10}
            ])
        },
        'source2': {
            'beacon': pd.DataFrame([
                {'DST_IP': '203.0.113.10', 'AVG_INTERVAL': 65.0, 'COUNT': 8}  # 65/10=6.5 → 6*10=60
            ])
        },
        'source3': {
            'beacon': pd.DataFrame([
                {'DST_IP': '203.0.113.10', 'AVG_INTERVAL': 69.0, 'COUNT': 12}  # 69/10=6.9 → 6*10=60
            ])
        }
    }
    
    result = correlate_beacon_timing(source_data)
    
    # Verify results
    assert isinstance(result, pd.DataFrame), "Result should be a DataFrame"
    assert not result.empty, "Result should detect synchronized beacons"
    assert 'BEACON_DESTINATION' in result.columns, "Result should have BEACON_DESTINATION column"
    assert 'AVG_INTERVAL' in result.columns, "Result should have AVG_INTERVAL column"
    assert 'SOURCE_COUNT' in result.columns, "Result should have SOURCE_COUNT column"
    
    # Verify synchronized beacon is detected
    synchronized = result[result['BEACON_DESTINATION'] == '203.0.113.10']
    assert len(synchronized) == 1, "Should detect synchronized beacon"
    assert synchronized.iloc[0]['SOURCE_COUNT'] == 3, "Should detect beacon in 3 sources"
    
    print(f"  Detected {len(result)} synchronized beacons")
    print("✓ correlate_beacon_timing() tests passed")


def test_parse_streams_with_source_id():
    """Test parse_streams with source_id parameter"""
    print("Testing parse_streams() with source_id parameter...")
    
    # Test with default source_id
    dns, tcp, http, tls, udp, icmp, dns_detail = parse_streams('nonexistent.pcap', 'test_source')
    
    # Verify SOURCE_ID column exists in all DataFrames
    for df, name in [(dns, 'dns'), (tcp, 'tcp'), (http, 'http'), (tls, 'tls'), (udp, 'udp'), (icmp, 'icmp'), (dns_detail, 'dns_detail')]:
        assert 'SOURCE_ID' in df.columns, f"{name} DataFrame should have SOURCE_ID column"
    
    print("✓ parse_streams() source_id tests passed")


def test_minimum_sources_requirement():
    """Test that correlation requires minimum sources"""
    print("Testing minimum sources requirement...")
    
    # Test with only 1 source (below minimum)
    source_data = {
        'source1': {
            'c2_full': pd.DataFrame([
                {'INDICATOR': 'test.com', 'TYPE': 'C2', 'SCORE': 85, 'COUNT': 10}
            ])
        }
    }
    
    result = correlate_cross_source_c2(source_data)
    
    # Should return empty DataFrame when below minimum sources
    assert isinstance(result, pd.DataFrame), "Result should be a DataFrame"
    assert result.empty, f"Should not correlate with only 1 source (minimum is {MIN_SOURCES_FOR_CORRELATION})"
    
    print(f"✓ Minimum sources requirement ({MIN_SOURCES_FOR_CORRELATION}) tests passed")


def test_all_correlation_functions_with_empty_data():
    """Test all correlation functions handle empty data gracefully"""
    print("Testing all correlation functions with empty data...")
    
    empty_source_data = {
        'source1': {
            'c2_full': pd.DataFrame(),
            'ddos': pd.DataFrame(),
            'beacon': pd.DataFrame(),
            'protocol_threats': pd.DataFrame()
        },
        'source2': {
            'c2_full': pd.DataFrame(),
            'ddos': pd.DataFrame(),
            'beacon': pd.DataFrame(),
            'protocol_threats': pd.DataFrame()
        }
    }
    
    # All should return DataFrames (empty or not)
    c2_result = correlate_cross_source_c2(empty_source_data)
    assert isinstance(c2_result, pd.DataFrame), "C2 correlation should return DataFrame"
    
    attack_result = correlate_attack_patterns(empty_source_data)
    assert isinstance(attack_result, pd.DataFrame), "Attack correlation should return DataFrame"
    
    lateral_result = detect_lateral_movement_across_sources(empty_source_data)
    assert isinstance(lateral_result, pd.DataFrame), "Lateral movement should return DataFrame"
    
    beacon_result = correlate_beacon_timing(empty_source_data)
    assert isinstance(beacon_result, pd.DataFrame), "Beacon correlation should return DataFrame"
    
    print("✓ All correlation functions handle empty data correctly")


def run_all_tests():
    """Run all multi-source correlation tests"""
    print("=" * 60)
    print("Multi-Source PCAP Correlation Tests")
    print("=" * 60)
    
    try:
        test_parse_streams_with_source_id()
        test_correlate_cross_source_c2()
        test_correlate_cross_source_c2_empty()
        test_correlate_attack_patterns()
        test_detect_lateral_movement()
        test_correlate_beacon_timing()
        test_minimum_sources_requirement()
        test_all_correlation_functions_with_empty_data()
        
        print("=" * 60)
        print("✓ ALL MULTI-SOURCE CORRELATION TESTS PASSED")
        print("=" * 60)
        return 0
        
    except AssertionError as e:
        print(f"\n❌ TEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        return 1
    except Exception as e:
        print(f"\n❌ UNEXPECTED ERROR: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(run_all_tests())
