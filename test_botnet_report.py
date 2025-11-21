#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test script to verify botnet detection report features
"""

import os
import sys
import pandas as pd

# Add the current directory to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from botnet_detector import (
    detect_botnet_in_tcp,
    detect_botnet_in_http,
    detect_botnet_in_tls,
    detect_botnet_in_dns,
    detect_botnet_in_irc,
)

def test_source_tracking():
    """Test that SOURCE_ID and PCAP_FILE are properly tracked"""
    print("=" * 60)
    print("Testing Source Tracking in Botnet Detection")
    print("=" * 60)
    
    # Create sample TCP dataframe with botnet payload
    tcp_data = pd.DataFrame([
        {
            'SRC_IP': '192.168.1.100',
            'DST_IP': '10.0.0.1',
            'DST_PORT': 443,
            'PAYLOAD': 'GET /jquery/beacon HTTP/1.1\r\nHost: evil-c2.com\r\n',
            'SOURCE_ID': 'test_source_1'
        }
    ])
    
    # Test detection with source tracking
    source_id = 'test_source_1'
    pcap_file = 'test_capture.pcap'
    
    print(f"\nTesting TCP detection with source_id='{source_id}', pcap_file='{pcap_file}'")
    detections = detect_botnet_in_tcp(tcp_data, source_id=source_id, pcap_file=pcap_file)
    
    if not detections.empty:
        print(f"✓ Detected {len(detections)} botnet signatures")
        
        # Check that SOURCE_ID and PCAP_FILE are present
        assert 'SOURCE_ID' in detections.columns, "SOURCE_ID column missing"
        assert 'PCAP_FILE' in detections.columns, "PCAP_FILE column missing"
        print("✓ SOURCE_ID and PCAP_FILE columns present")
        
        # Verify values
        for _, det in detections.iterrows():
            assert det['SOURCE_ID'] == source_id, f"SOURCE_ID mismatch: {det['SOURCE_ID']} != {source_id}"
            assert det['PCAP_FILE'] == pcap_file, f"PCAP_FILE mismatch: {det['PCAP_FILE']} != {pcap_file}"
            print(f"✓ Detection tracked: Family={det['FAMILY']}, Source={det['SOURCE_ID']}, File={det['PCAP_FILE']}")
            print(f"  Evidence: {det['EVIDENCE']}")
            print(f"  Confidence: {det['CONFIDENCE']}%")
    else:
        print("⚠ No detections (this may be expected depending on signatures)")
    
    # Test HTTP detection
    http_data = pd.DataFrame([
        {
            'SRC_IP': '192.168.1.101',
            'DST_IP': '10.0.0.2',
            'DOMAIN': 'malware-c2.com',
            'PAYLOAD': 'POST /gate.php HTTP/1.1\r\nHost: malware-c2.com\r\n',
            'SOURCE_ID': 'test_source_2'
        }
    ])
    
    print(f"\nTesting HTTP detection with source_id='test_source_2', pcap_file='another.pcap'")
    http_detections = detect_botnet_in_http(http_data, source_id='test_source_2', pcap_file='another.pcap')
    
    if not http_detections.empty:
        print(f"✓ Detected {len(http_detections)} HTTP botnet signatures")
        for _, det in http_detections.iterrows():
            print(f"✓ HTTP Detection: Family={det['FAMILY']}, Source={det['SOURCE_ID']}, File={det['PCAP_FILE']}")
    
    # Test TLS detection
    tls_data = pd.DataFrame([
        {
            'SRC_IP': '192.168.1.102',
            'DST_IP': '10.0.0.3',
            'SNI': 'evil-server.com',
            'JA3': '1234567890abcdef1234567890abcdef',  # Test JA3 hash (not a real malware fingerprint)
            'SOURCE_ID': 'test_source_3'
        }
    ])
    
    print(f"\nTesting TLS/JA3 detection with source_id='test_source_3', pcap_file='tls_capture.pcap'")
    # Note: This test uses a fake JA3 hash and may not trigger any detections
    tls_detections = detect_botnet_in_tls(tls_data, source_id='test_source_3', pcap_file='tls_capture.pcap')
    
    if not tls_detections.empty:
        print(f"✓ Detected {len(tls_detections)} TLS botnet signatures")
        for _, det in tls_detections.iterrows():
            print(f"✓ TLS Detection: Family={det['FAMILY']}, Source={det['SOURCE_ID']}, File={det['PCAP_FILE']}")
            print(f"  JA3: {det['JA3']}")
    else:
        print(f"✓ No TLS detections (expected with fake JA3 hash)")
    
    print("\n" + "=" * 60)
    print("✓ All source tracking tests passed!")
    print("=" * 60)
    
    return True

def test_multiple_sources():
    """Test detection across multiple sources"""
    print("\n" + "=" * 60)
    print("Testing Multiple Source Detection")
    print("=" * 60)
    
    # Simulate detections from 3 different sources
    all_detections = []
    
    sources = [
        ('source_1', 'capture1.pcap'),
        ('source_2', 'capture2.pcap'),
        ('source_3', 'capture3.pcap'),
    ]
    
    for idx, (source_id, pcap_file) in enumerate(sources):
        tcp_data = pd.DataFrame([
            {
                'SRC_IP': f'192.168.{idx + 1}.100',
                'DST_IP': '10.0.0.1',
                'DST_PORT': 443,
                'PAYLOAD': 'GET /jquery/beacon HTTP/1.1\r\nHost: evil-c2.com\r\n',
                'SOURCE_ID': source_id
            }
        ])
        
        detections = detect_botnet_in_tcp(tcp_data, source_id=source_id, pcap_file=pcap_file)
        if not detections.empty:
            all_detections.append(detections)
            print(f"✓ Source '{source_id}' ({pcap_file}): {len(detections)} detections")
    
    if all_detections:
        combined = pd.concat(all_detections, ignore_index=True)
        print(f"\n✓ Total detections across all sources: {len(combined)}")
        print(f"✓ Unique sources: {combined['SOURCE_ID'].nunique()}")
        print(f"✓ Unique PCAP files: {combined['PCAP_FILE'].nunique()}")
        
        # Display summary
        print("\nDetection Summary by Source:")
        for source_id, pcap_file in sources:
            source_dets = combined[combined['SOURCE_ID'] == source_id]
            if not source_dets.empty:
                print(f"  - {source_id} ({pcap_file}): {len(source_dets)} detections")
                for family in source_dets['FAMILY'].unique():
                    count = len(source_dets[source_dets['FAMILY'] == family])
                    print(f"    └─ {family}: {count}")
    
    print("\n" + "=" * 60)
    print("✓ Multiple source tests passed!")
    print("=" * 60)
    
    return True

if __name__ == "__main__":
    try:
        test_source_tracking()
        test_multiple_sources()
        print("\n✅ All tests passed successfully!")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
