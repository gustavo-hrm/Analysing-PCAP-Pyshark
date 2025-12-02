#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test script for C2 blocklist correlation functionality
"""

import sys
import os

# Add the current directory to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Mock pandas first for environments without it
try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    from unittest.mock import MagicMock
    sys.modules['pandas'] = MagicMock()
    import pandas as pd
    PANDAS_AVAILABLE = False

from c2_blocklist import (
    load_c2_blocklist,
    correlate_c2_ips_from_pcap,
    is_valid_ipv4,
    get_ip_enrichment,
    DEFAULT_C2_IPS
)


def test_default_blocklist():
    """Test that default blocklist is properly loaded"""
    print("Testing default blocklist loading...")
    
    assert len(DEFAULT_C2_IPS) >= 10, f"Expected at least 10 default C2 IPs, got {len(DEFAULT_C2_IPS)}"
    print(f"✓ Default blocklist has {len(DEFAULT_C2_IPS)} IPs")
    
    # Test loading
    c2_ips = load_c2_blocklist()
    assert len(c2_ips) >= 10, f"Expected at least 10 C2 IPs after loading, got {len(c2_ips)}"
    print(f"✓ Loaded {len(c2_ips)} C2 IPs")


def test_ip_validation():
    """Test IP address validation"""
    print("\nTesting IP validation...")
    
    # Valid IPs
    assert is_valid_ipv4("192.168.1.1") == True
    assert is_valid_ipv4("10.0.0.1") == True
    assert is_valid_ipv4("255.255.255.255") == True
    assert is_valid_ipv4("0.0.0.0") == True
    print("✓ Valid IPs pass validation")
    
    # Invalid IPs
    assert is_valid_ipv4("") == False
    assert is_valid_ipv4(None) == False
    assert is_valid_ipv4("256.1.1.1") == False
    assert is_valid_ipv4("1.2.3") == False
    assert is_valid_ipv4("not.an.ip.address") == False
    assert is_valid_ipv4("1.2.3.4.5") == False
    print("✓ Invalid IPs fail validation")


def test_ip_enrichment():
    """Test IP enrichment function"""
    print("\nTesting IP enrichment...")
    
    # Test with known C2 IP
    enrichment = get_ip_enrichment("45.33.32.156")
    
    assert 'asn' in enrichment, "Enrichment should have 'asn' field"
    assert 'asn_owner' in enrichment, "Enrichment should have 'asn_owner' field"
    assert 'reputation' in enrichment, "Enrichment should have 'reputation' field"
    
    print(f"✓ IP enrichment returns: ASN={enrichment['asn']}, Owner={enrichment['asn_owner']}, Rep={enrichment['reputation']}")


def test_correlation():
    """Test correlation function with sample data"""
    print("\nTesting correlation with sample data...")
    
    if not PANDAS_AVAILABLE:
        print("⚠ Pandas not available, skipping correlation test")
        return
    
    # Create sample TCP dataframe
    sample_tcp = pd.DataFrame([
        {'SRC_IP': '192.168.1.100', 'DST_IP': '45.33.32.156', 'DST_PORT': 443},  # DST matches C2
        {'SRC_IP': '192.168.1.101', 'DST_IP': '8.8.8.8', 'DST_PORT': 53},        # No match
        {'SRC_IP': '104.131.74.14', 'DST_IP': '192.168.1.102', 'DST_PORT': 8080}, # SRC matches C2
    ])
    
    c2_ips = load_c2_blocklist()
    hits = correlate_c2_ips_from_pcap(tcp_df=sample_tcp, c2_ips=c2_ips, pcap_file='test.pcap')
    
    assert not hits.empty, "Should have hits for sample data"
    assert len(hits) == 2, f"Expected 2 hits, got {len(hits)}"
    print(f"✓ Found {len(hits)} C2 matches in sample data")
    
    # Check columns exist
    expected_columns = ['PCAP_FILE', 'PROTOCOL', 'SRC_IP', 'DST_IP', 'DEST_PORT', 
                        'MATCHED_C2_IP', 'ASN', 'ASN_OWNER', 'REPUTATION']
    for col in expected_columns:
        assert col in hits.columns, f"Missing column: {col}"
    print(f"✓ All expected columns present: {list(hits.columns)}")
    
    # Check that matched IPs are in our blocklist
    for matched_ip in hits['MATCHED_C2_IP']:
        assert matched_ip in c2_ips, f"Matched IP {matched_ip} should be in blocklist"
    print("✓ All matched IPs are in blocklist")


def test_no_false_positives():
    """Test that legitimate IPs don't match"""
    print("\nTesting no false positives...")
    
    if not PANDAS_AVAILABLE:
        print("⚠ Pandas not available, skipping false positive test")
        return
    
    # Create sample with only legitimate IPs
    sample_tcp = pd.DataFrame([
        {'SRC_IP': '192.168.1.100', 'DST_IP': '8.8.8.8', 'DST_PORT': 53},
        {'SRC_IP': '192.168.1.101', 'DST_IP': '1.1.1.1', 'DST_PORT': 53},
        {'SRC_IP': '10.0.0.1', 'DST_IP': '142.250.185.46', 'DST_PORT': 443},  # google.com
    ])
    
    c2_ips = load_c2_blocklist()
    hits = correlate_c2_ips_from_pcap(tcp_df=sample_tcp, c2_ips=c2_ips, pcap_file='test.pcap')
    
    assert hits.empty, f"Should have no hits for legitimate IPs, got {len(hits)}"
    print("✓ No false positives for legitimate IPs")


def test_multi_protocol():
    """Test correlation across multiple protocols"""
    print("\nTesting multi-protocol correlation...")
    
    if not PANDAS_AVAILABLE:
        print("⚠ Pandas not available, skipping multi-protocol test")
        return
    
    # TCP with C2 match
    tcp_df = pd.DataFrame([
        {'SRC_IP': '192.168.1.100', 'DST_IP': '45.33.32.156', 'DST_PORT': 443},
    ])
    
    # HTTP with C2 match
    http_df = pd.DataFrame([
        {'SRC_IP': '192.168.1.100', 'DST_IP': '104.131.74.14', 'DST_PORT': 80},
    ])
    
    # TLS with C2 match
    tls_df = pd.DataFrame([
        {'SRC_IP': '192.168.1.100', 'DST_IP': '185.220.101.182', 'DST_PORT': 443},
    ])
    
    c2_ips = load_c2_blocklist()
    hits = correlate_c2_ips_from_pcap(
        tcp_df=tcp_df, 
        http_df=http_df, 
        tls_df=tls_df,
        c2_ips=c2_ips, 
        pcap_file='test.pcap'
    )
    
    assert len(hits) == 3, f"Expected 3 hits across protocols, got {len(hits)}"
    
    protocols = hits['PROTOCOL'].unique()
    assert 'TCP' in protocols, "Should have TCP protocol"
    assert 'HTTP' in protocols, "Should have HTTP protocol"
    assert 'TLS' in protocols, "Should have TLS protocol"
    
    print(f"✓ Found matches across {len(protocols)} protocols: {list(protocols)}")


def main():
    """Run all tests"""
    print("=" * 60)
    print("C2 Blocklist Correlation Test Suite")
    print("=" * 60)
    
    try:
        test_default_blocklist()
        test_ip_validation()
        test_ip_enrichment()
        test_correlation()
        test_no_false_positives()
        test_multi_protocol()
        
        print("\n" + "=" * 60)
        print("✓ All tests passed!")
        print("=" * 60)
        return 0
        
    except AssertionError as e:
        print(f"\n✗ Test failed: {e}")
        return 1
    except Exception as e:
        print(f"\n✗ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
