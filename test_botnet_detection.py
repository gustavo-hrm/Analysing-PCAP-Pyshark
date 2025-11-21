#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test script for botnet detection functionality
"""

# Test without dependencies by mocking pandas
import sys
from unittest.mock import MagicMock

# Mock pandas
sys.modules['pandas'] = MagicMock()

# Now import our modules
from botnet_signatures import BOTNET_SIGNATURES, get_all_ja3_fingerprints, get_all_ports
from botnet_detector import detect_botnet_in_payload

def test_signatures_loaded():
    """Test that signatures are properly loaded"""
    print("Testing signature loading...")
    assert len(BOTNET_SIGNATURES) >= 9, f"Expected at least 9 families, got {len(BOTNET_SIGNATURES)}"
    
    expected_families = ['Emotet', 'TrickBot', 'Mirai', 'Cobalt Strike', 'Sliver', 'Qakbot', 'AsyncRAT', 'Meterpreter', 'Unknown_Botnet']
    for family in expected_families:
        assert family in BOTNET_SIGNATURES, f"Missing family: {family}"
    
    print(f"✓ All {len(BOTNET_SIGNATURES)} families loaded correctly")

def test_ja3_index():
    """Test JA3 fingerprint indexing"""
    print("\nTesting JA3 fingerprint index...")
    ja3_map = get_all_ja3_fingerprints()
    
    # Check some known JA3 hashes
    assert "72a589da586844d7f0818ce684948eea" in ja3_map, "Cobalt Strike JA3 not found"
    assert "Cobalt Strike" in ja3_map["72a589da586844d7f0818ce684948eea"], "Cobalt Strike not mapped to JA3"
    
    print(f"✓ JA3 index contains {len(ja3_map)} unique fingerprints")

def test_port_index():
    """Test port indexing"""
    print("\nTesting port index...")
    port_map = get_all_ports()
    
    # Check some common botnet ports
    assert 443 in port_map, "Port 443 not in index"
    assert 23 in port_map, "Telnet port 23 not in index (Mirai)"
    
    print(f"✓ Port index contains {len(port_map)} unique ports")

def test_payload_detection():
    """Test payload detection with synthetic data"""
    print("\nTesting payload detection...")
    
    # Test 1: Cobalt Strike beacon pattern
    test_payload1 = "GET /jquery/beacon HTTP/1.1\r\nHost: evil-c2.com\r\n"
    detections1 = detect_botnet_in_payload(test_payload1, "192.168.1.100", "10.0.0.1", 443, "72a589da586844d7f0818ce684948eea")
    assert len(detections1) > 0, "Should detect Cobalt Strike pattern"
    assert any(d['FAMILY'] == 'Cobalt Strike' for d in detections1), "Should identify Cobalt Strike"
    print("  ✓ Detected Cobalt Strike (JA3 + HTTP endpoint)")
    
    # Test 2: Generic gate.php pattern
    test_payload2 = "POST /gate.php HTTP/1.1\r\nHost: malware-c2.com\r\n"
    detections2 = detect_botnet_in_payload(test_payload2, "192.168.1.100", "10.0.0.1", 8080)
    assert len(detections2) > 0, "Should detect generic botnet pattern"
    assert any(d['FAMILY'] == 'Unknown_Botnet' for d in detections2), "Should identify Unknown_Botnet"
    print("  ✓ Detected generic botnet pattern (gate.php)")
    
    # Test 3: Mirai payload
    test_payload3 = b"busybox tftp -g -r /bins/mirai.arm"
    detections3 = detect_botnet_in_payload(test_payload3, "192.168.1.100", "10.0.0.1", 23)
    assert len(detections3) > 0, "Should detect Mirai pattern"
    assert any(d['FAMILY'] == 'Mirai' for d in detections3), "Should identify Mirai"
    print("  ✓ Detected Mirai (payload pattern + port)")

def test_signature_fields():
    """Test that all signatures have required fields"""
    print("\nTesting signature completeness...")
    required_fields = ['description', 'family', 'category', 'confidence_base', 'severity']
    
    for family, sig in BOTNET_SIGNATURES.items():
        for field in required_fields:
            assert field in sig, f"{family} missing required field: {field}"
        
        # Check severity is valid
        assert sig['severity'] in ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'], f"{family} has invalid severity: {sig['severity']}"
        
        # Check confidence is in valid range
        assert 0 <= sig['confidence_base'] <= 100, f"{family} has invalid confidence: {sig['confidence_base']}"
    
    print(f"✓ All {len(BOTNET_SIGNATURES)} signatures have required fields")

def test_evidence_logging():
    """Test that detections include proper evidence"""
    print("\nTesting evidence logging...")
    
    test_payload = "GET /jquery/beacon HTTP/1.1\r\nHost: evil-c2.com\r\n"
    detections = detect_botnet_in_payload(test_payload, "192.168.1.100", "10.0.0.1", 443, "72a589da586844d7f0818ce684948eea")
    
    if detections:
        det = detections[0]
        assert 'EVIDENCE' in det, "Detection should include evidence"
        assert 'CONFIDENCE' in det, "Detection should include confidence"
        assert 'PAYLOAD_SAMPLE' in det, "Detection should include payload sample"
        
        # Check evidence contains useful info
        assert len(det['EVIDENCE']) > 0, "Evidence should not be empty"
        print(f"  ✓ Evidence logged: {det['EVIDENCE'][:100]}")
        print(f"  ✓ Confidence: {det['CONFIDENCE']}%")

def main():
    """Run all tests"""
    print("=" * 60)
    print("Botnet Detection Test Suite")
    print("=" * 60)
    
    try:
        test_signatures_loaded()
        test_ja3_index()
        test_port_index()
        test_signature_fields()
        test_payload_detection()
        test_evidence_logging()
        
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
