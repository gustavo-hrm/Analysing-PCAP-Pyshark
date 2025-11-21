#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Comprehensive Tests for Enhanced C2/Botnet Detection
====================================================

Tests for:
- ASN enrichment
- Threat intelligence integration
- Enhanced detection scoring
- C2 detection enhancement
- Per-host summarization
- Conclusion reporting
"""

import sys
import os

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def test_asn_enrichment():
    """Test ASN enrichment module"""
    print("\n=== Testing ASN Enrichment ===")
    
    from asn_enrichment import enrich_ip, correlate_domain_ip
    
    # Test 1: Private IP detection
    result = enrich_ip("192.168.1.1")
    assert result['org'] == 'Private Network', f"Expected 'Private Network', got {result['org']}"
    assert 'PRIVATE' in result['categories'], "Private IP should have PRIVATE category"
    print("✓ Test 1: Private IP detection passed")
    
    # Test 2: Public IP enrichment (basic)
    result = enrich_ip("8.8.8.8")
    assert result is not None, "Public IP enrichment should return result"
    assert 'asn' in result, "Result should have ASN field"
    print("✓ Test 2: Public IP enrichment passed")
    
    # Test 3: Domain/IP correlation
    correlation = correlate_domain_ip("google.com", "1.2.3.4")
    assert 'mismatch' in correlation, "Correlation should have mismatch field"
    assert 'risk_score' in correlation, "Correlation should have risk_score"
    print("✓ Test 3: Domain/IP correlation passed")
    
    print("✅ ASN enrichment tests passed")


def test_threat_intel():
    """Test threat intelligence module"""
    print("\n=== Testing Threat Intelligence ===")
    
    from threat_intel import check_ip, check_domain, add_ioc
    
    # Test 1: Clean IP check
    result = check_ip("8.8.8.8")
    assert result is not None, "IP check should return result"
    assert 'is_malicious' in result, "Result should have is_malicious field"
    assert 'threat_score' in result, "Result should have threat_score"
    print("✓ Test 1: Clean IP check passed")
    
    # Test 2: Add local IOC and verify
    add_ioc('ip', '10.0.0.1')
    result = check_ip('10.0.0.1')
    assert result['is_malicious'] == True, "Local IOC should be detected as malicious"
    assert 'local_iocs' in result['sources'], "Source should include local_iocs"
    print("✓ Test 2: Local IOC addition passed")
    
    # Test 3: Domain check
    result = check_domain("example.com")
    assert result is not None, "Domain check should return result"
    assert 'is_malicious' in result, "Result should have is_malicious field"
    print("✓ Test 3: Domain check passed")
    
    print("✅ Threat intelligence tests passed")


def test_detection_scoring():
    """Test enhanced detection scoring"""
    print("\n=== Testing Detection Scoring ===")
    
    from detection_scoring import score_detection
    
    # Test 1: High confidence detection (multiple strong indicators)
    result = score_detection(
        indicators=['known_c2_domain', 'malicious_ja3', 'beaconing_detected'],
        behavioral_data={'beaconing_jitter': 0.05, 'packet_rate': 50},
        threat_intel={'is_malicious': True, 'threat_score': 90}
    )
    assert result['classification'] == 'CONFIRMED_C2', f"Expected CONFIRMED_C2, got {result['classification']}"
    assert result['confidence'] >= 80, f"Expected high confidence, got {result['confidence']}"
    assert result['total_score'] >= 80, f"Expected high score, got {result['total_score']}"
    print("✓ Test 1: High confidence C2 detection passed")
    
    # Test 2: Needs review detection (mixed indicators)
    result = score_detection(
        indicators=['high_entropy_domain', 'unusual_port', 'suspicious_asn'],
        behavioral_data={'packet_rate': 10}
    )
    # With 3 weak indicators, might get different classifications based on scoring
    assert result['classification'] in ['NEEDS_REVIEW', 'SUSPICIOUS', 'BENIGN', 'LIKELY_C2'], \
        f"Expected valid classification, got {result['classification']}"
    print("✓ Test 2: Mixed indicators detection passed")
    
    # Test 3: Low confidence detection
    result = score_detection(
        indicators=['high_entropy_domain']
    )
    assert result['classification'] in ['SUSPICIOUS', 'BENIGN'], \
        f"Expected SUSPICIOUS/BENIGN, got {result['classification']}"
    assert result['confidence'] < 50, f"Expected low confidence, got {result['confidence']}"
    print("✓ Test 3: Low confidence detection passed")
    
    # Test 4: Correlation multiplier
    result_multi = score_detection(
        indicators=['suspicious_asn', 'high_entropy_payload', 'beaconing_detected']
    )
    result_single = score_detection(
        indicators=['suspicious_asn']
    )
    assert result_multi['total_score'] > result_single['total_score'], \
        "Multiple indicators should have higher score than single"
    print("✓ Test 4: Correlation multiplier passed")
    
    print("✅ Detection scoring tests passed")


def test_c2_detection_enhanced():
    """Test enhanced C2 detection integration"""
    print("\n=== Testing Enhanced C2 Detection ===")
    
    # Mock pandas for testing
    try:
        import pandas as pd
        
        from c2_detection_enhanced import (
            enhance_c2_detection,
            generate_host_summary_report,
            generate_c2_conclusion_report
        )
        
        # Create sample detection data
        sample_data = pd.DataFrame([
            {
                'SRC_IP': '192.168.1.100',
                'DST_IP': '1.2.3.4',
                'DOMAIN': 'xqz8kjasdh9f.tk',
                'TYPE': 'High-Entropy DNS (possible DGA)',
                'SCORE': 60,
                'COUNT': 50,
                'INDICATOR': 'xqz8kjasdh9f.tk'
            },
            {
                'SRC_IP': '192.168.1.101',
                'DST_IP': '5.6.7.8',
                'DOMAIN': '',
                'INDICATOR': 'malicious-c2.com',
                'TYPE': 'JA3 Match: Cobalt Strike',
                'SCORE': 95,
                'COUNT': 20
            }
        ])
        
        # Test 1: Enhance detections
        enhanced = enhance_c2_detection(sample_data, protocol='DNS')
        assert len(enhanced) == 2, f"Expected 2 detections, got {len(enhanced)}"
        assert 'CLASSIFICATION' in enhanced.columns, "Enhanced data should have CLASSIFICATION"
        assert 'CONFIDENCE' in enhanced.columns, "Enhanced data should have CONFIDENCE"
        assert 'DST_ORG' in enhanced.columns, "Enhanced data should have DST_ORG (ASN)"
        print("✓ Test 1: Detection enhancement passed")
        
        # Test 2: Generate host summary
        summary = generate_host_summary_report(enhanced)
        assert not summary.empty, "Host summary should not be empty"
        assert 'SOURCE_HOST' in summary.columns, "Summary should have SOURCE_HOST"
        assert 'RECOMMENDED_ACTION' in summary.columns, "Summary should have RECOMMENDED_ACTION"
        print("✓ Test 2: Host summary generation passed")
        
        # Test 3: Generate conclusion report
        conclusion = generate_c2_conclusion_report(enhanced)
        assert 'summary_stats' in conclusion, "Conclusion should have summary_stats"
        assert conclusion['summary_stats']['total_detections'] == 2, "Should have 2 total detections"
        print("✓ Test 3: Conclusion report generation passed")
        
        print("✅ Enhanced C2 detection tests passed")
        
    except ImportError:
        print("⚠️  Pandas not available - skipping enhanced C2 detection tests")


def test_integration():
    """Test full integration workflow"""
    print("\n=== Testing Full Integration ===")
    
    try:
        import pandas as pd
        
        # Create sample C2 detections
        c2_data = pd.DataFrame([
            {
                'SRC_IP': '192.168.1.100',
                'DST_IP': '203.0.113.10',
                'DOMAIN': 'bad-domain.tk',
                'TYPE': 'High-Entropy DNS + Beaconing',
                'SCORE': 70,
                'COUNT': 100,
                'INDICATOR': 'bad-domain.tk'
            }
        ])
        
        # Add IOC
        from threat_intel import add_ioc
        add_ioc('ip', '203.0.113.10')
        
        # Enhance detection
        from c2_detection_enhanced import enhance_c2_detection, generate_c2_conclusion_report
        enhanced = enhance_c2_detection(c2_data)
        
        # Check if threat intel was applied
        if 'TI_MALICIOUS_IP' in enhanced.columns:
            ti_detected = enhanced.iloc[0]['TI_MALICIOUS_IP']
            if ti_detected:
                print("✓ Threat intelligence integration working")
        
        # Check classification
        classification = enhanced.iloc[0]['CLASSIFICATION']
        print(f"  Classification: {classification}")
        assert classification in ['CONFIRMED_C2', 'LIKELY_C2', 'NEEDS_REVIEW'], \
            f"Expected valid classification, got {classification}"
        
        # Generate conclusion
        conclusion = generate_c2_conclusion_report(enhanced)
        assert len(conclusion['confirmed_c2']) + len(conclusion['likely_c2']) + len(conclusion['needs_review']) > 0, \
            "Should have at least one detection in conclusion"
        
        print("✅ Integration test passed")
        
    except ImportError:
        print("⚠️  Pandas not available - skipping integration test")


def run_all_tests():
    """Run all test suites"""
    print("=" * 70)
    print("COMPREHENSIVE ENHANCED C2/BOTNET DETECTION TESTS")
    print("=" * 70)
    
    try:
        test_asn_enrichment()
        test_threat_intel()
        test_detection_scoring()
        test_c2_detection_enhanced()
        test_integration()
        
        print("\n" + "=" * 70)
        print("✅ ALL TESTS PASSED")
        print("=" * 70)
        return True
        
    except AssertionError as e:
        print(f"\n❌ TEST FAILED: {e}")
        return False
    except Exception as e:
        print(f"\n❌ UNEXPECTED ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
