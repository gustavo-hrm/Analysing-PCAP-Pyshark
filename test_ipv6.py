#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test script for IPv6 support in main.py
"""

import sys
import os

# Add the current directory to the path
sys.path.insert(0, os.path.dirname(__file__))

from main import is_private_ipv6, is_private_ip, get_ip_layer

def test_is_private_ipv6():
    """Test IPv6 private address detection"""
    print("Testing is_private_ipv6()...")
    
    # Test cases: (ip, expected_result)
    test_cases = [
        # Loopback
        ("::1", True),
        
        # Link-local
        ("fe80::1", True),
        ("fe80:0000:0000:0000:0202:b3ff:fe1e:8329", True),
        
        # Unique local
        ("fc00::1", True),
        ("fd00::1", True),
        
        # IPv4-mapped
        ("::ffff:192.168.1.1", True),
        
        # Documentation
        ("2001:db8::1", True),
        
        # Unspecified
        ("::", True),
        
        # Public IPv6 (should be False)
        ("2001:4860:4860::8888", False),  # Google DNS
        ("2606:4700:4700::1111", False),  # Cloudflare DNS
    ]
    
    passed = 0
    failed = 0
    
    for ip, expected in test_cases:
        result = is_private_ipv6(ip)
        status = "✓" if result == expected else "✗"
        if result == expected:
            passed += 1
        else:
            failed += 1
        print(f"  {status} {ip:45} -> {result} (expected {expected})")
    
    print(f"\nResults: {passed} passed, {failed} failed")
    return failed == 0


def test_is_private_ip():
    """Test unified IPv4/IPv6 private address detection"""
    print("\nTesting is_private_ip() with IPv6 support...")
    
    test_cases = [
        # IPv6 private
        ("::1", True),
        ("fe80::1", True),
        ("2001:4860:4860::8888", False),
        
        # IPv4 private
        ("192.168.1.1", True),
        ("10.0.0.1", True),
        ("172.16.0.1", True),
        ("127.0.0.1", True),
        
        # IPv4 public
        ("8.8.8.8", False),
        ("1.1.1.1", False),
    ]
    
    passed = 0
    failed = 0
    
    for ip, expected in test_cases:
        result = is_private_ip(ip)
        status = "✓" if result == expected else "✗"
        if result == expected:
            passed += 1
        else:
            failed += 1
        print(f"  {status} {ip:45} -> {result} (expected {expected})")
    
    print(f"\nResults: {passed} passed, {failed} failed")
    return failed == 0


def test_get_ip_layer():
    """Test IP layer extraction"""
    print("\nTesting get_ip_layer()...")
    
    try:
        from scapy.all import IP, IPv6, TCP
        
        # Create test packets
        ipv4_pkt = IP(src="192.168.1.1", dst="8.8.8.8") / TCP()
        ipv6_pkt = IPv6(src="2001:db8::1", dst="2001:4860:4860::8888") / TCP()
        
        # Test IPv4
        layer, version = get_ip_layer(ipv4_pkt)
        if layer and version == 'v4':
            print(f"  ✓ IPv4 packet: {layer.src} -> {layer.dst} (version: {version})")
        else:
            print(f"  ✗ IPv4 packet failed")
            return False
        
        # Test IPv6
        layer, version = get_ip_layer(ipv6_pkt)
        if layer and version == 'v6':
            print(f"  ✓ IPv6 packet: {layer.src} -> {layer.dst} (version: {version})")
        else:
            print(f"  ✗ IPv6 packet failed")
            return False
        
        print("\nAll get_ip_layer() tests passed!")
        return True
        
    except ImportError:
        print("  ⚠ Scapy not available, skipping packet tests")
        return True


def main():
    """Run all tests"""
    print("="*60)
    print("IPv6 Support Test Suite")
    print("="*60)
    
    all_passed = True
    
    # Run tests
    all_passed &= test_is_private_ipv6()
    all_passed &= test_is_private_ip()
    all_passed &= test_get_ip_layer()
    
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
