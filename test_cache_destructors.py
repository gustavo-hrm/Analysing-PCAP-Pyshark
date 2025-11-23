#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test cache class destructors handle interpreter shutdown gracefully
"""

import sys
import os

# Test 1: Import and create cache instances
print("Test 1: Creating cache instances...")
from threat_intel import ThreatIntelCache
from asn_enrichment import ASNCache

threat_cache = ThreatIntelCache()
asn_cache = ASNCache()
print("✓ Cache instances created successfully")

# Test 2: Add some data to caches
print("\nTest 2: Adding data to caches...")
threat_cache.set("test_key", {"test": "data"})
asn_cache.set("192.168.1.1", {"test": "data"})
print("✓ Data added to caches")

# Test 3: Verify __del__ methods exist and are callable
print("\nTest 3: Verifying __del__ methods...")
assert hasattr(threat_cache, '__del__'), "ThreatIntelCache missing __del__ method"
assert hasattr(asn_cache, '__del__'), "ASNCache missing __del__ method"
assert callable(threat_cache.__del__), "ThreatIntelCache.__del__ not callable"
assert callable(asn_cache.__del__), "ASNCache.__del__ not callable"
print("✓ __del__ methods exist and are callable")

# Test 4: Call __del__ explicitly to verify error handling
print("\nTest 4: Testing explicit __del__ calls...")
try:
    threat_cache.__del__()
    print("✓ ThreatIntelCache.__del__() completed without exception")
except Exception as e:
    print(f"✗ ThreatIntelCache.__del__() raised exception: {e}")
    sys.exit(1)

try:
    asn_cache.__del__()
    print("✓ ASNCache.__del__() completed without exception")
except Exception as e:
    print(f"✗ ASNCache.__del__() raised exception: {e}")
    sys.exit(1)

# Test 5: Simulate interpreter shutdown by deleting builtin 'open'
print("\nTest 5: Simulating interpreter shutdown (deleting builtins)...")
import builtins
original_open = builtins.open

# Create new cache instances
threat_cache2 = ThreatIntelCache()
asn_cache2 = ASNCache()
threat_cache2.set("test_key2", {"test": "data2"})
asn_cache2.set("10.0.0.1", {"test": "data2"})

# Delete 'open' to simulate interpreter teardown
del builtins.open

# Now call __del__ - should not raise exception AND should not print errors
print("Note: The following tests should NOT print any error messages...")
try:
    try:
        threat_cache2.__del__()
        print("✓ ThreatIntelCache.__del__() handled missing 'open' gracefully (no error messages)")
    except Exception as e:
        print(f"✗ ThreatIntelCache.__del__() raised exception with missing 'open': {e}")
        sys.exit(1)

    try:
        asn_cache2.__del__()
        print("✓ ASNCache.__del__() handled missing 'open' gracefully (no error messages)")
    except Exception as e:
        print(f"✗ ASNCache.__del__() raised exception with missing 'open': {e}")
        sys.exit(1)
finally:
    # Always restore 'open' regardless of test outcome
    builtins.open = original_open

print("✓ Destructors handle interpreter shutdown gracefully")

print("\n" + "="*60)
print("All tests passed! Cache destructors are safe.")
print("="*60)
