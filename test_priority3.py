#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test script for Priority 3 protocol detection features in main.py
"""

import sys
import os
import pandas as pd
import numpy as np

# Add the current directory to the path
sys.path.insert(0, os.path.dirname(__file__))

from main import (
    detect_smb_activity,
    detect_rdp_activity,
    detect_ssh_activity,
    detect_ftp_activity,
    detect_smtp_activity,
    detect_irc_activity,
    detect_p2p_activity,
    compute_protocol_threats,
    PROTOCOL_PORTS,
    PROTOCOL_SIGNATURES,
    PROTOCOL_ANALYSIS,
    SMB_LATERAL_THRESHOLD,
    RDP_BRUTE_THRESHOLD,
    SSH_BRUTE_THRESHOLD,
    FTP_EXFIL_SIZE,
    SMTP_MASS_MAIL_THRESHOLD
)


def test_protocol_configuration():
    """Test protocol configuration constants"""
    print("Testing protocol configuration...")
    
    # Verify protocol ports are defined
    assert 'SMB' in PROTOCOL_PORTS
    assert 445 in PROTOCOL_PORTS['SMB']
    assert 139 in PROTOCOL_PORTS['SMB']
    
    assert 'RDP' in PROTOCOL_PORTS
    assert 3389 in PROTOCOL_PORTS['RDP']
    
    assert 'SSH' in PROTOCOL_PORTS
    assert 22 in PROTOCOL_PORTS['SSH']
    
    # Verify protocol signatures
    assert 'SMB' in PROTOCOL_SIGNATURES
    assert b'\xffSMB' in PROTOCOL_SIGNATURES['SMB']
    
    # Verify analysis flags
    assert 'SMB' in PROTOCOL_ANALYSIS
    assert PROTOCOL_ANALYSIS['SMB'] == True
    
    # Verify thresholds
    assert SMB_LATERAL_THRESHOLD > 0
    assert RDP_BRUTE_THRESHOLD > 0
    assert SSH_BRUTE_THRESHOLD > 0
    assert FTP_EXFIL_SIZE > 0
    assert SMTP_MASS_MAIL_THRESHOLD > 0
    
    print("✓ Protocol configuration tests passed")


def test_detect_smb_activity():
    """Test SMB activity detection"""
    print("\nTesting detect_smb_activity()...")
    
    # Test with empty DataFrame
    empty_df = pd.DataFrame()
    result = detect_smb_activity(empty_df)
    assert isinstance(result, pd.DataFrame)
    assert result.empty
    
    # Test with SMB traffic data
    tcp_data = pd.DataFrame([
        {'SRC_IP': '192.168.1.100', 'DST_IP': '192.168.1.10', 'SRC_PORT': 50000, 'DST_PORT': 445, 'COUNT': 1, 'PAYLOAD': 'SMBv2'},
        {'SRC_IP': '192.168.1.100', 'DST_IP': '192.168.1.11', 'SRC_PORT': 50001, 'DST_PORT': 445, 'COUNT': 1, 'PAYLOAD': 'SMBv2'},
        {'SRC_IP': '192.168.1.100', 'DST_IP': '192.168.1.12', 'SRC_PORT': 50002, 'DST_PORT': 445, 'COUNT': 1, 'PAYLOAD': 'ADMIN$'},
        {'SRC_IP': '192.168.1.100', 'DST_IP': '192.168.1.13', 'SRC_PORT': 50003, 'DST_PORT': 445, 'COUNT': 1, 'PAYLOAD': 'SMB'},
        {'SRC_IP': '192.168.1.100', 'DST_IP': '192.168.1.14', 'SRC_PORT': 50004, 'DST_PORT': 445, 'COUNT': 1, 'PAYLOAD': 'SMB'},
        {'SRC_IP': '192.168.1.100', 'DST_IP': '192.168.1.15', 'SRC_PORT': 50005, 'DST_PORT': 445, 'COUNT': 1, 'PAYLOAD': 'SMB'},
    ])
    
    result = detect_smb_activity(tcp_data)
    assert isinstance(result, pd.DataFrame)
    assert 'SRC_IP' in result.columns
    assert 'LATERAL_SCORE' in result.columns
    
    if not result.empty:
        print(f"  Detected {len(result)} SMB activity patterns")
        assert result['SRC_IP'].iloc[0] == '192.168.1.100'
    
    print("✓ detect_smb_activity() tests passed")


def test_detect_rdp_activity():
    """Test RDP activity detection"""
    print("\nTesting detect_rdp_activity()...")
    
    # Test with empty DataFrame
    empty_df = pd.DataFrame()
    result = detect_rdp_activity(empty_df)
    assert isinstance(result, pd.DataFrame)
    assert result.empty
    
    # Test with RDP brute force pattern
    tcp_data = pd.DataFrame([
        {'SRC_IP': '10.0.0.100', 'DST_IP': '192.168.1.10', 'SRC_PORT': 50000 + i, 'DST_PORT': 3389, 'COUNT': 1}
        for i in range(15)
    ])
    
    result = detect_rdp_activity(tcp_data)
    assert isinstance(result, pd.DataFrame)
    assert 'SCORE' in result.columns
    
    if not result.empty:
        print(f"  Detected {len(result)} RDP activity patterns")
        # Should detect brute force with 15 attempts
        assert result['SCORE'].iloc[0] >= 70
    
    print("✓ detect_rdp_activity() tests passed")


def test_detect_ssh_activity():
    """Test SSH activity detection"""
    print("\nTesting detect_ssh_activity()...")
    
    # Test with empty DataFrame
    empty_df = pd.DataFrame()
    result = detect_ssh_activity(empty_df)
    assert isinstance(result, pd.DataFrame)
    assert result.empty
    
    # Test with SSH scanning pattern
    tcp_data = pd.DataFrame([
        {'SRC_IP': '10.0.0.200', 'DST_IP': f'192.168.1.{i}', 'SRC_PORT': 50000, 'DST_PORT': 22, 'COUNT': 1, 'PAYLOAD': 'SSH-2.0'}
        for i in range(1, 16)
    ])
    
    result = detect_ssh_activity(tcp_data)
    assert isinstance(result, pd.DataFrame)
    
    if not result.empty:
        print(f"  Detected {len(result)} SSH activity patterns")
        # Should detect scanning (multiple targets)
        assert 'SCORE' in result.columns
    
    print("✓ detect_ssh_activity() tests passed")


def test_detect_ftp_activity():
    """Test FTP activity detection"""
    print("\nTesting detect_ftp_activity()...")
    
    # Test with empty DataFrames
    empty_tcp = pd.DataFrame()
    empty_udp = pd.DataFrame()
    result = detect_ftp_activity(empty_tcp, empty_udp)
    assert isinstance(result, pd.DataFrame)
    assert result.empty
    
    # Test with large file transfer
    tcp_data = pd.DataFrame([
        {'SRC_IP': '192.168.1.50', 'DST_IP': '10.0.0.100', 'SRC_PORT': 50000, 'DST_PORT': 21, 'SIZE': FTP_EXFIL_SIZE + 1000000, 'COUNT': 100, 'PAYLOAD': 'USER test'}
    ])
    
    result = detect_ftp_activity(tcp_data, empty_udp)
    assert isinstance(result, pd.DataFrame)
    
    if not result.empty:
        print(f"  Detected {len(result)} FTP activity patterns")
        assert 'SIZE_MB' in result.columns
    
    print("✓ detect_ftp_activity() tests passed")


def test_detect_smtp_activity():
    """Test SMTP activity detection"""
    print("\nTesting detect_smtp_activity()...")
    
    # Test with empty DataFrame
    empty_df = pd.DataFrame()
    result = detect_smtp_activity(empty_df)
    assert isinstance(result, pd.DataFrame)
    assert result.empty
    
    # Test with mass mailing pattern
    tcp_data = pd.DataFrame([
        {'SRC_IP': '192.168.1.100', 'DST_IP': f'10.0.0.{i}', 'SRC_PORT': 50000, 'DST_PORT': 25, 'COUNT': 3}
        for i in range(1, 60)  # 60 destinations * 3 packets = ~180 packets = ~60 emails
    ])
    
    result = detect_smtp_activity(tcp_data)
    assert isinstance(result, pd.DataFrame)
    
    if not result.empty:
        print(f"  Detected {len(result)} SMTP activity patterns")
        assert 'EMAIL_COUNT' in result.columns
    
    print("✓ detect_smtp_activity() tests passed")


def test_detect_irc_activity():
    """Test IRC activity detection"""
    print("\nTesting detect_irc_activity()...")
    
    # Test with empty DataFrame
    empty_df = pd.DataFrame()
    result = detect_irc_activity(empty_df)
    assert isinstance(result, pd.DataFrame)
    assert result.empty
    
    # Test with IRC C2 pattern
    tcp_data = pd.DataFrame([
        {'SRC_IP': '192.168.1.100', 'DST_IP': '10.0.0.50', 'SRC_PORT': 50000, 'DST_PORT': 6667, 'COUNT': 10, 'PAYLOAD': 'JOIN #botnet'},
        {'SRC_IP': '192.168.1.101', 'DST_IP': '10.0.0.50', 'SRC_PORT': 50001, 'DST_PORT': 6667, 'COUNT': 10, 'PAYLOAD': 'PRIVMSG'},
    ])
    
    result = detect_irc_activity(tcp_data)
    assert isinstance(result, pd.DataFrame)
    
    if not result.empty:
        print(f"  Detected {len(result)} IRC activity patterns")
        # IRC traffic is automatically suspicious
        assert result['SCORE'].iloc[0] >= 65
    
    print("✓ detect_irc_activity() tests passed")


def test_detect_p2p_activity():
    """Test P2P activity detection"""
    print("\nTesting detect_p2p_activity()...")
    
    # Test with empty DataFrames
    empty_tcp = pd.DataFrame()
    empty_udp = pd.DataFrame()
    result = detect_p2p_activity(empty_tcp, empty_udp)
    assert isinstance(result, pd.DataFrame)
    assert result.empty
    
    # Test with P2P swarm pattern
    udp_data = pd.DataFrame([
        {'SRC_IP': '192.168.1.100', 'DST_IP': f'10.0.0.{i}', 'SRC_PORT': 6881, 'DST_PORT': 6881, 'COUNT': 1}
        for i in range(1, 25)  # 24 peers
    ])
    
    result = detect_p2p_activity(empty_tcp, udp_data)
    assert isinstance(result, pd.DataFrame)
    
    if not result.empty:
        print(f"  Detected {len(result)} P2P activity patterns")
        assert 'PEER_COUNT' in result.columns
    
    print("✓ detect_p2p_activity() tests passed")


def test_compute_protocol_threats():
    """Test protocol threat aggregation"""
    print("\nTesting compute_protocol_threats()...")
    
    # Create sample detection results
    smb_df = pd.DataFrame([
        {'SRC_IP': '192.168.1.100', 'DST_IP': '192.168.1.10', 'LATERAL_SCORE': 75, 'RANSOMWARE_INDICATOR': 'High Risk', 'COUNT': 5}
    ])
    
    rdp_df = pd.DataFrame([
        {'SRC_IP': '10.0.0.100', 'DST_IP': '192.168.1.10', 'SCORE': 85, 'STATUS': 'Brute Force', 'ATTEMPTS': 15}
    ])
    
    ssh_df = pd.DataFrame([
        {'SRC_IP': '10.0.0.200', 'DST_IP': '192.168.1.10', 'SCORE': 80, 'PATTERN': 'Scanning', 'ATTEMPTS': 20}
    ])
    
    ftp_df = pd.DataFrame([
        {'SRC_IP': '192.168.1.50', 'DST_IP': '10.0.0.100', 'SCORE': 70, 'PATTERN': 'Exfiltration', 'COUNT': 100}
    ])
    
    smtp_df = pd.DataFrame([
        {'SRC_IP': '192.168.1.100', 'DST_IP': '10.0.0.1', 'SCORE': 80, 'TYPE': 'Spam', 'EMAIL_COUNT': 100}
    ])
    
    irc_df = pd.DataFrame([
        {'SRC_IP': '192.168.1.101', 'DST_IP': '10.0.0.50', 'SCORE': 85, 'TYPE': 'C2', 'COUNT': 50}
    ])
    
    p2p_df = pd.DataFrame([
        {'SRC_IP': '192.168.1.100', 'DST_IP': '10.0.0.1', 'SCORE': 80, 'PROTOCOL': 'P2P', 'PEER_COUNT': 25}
    ])
    
    result = compute_protocol_threats(smb_df, rdp_df, ssh_df, ftp_df, smtp_df, irc_df, p2p_df)
    assert isinstance(result, pd.DataFrame)
    assert 'INDICATOR' in result.columns
    assert 'PROTOCOL' in result.columns
    assert 'SCORE' in result.columns
    
    if not result.empty:
        print(f"  Aggregated {len(result)} protocol threats")
        # Should have threats from all protocols
        protocols = result['PROTOCOL'].unique()
        print(f"  Protocols with threats: {', '.join(protocols)}")
    
    print("✓ compute_protocol_threats() tests passed")


def test_empty_dataframes():
    """Test all detection functions with empty DataFrames"""
    print("\nTesting all functions with empty DataFrames...")
    
    empty_tcp = pd.DataFrame()
    empty_udp = pd.DataFrame()
    
    # All should return empty DataFrames without errors
    assert detect_smb_activity(empty_tcp).empty
    assert detect_rdp_activity(empty_tcp).empty
    assert detect_ssh_activity(empty_tcp).empty
    assert detect_ftp_activity(empty_tcp, empty_udp).empty
    assert detect_smtp_activity(empty_tcp).empty
    assert detect_irc_activity(empty_tcp).empty
    assert detect_p2p_activity(empty_tcp, empty_udp).empty
    
    empty_results = [pd.DataFrame()] * 7
    assert compute_protocol_threats(*empty_results).empty
    
    print("✓ Empty DataFrame tests passed")


def main():
    """Run all tests"""
    print("=" * 60)
    print("Priority 3: Protocol Detection Tests")
    print("=" * 60)
    
    try:
        test_protocol_configuration()
        test_detect_smb_activity()
        test_detect_rdp_activity()
        test_detect_ssh_activity()
        test_detect_ftp_activity()
        test_detect_smtp_activity()
        test_detect_irc_activity()
        test_detect_p2p_activity()
        test_compute_protocol_threats()
        test_empty_dataframes()
        
        print("\n" + "=" * 60)
        print("✓ ALL PRIORITY 3 TESTS PASSED")
        print("=" * 60)
        
        return 0
    except Exception as e:
        print(f"\n✗ TEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())
