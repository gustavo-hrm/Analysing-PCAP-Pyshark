#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Integration test for Priority 3 - End-to-end pipeline test with synthetic protocol data
"""

import sys
import os
import pandas as pd

sys.path.insert(0, os.path.dirname(__file__))

from main import (
    detect_smb_activity,
    detect_rdp_activity,
    detect_ssh_activity,
    detect_ftp_activity,
    detect_smtp_activity,
    detect_irc_activity,
    detect_p2p_activity,
    compute_protocol_threats
)


def create_synthetic_smb_lateral_movement():
    """Create synthetic data simulating SMB lateral movement"""
    # Attacker scanning multiple hosts via SMB
    data = []
    attacker_ip = '192.168.1.100'
    for i in range(1, 11):  # 10 targets
        target_ip = f'192.168.1.{i}'
        data.append({
            'SRC_IP': attacker_ip,
            'DST_IP': target_ip,
            'SRC_PORT': 50000 + i,
            'DST_PORT': 445,
            'COUNT': 5,
            'SIZE': 500,
            'PAYLOAD': 'SMBv2 ADMIN$ access attempt'
        })
    return pd.DataFrame(data)


def create_synthetic_rdp_brute_force():
    """Create synthetic data simulating RDP brute force"""
    data = []
    attacker_ip = '10.0.0.50'
    target_ip = '192.168.1.10'
    for i in range(20):  # 20 connection attempts
        data.append({
            'SRC_IP': attacker_ip,
            'DST_IP': target_ip,
            'SRC_PORT': 50000 + i,
            'DST_PORT': 3389,
            'COUNT': 1,
            'SIZE': 200,
            'PAYLOAD': 'RDP connection attempt'
        })
    return pd.DataFrame(data)


def create_synthetic_ssh_scanning():
    """Create synthetic data simulating SSH port scanning"""
    data = []
    scanner_ip = '10.0.0.100'
    for i in range(1, 21):  # Scanning 20 hosts
        target_ip = f'192.168.1.{i}'
        data.append({
            'SRC_IP': scanner_ip,
            'DST_IP': target_ip,
            'SRC_PORT': 50000,
            'DST_PORT': 22,
            'COUNT': 3,
            'SIZE': 150,
            'PAYLOAD': 'SSH-2.0-OpenSSH_7.4'
        })
    return pd.DataFrame(data)


def create_synthetic_ftp_exfiltration():
    """Create synthetic data simulating FTP data exfiltration"""
    return pd.DataFrame([{
        'SRC_IP': '192.168.1.50',
        'DST_IP': '10.0.0.200',
        'SRC_PORT': 50000,
        'DST_PORT': 21,
        'COUNT': 100,
        'SIZE': 15000000,  # 15 MB
        'PAYLOAD': 'USER admin\nPASS password\n'
    }])


def create_synthetic_smtp_spam():
    """Create synthetic data simulating SMTP spam botnet"""
    data = []
    bot_ip = '192.168.1.99'
    for i in range(1, 70):  # Sending to 70 servers
        data.append({
            'SRC_IP': bot_ip,
            'DST_IP': f'10.0.{i//256}.{i%256}',
            'SRC_PORT': 50000,
            'DST_PORT': 25,
            'COUNT': 5,
            'SIZE': 1000,
            'PAYLOAD': 'HELO spambot\nMAIL FROM:<spam@bot.com>\n'
        })
    return pd.DataFrame(data)


def create_synthetic_irc_botnet():
    """Create synthetic data simulating IRC C2 botnet"""
    data = []
    c2_server = '10.0.0.66'
    for i in range(1, 6):  # 5 bots connecting
        bot_ip = f'192.168.1.{100 + i}'
        data.append({
            'SRC_IP': bot_ip,
            'DST_IP': c2_server,
            'SRC_PORT': 50000 + i,
            'DST_PORT': 6667,
            'COUNT': 20,
            'SIZE': 500,
            'PAYLOAD': 'JOIN #botnet\nPRIVMSG #botnet :!ddos target.com\n'
        })
    return pd.DataFrame(data)


def create_synthetic_p2p_malware():
    """Create synthetic data simulating P2P malware distribution"""
    data = []
    infected_host = '192.168.1.150'
    for i in range(1, 31):  # Connected to 30 peers
        peer_ip = f'10.{i//256}.{i%256}.{i%256}'
        data.append({
            'SRC_IP': infected_host,
            'DST_IP': peer_ip,
            'SRC_PORT': 6881,
            'DST_PORT': 6881,
            'COUNT': 10,
            'SIZE': 5000,
        })
    return pd.DataFrame(data)


def test_integration():
    """Run integration test with all protocol detections"""
    print("=" * 70)
    print("Priority 3 Integration Test - Synthetic Attack Scenarios")
    print("=" * 70)
    
    # Create synthetic attack data
    print("\n[1/7] Creating synthetic SMB lateral movement attack...")
    tcp_smb = create_synthetic_smb_lateral_movement()
    smb_results = detect_smb_activity(tcp_smb)
    print(f"  ✓ Detected {len(smb_results)} SMB lateral movement patterns")
    if not smb_results.empty:
        print(f"    - Lateral Score: {smb_results['LATERAL_SCORE'].max()}")
        print(f"    - Targets: {smb_results['COUNT'].max()}")
    
    print("\n[2/7] Creating synthetic RDP brute force attack...")
    tcp_rdp = create_synthetic_rdp_brute_force()
    rdp_results = detect_rdp_activity(tcp_rdp)
    print(f"  ✓ Detected {len(rdp_results)} RDP attack patterns")
    if not rdp_results.empty:
        print(f"    - Threat Score: {rdp_results['SCORE'].max()}")
        print(f"    - Status: {rdp_results['STATUS'].iloc[0]}")
    
    print("\n[3/7] Creating synthetic SSH port scanning...")
    tcp_ssh = create_synthetic_ssh_scanning()
    ssh_results = detect_ssh_activity(tcp_ssh)
    print(f"  ✓ Detected {len(ssh_results)} SSH scan patterns")
    if not ssh_results.empty:
        print(f"    - Threat Score: {ssh_results['SCORE'].max()}")
        print(f"    - Pattern: {ssh_results['PATTERN'].iloc[0]}")
    
    print("\n[4/7] Creating synthetic FTP data exfiltration...")
    tcp_ftp = create_synthetic_ftp_exfiltration()
    ftp_results = detect_ftp_activity(tcp_ftp, pd.DataFrame())
    print(f"  ✓ Detected {len(ftp_results)} FTP exfiltration patterns")
    if not ftp_results.empty:
        print(f"    - Size: {ftp_results['SIZE_MB'].max():.2f} MB")
        print(f"    - Threat Score: {ftp_results['SCORE'].max()}")
    
    print("\n[5/7] Creating synthetic SMTP spam botnet...")
    tcp_smtp = create_synthetic_smtp_spam()
    smtp_results = detect_smtp_activity(tcp_smtp)
    print(f"  ✓ Detected {len(smtp_results)} SMTP spam patterns")
    if not smtp_results.empty:
        print(f"    - Email Count: {smtp_results['EMAIL_COUNT'].max()}")
        print(f"    - Type: {smtp_results['TYPE'].iloc[0]}")
    
    print("\n[6/7] Creating synthetic IRC C2 botnet...")
    tcp_irc = create_synthetic_irc_botnet()
    irc_results = detect_irc_activity(tcp_irc)
    print(f"  ✓ Detected {len(irc_results)} IRC C2 patterns")
    if not irc_results.empty:
        print(f"    - Threat Score: {irc_results['SCORE'].max()}")
        print(f"    - Type: {irc_results['TYPE'].iloc[0]}")
    
    print("\n[7/7] Creating synthetic P2P malware distribution...")
    udp_p2p = create_synthetic_p2p_malware()
    p2p_results = detect_p2p_activity(pd.DataFrame(), udp_p2p)
    print(f"  ✓ Detected {len(p2p_results)} P2P malware patterns")
    if not p2p_results.empty:
        print(f"    - Peer Count: {p2p_results['PEER_COUNT'].max()}")
        print(f"    - Threat Score: {p2p_results['SCORE'].max()}")
    
    # Aggregate threats
    print("\n[8/8] Aggregating protocol threats...")
    protocol_threats = compute_protocol_threats(
        smb_results, rdp_results, ssh_results, ftp_results,
        smtp_results, irc_results, p2p_results
    )
    print(f"  ✓ Total high-severity threats: {len(protocol_threats)}")
    
    # Summary
    print("\n" + "=" * 70)
    print("INTEGRATION TEST SUMMARY")
    print("=" * 70)
    print(f"SMB Lateral Movement:    {len(smb_results)} detections")
    print(f"RDP Brute Force:         {len(rdp_results)} detections")
    print(f"SSH Port Scanning:       {len(ssh_results)} detections")
    print(f"FTP Data Exfiltration:   {len(ftp_results)} detections")
    print(f"SMTP Spam Botnet:        {len(smtp_results)} detections")
    print(f"IRC C2 Communication:    {len(irc_results)} detections")
    print(f"P2P Malware Distribution:{len(p2p_results)} detections")
    print("-" * 70)
    print(f"TOTAL THREATS (Score ≥60): {len(protocol_threats)}")
    
    if not protocol_threats.empty:
        print("\nTop Threats:")
        for idx, row in protocol_threats.head(5).iterrows():
            print(f"  - [{row['PROTOCOL']}] {row['TYPE']}: Score {row['SCORE']}")
    
    print("=" * 70)
    
    # Assertions
    assert len(smb_results) > 0, "SMB detection failed"
    assert len(rdp_results) > 0, "RDP detection failed"
    assert len(ssh_results) > 0, "SSH detection failed"
    assert len(ftp_results) > 0, "FTP detection failed"
    assert len(smtp_results) > 0, "SMTP detection failed"
    assert len(irc_results) > 0, "IRC detection failed"
    assert len(p2p_results) > 0, "P2P detection failed"
    assert len(protocol_threats) > 0, "Threat aggregation failed"
    
    print("\n✓ ALL INTEGRATION TESTS PASSED\n")
    return 0


if __name__ == '__main__':
    try:
        sys.exit(test_integration())
    except Exception as e:
        print(f"\n✗ INTEGRATION TEST FAILED: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
