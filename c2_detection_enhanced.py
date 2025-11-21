#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Enhanced C2 Detection Module
=============================

Integrates ASN enrichment, threat intelligence, and enhanced scoring
into C2/botnet detection workflows.

This module wraps and enhances existing detection functions with:
- ASN/IP enrichment
- Threat intelligence correlation
- Multi-indicator scoring
- Flexible triage classification
- Per-host summarized reporting
"""

import pandas as pd
from collections import defaultdict
import math

# Import enrichment modules
try:
    from asn_enrichment import enrich_ip, correlate_domain_ip, track_abuse
    ASN_AVAILABLE = True
except ImportError:
    ASN_AVAILABLE = False
    print("[WARN] ASN enrichment not available")

try:
    from threat_intel import check_ip, check_domain, add_ioc
    THREAT_INTEL_AVAILABLE = True
except ImportError:
    THREAT_INTEL_AVAILABLE = False
    print("[WARN] Threat intelligence not available")

try:
    from detection_scoring import score_detection
    SCORING_AVAILABLE = True
except ImportError:
    SCORING_AVAILABLE = False
    print("[WARN] Enhanced scoring not available")


def shannon_entropy(s):
    """Calculate Shannon entropy of a string"""
    if not s: return 0.0
    s = str(s)
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs if p > 0)


def enhance_c2_detection(detection_df, protocol='TCP'):
    """
    Enhance existing C2 detections with enrichment and scoring
    
    Args:
        detection_df: DataFrame with existing C2 detections
        protocol: Protocol type (TCP, HTTP, DNS, TLS)
        
    Returns:
        Enhanced DataFrame with additional columns:
        - ASN, ORG, CLOUD_PROVIDER
        - THREAT_INTEL_SCORE
        - ENHANCED_SCORE
        - CLASSIFICATION (CONFIRMED_C2, NEEDS_REVIEW, etc.)
        - CONFIDENCE
        - RECOMMENDATION
    """
    if detection_df.empty:
        return detection_df
    
    enhanced_rows = []
    
    for _, row in detection_df.iterrows():
        enhanced_row = row.to_dict()
        
        # Extract IPs
        src_ip = row.get('SRC_IP', '')
        dst_ip = row.get('DST_IP', '')
        domain = row.get('DOMAIN', '') or row.get('INDICATOR', '')
        
        # Initialize enrichment data
        asn_info = None
        threat_intel_ip = None
        threat_intel_domain = None
        domain_correlation = None
        
        # ASN Enrichment
        if ASN_AVAILABLE and dst_ip:
            asn_info = enrich_ip(dst_ip)
            enhanced_row['DST_ASN'] = asn_info.get('asn')
            enhanced_row['DST_ORG'] = asn_info.get('org', 'Unknown')
            enhanced_row['CLOUD_PROVIDER'] = asn_info.get('cloud_provider', '')
            enhanced_row['ASN_SUSPICIOUS'] = asn_info.get('is_suspicious', False)
            
            # Check domain/IP correlation
            if domain:
                domain_correlation = correlate_domain_ip(domain, dst_ip)
                enhanced_row['DOMAIN_IP_MISMATCH'] = domain_correlation.get('mismatch', False)
                enhanced_row['MISMATCH_REASON'] = domain_correlation.get('reason', '')
        
        # Threat Intelligence
        if THREAT_INTEL_AVAILABLE:
            if dst_ip:
                threat_intel_ip = check_ip(dst_ip)
                enhanced_row['TI_MALICIOUS_IP'] = threat_intel_ip.get('is_malicious', False)
                enhanced_row['TI_SCORE_IP'] = threat_intel_ip.get('threat_score', 0)
                enhanced_row['TI_SOURCES_IP'] = ', '.join(threat_intel_ip.get('sources', []))
            
            if domain:
                threat_intel_domain = check_domain(domain)
                enhanced_row['TI_MALICIOUS_DOMAIN'] = threat_intel_domain.get('is_malicious', False)
                enhanced_row['TI_SCORE_DOMAIN'] = threat_intel_domain.get('threat_score', 0)
                enhanced_row['TI_SOURCES_DOMAIN'] = ', '.join(threat_intel_domain.get('sources', []))
        
        # Determine indicators for scoring
        indicators = []
        
        # Add indicators from original detection type
        detection_type = row.get('TYPE', '')
        if 'JA3' in detection_type:
            indicators.append('malicious_ja3')
        if 'DGA' in detection_type or 'High-Entropy' in detection_type:
            indicators.append('dga_domain')
        if 'Beaconing' in detection_type:
            indicators.append('beaconing_detected')
        if 'DNS Tunneling' in detection_type:
            indicators.append('dns_tunneling')
        if 'Suspicious HTTP' in detection_type:
            indicators.append('suspicious_http_endpoint')
        if 'Fast-Flux' in detection_type:
            indicators.append('fast_flux')
        
        # Add threat intelligence indicators
        if threat_intel_ip and threat_intel_ip.get('is_malicious'):
            indicators.append('known_c2_ip')
        if threat_intel_domain and threat_intel_domain.get('is_malicious'):
            indicators.append('known_c2_domain')
        
        # Add ASN indicators
        if asn_info and asn_info.get('is_suspicious'):
            indicators.append('suspicious_asn')
        if domain_correlation and domain_correlation.get('mismatch'):
            indicators.append('domain_ip_mismatch')
        
        # Add entropy-based indicators
        if domain:
            entropy = shannon_entropy(domain)
            if entropy >= 4.0:
                indicators.append('high_entropy_domain')
                enhanced_row['DOMAIN_ENTROPY'] = round(entropy, 2)
        
        # Enhanced Scoring
        if SCORING_AVAILABLE and indicators:
            # Prepare behavioral data
            behavioral_data = {
                'packet_rate': row.get('COUNT', 0) / max(1, row.get('DURATION', 1)),
                'beaconing_jitter': row.get('JITTER', 1.0),
            }
            
            # Score detection
            scoring_result = score_detection(
                indicators=indicators,
                behavioral_data=behavioral_data,
                threat_intel=threat_intel_ip or threat_intel_domain,
                asn_info=asn_info
            )
            
            enhanced_row['ENHANCED_SCORE'] = scoring_result['total_score']
            enhanced_row['CLASSIFICATION'] = scoring_result['classification']
            enhanced_row['CONFIDENCE'] = scoring_result['confidence']
            enhanced_row['NUM_INDICATORS'] = scoring_result['num_indicators']
            enhanced_row['ANALYST_ACTION'] = scoring_result['recommendation']['action']
            enhanced_row['PRIORITY'] = scoring_result['recommendation']['priority']
        else:
            # Fallback to original score if enhanced scoring not available
            enhanced_row['ENHANCED_SCORE'] = row.get('SCORE', 0)
            enhanced_row['CLASSIFICATION'] = 'NEEDS_REVIEW'
            enhanced_row['CONFIDENCE'] = 50
            enhanced_row['NUM_INDICATORS'] = len(indicators)
            enhanced_row['ANALYST_ACTION'] = 'REVIEW'
            enhanced_row['PRIORITY'] = 'MEDIUM'
        
        # Track abuse for ASN
        if ASN_AVAILABLE and asn_info and asn_info.get('asn') and enhanced_row['CLASSIFICATION'] in ['CONFIRMED_C2', 'LIKELY_C2']:
            track_abuse(asn_info['asn'])
        
        enhanced_rows.append(enhanced_row)
    
    return pd.DataFrame(enhanced_rows)


def generate_host_summary_report(enhanced_detections_df):
    """
    Generate per-host summarized C2 detection report
    
    Groups detections by source host and provides:
    - List of potential C2 destinations
    - Aggregated evidence and scoring
    - Clear analyst recommendations
    
    Returns:
        DataFrame with per-host summaries
    """
    if enhanced_detections_df.empty:
        return pd.DataFrame(columns=[
            'SOURCE_HOST', 'NUM_C2_DESTINATIONS', 'HIGHEST_CLASSIFICATION',
            'AVG_CONFIDENCE', 'C2_DESTINATIONS', 'PRIMARY_INDICATORS',
            'RECOMMENDED_ACTION', 'PRIORITY'
        ])
    
    host_summaries = []
    
    # Group by source IP
    for src_host, group in enhanced_detections_df.groupby('SRC_IP'):
        if not src_host or src_host == 'None':
            continue
        
        # Get all unique C2 destinations
        c2_dests = group['DST_IP'].unique().tolist()
        c2_dests = [d for d in c2_dests if d and d != 'None']
        
        # Get highest classification
        classifications = ['CONFIRMED_C2', 'LIKELY_C2', 'NEEDS_REVIEW', 'SUSPICIOUS', 'BENIGN']
        highest_class = 'BENIGN'
        for cls in classifications:
            if cls in group['CLASSIFICATION'].values:
                highest_class = cls
                break
        
        # Calculate average confidence
        avg_confidence = int(group['CONFIDENCE'].mean()) if 'CONFIDENCE' in group.columns else 50
        
        # Get primary indicators
        all_indicators = []
        for _, row in group.iterrows():
            detection_type = row.get('TYPE', '')
            if detection_type:
                all_indicators.append(detection_type)
        
        # Get unique indicators (top 3)
        unique_indicators = list(set(all_indicators))[:3]
        
        # Determine recommended action
        if highest_class == 'CONFIRMED_C2':
            action = 'IMMEDIATE_RESPONSE'
            priority = 'CRITICAL'
        elif highest_class == 'LIKELY_C2':
            action = 'INVESTIGATE'
            priority = 'HIGH'
        elif highest_class == 'NEEDS_REVIEW':
            action = 'ANALYST_REVIEW'
            priority = 'MEDIUM'
        else:
            action = 'MONITOR'
            priority = 'LOW'
        
        host_summaries.append({
            'SOURCE_HOST': src_host,
            'NUM_C2_DESTINATIONS': len(c2_dests),
            'HIGHEST_CLASSIFICATION': highest_class,
            'AVG_CONFIDENCE': avg_confidence,
            'C2_DESTINATIONS': ', '.join(c2_dests[:5]),  # Top 5
            'PRIMARY_INDICATORS': ' | '.join(unique_indicators),
            'RECOMMENDED_ACTION': action,
            'PRIORITY': priority,
            'TOTAL_DETECTIONS': len(group)
        })
    
    # Sort by priority and confidence
    priority_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3, 'INFO': 4}
    df = pd.DataFrame(host_summaries)
    if not df.empty:
        df['_priority_rank'] = df['PRIORITY'].map(priority_order)
        df = df.sort_values(['_priority_rank', 'AVG_CONFIDENCE'], ascending=[True, False])
        df = df.drop('_priority_rank', axis=1)
    
    return df


def generate_c2_conclusion_report(enhanced_detections_df):
    """
    Generate final conclusion report with actionable C2 host evidence
    
    Returns:
        Dict with:
        - summary_stats: Overall statistics
        - confirmed_c2: List of confirmed C2 hosts
        - needs_review: List of hosts needing analyst review
        - recommendations: Overall recommendations
    """
    if enhanced_detections_df.empty:
        return {
            'summary_stats': {
                'total_detections': 0,
                'confirmed_c2': 0,
                'likely_c2': 0,
                'needs_review': 0,
                'unique_hosts': 0
            },
            'confirmed_c2': [],
            'likely_c2': [],
            'needs_review': [],
            'recommendations': []
        }
    
    # Calculate summary statistics
    summary_stats = {
        'total_detections': len(enhanced_detections_df),
        'confirmed_c2': len(enhanced_detections_df[enhanced_detections_df['CLASSIFICATION'] == 'CONFIRMED_C2']),
        'likely_c2': len(enhanced_detections_df[enhanced_detections_df['CLASSIFICATION'] == 'LIKELY_C2']),
        'needs_review': len(enhanced_detections_df[enhanced_detections_df['CLASSIFICATION'] == 'NEEDS_REVIEW']),
        'unique_hosts': enhanced_detections_df['SRC_IP'].nunique() if 'SRC_IP' in enhanced_detections_df.columns else 0
    }
    
    # Extract confirmed C2 hosts
    confirmed = enhanced_detections_df[enhanced_detections_df['CLASSIFICATION'] == 'CONFIRMED_C2']
    confirmed_list = []
    for _, row in confirmed.iterrows():
        confirmed_list.append({
            'host': row.get('SRC_IP', ''),
            'c2_destination': row.get('DST_IP', ''),
            'domain': row.get('DOMAIN', '') or row.get('INDICATOR', ''),
            'evidence': row.get('TYPE', ''),
            'confidence': row.get('CONFIDENCE', 0),
            'threat_intel': row.get('TI_SOURCES_IP', '') or row.get('TI_SOURCES_DOMAIN', '')
        })
    
    # Extract likely C2 hosts
    likely = enhanced_detections_df[enhanced_detections_df['CLASSIFICATION'] == 'LIKELY_C2']
    likely_list = []
    for _, row in likely.iterrows():
        likely_list.append({
            'host': row.get('SRC_IP', ''),
            'c2_destination': row.get('DST_IP', ''),
            'domain': row.get('DOMAIN', '') or row.get('INDICATOR', ''),
            'evidence': row.get('TYPE', ''),
            'confidence': row.get('CONFIDENCE', 0)
        })
    
    # Extract needs review hosts
    needs_review = enhanced_detections_df[enhanced_detections_df['CLASSIFICATION'] == 'NEEDS_REVIEW']
    review_list = []
    for _, row in needs_review.iterrows():
        review_list.append({
            'host': row.get('SRC_IP', ''),
            'c2_destination': row.get('DST_IP', ''),
            'domain': row.get('DOMAIN', '') or row.get('INDICATOR', ''),
            'reason': row.get('TYPE', ''),
            'indicators': row.get('NUM_INDICATORS', 0)
        })
    
    # Generate recommendations
    recommendations = []
    if confirmed_list:
        recommendations.append({
            'priority': 'CRITICAL',
            'action': 'Immediately isolate and investigate the following confirmed C2 hosts',
            'count': len(confirmed_list)
        })
    if likely_list:
        recommendations.append({
            'priority': 'HIGH',
            'action': 'Investigate the following likely C2 communications',
            'count': len(likely_list)
        })
    if review_list:
        recommendations.append({
            'priority': 'MEDIUM',
            'action': 'Review the following suspicious activities for false positives',
            'count': len(review_list)
        })
    
    return {
        'summary_stats': summary_stats,
        'confirmed_c2': confirmed_list,
        'likely_c2': likely_list,
        'needs_review': review_list,
        'recommendations': recommendations
    }


if __name__ == "__main__":
    # Test module
    print("=== Enhanced C2 Detection Module ===")
    print("Testing detection enhancement...")
    
    # Create sample detection data
    sample_data = pd.DataFrame([
        {
            'SRC_IP': '192.168.1.100',
            'DST_IP': '1.2.3.4',
            'DOMAIN': 'xqz8kjasdh9f.tk',
            'TYPE': 'High-Entropy DNS (possible DGA)',
            'SCORE': 60,
            'COUNT': 50
        },
        {
            'SRC_IP': '192.168.1.101',
            'DST_IP': '5.6.7.8',
            'INDICATOR': 'malicious-c2.com',
            'TYPE': 'JA3 Match: Cobalt Strike',
            'SCORE': 95,
            'COUNT': 20
        }
    ])
    
    # Enhance detections
    enhanced = enhance_c2_detection(sample_data, protocol='DNS')
    print(f"\nEnhanced {len(enhanced)} detections")
    print(f"Classifications: {enhanced['CLASSIFICATION'].tolist()}")
    
    # Generate host summary
    summary = generate_host_summary_report(enhanced)
    print(f"\nHost summaries: {len(summary)}")
    if not summary.empty:
        print(f"Priorities: {summary['PRIORITY'].tolist()}")
    
    # Generate conclusion report
    conclusion = generate_c2_conclusion_report(enhanced)
    print(f"\nConclusion Report:")
    print(f"  Total detections: {conclusion['summary_stats']['total_detections']}")
    print(f"  Confirmed C2: {conclusion['summary_stats']['confirmed_c2']}")
    print(f"  Needs Review: {conclusion['summary_stats']['needs_review']}")
    
    print("\n✓ Enhanced C2 detection module ready")
