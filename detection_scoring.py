#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Enhanced Detection Scoring Module
===================================

Implements flexible triage system with:
- Multi-indicator scoring
- "Needs Review" vs "Confirmed C2" classification
- Behavioral analysis scoring
- Evidence-based confidence levels
"""

import math
from collections import defaultdict


# Detection confidence thresholds
CONFIDENCE_THRESHOLDS = {
    'CONFIRMED_C2': 80,      # High confidence C2 detection
    'LIKELY_C2': 65,         # Probable C2, warrants investigation
    'NEEDS_REVIEW': 45,      # Suspicious but requires analyst review
    'SUSPICIOUS': 30,        # Low confidence, may be legitimate
    'BENIGN': 0,            # Appears legitimate
}

# Scoring weights for different indicators
INDICATOR_WEIGHTS = {
    # Strong indicators (definitive evidence)
    'known_c2_ip': 50,
    'known_c2_domain': 50,
    'malicious_ja3': 45,
    'botnet_signature': 45,
    'known_exploit_pattern': 40,
    
    # Moderate indicators (suspicious patterns)
    'suspicious_asn': 25,
    'cloud_asn_with_abuse': 30,
    'high_entropy_payload': 20,
    'dga_domain': 25,
    'beaconing_detected': 30,
    'dns_tunneling': 35,
    'suspicious_http_endpoint': 25,
    'rare_ja3': 20,
    'suspicious_user_agent': 20,
    
    # Weak indicators (context-dependent)
    'high_entropy_domain': 10,
    'unusual_port': 10,
    'fast_flux': 15,
    'domain_ip_mismatch': 20,
    'high_packet_frequency': 15,
    'asymmetric_traffic': 15,
    
    # Behavioral indicators
    'regular_beaconing': 25,
    'data_exfiltration_pattern': 30,
    'command_response_pattern': 25,
    'lateral_movement': 35,
    'multi_target_scanning': 20,
}

# Multipliers for evidence correlation
CORRELATION_MULTIPLIERS = {
    2: 1.2,   # 2 indicators: 20% bonus
    3: 1.4,   # 3 indicators: 40% bonus
    4: 1.6,   # 4+ indicators: 60% bonus
}


class DetectionScorer:
    """Enhanced detection scoring with flexible triage"""
    
    def __init__(self):
        self.evidence_history = defaultdict(list)
    
    def score_detection(self, indicators, behavioral_data=None, threat_intel=None, asn_info=None):
        """
        Calculate comprehensive detection score with triage classification
        
        Args:
            indicators: List of indicator names that matched
            behavioral_data: Dict with behavioral analysis results
            threat_intel: Dict with threat intelligence results
            asn_info: Dict with ASN enrichment results
            
        Returns:
            Dict with:
            - total_score: Raw score (0-100+)
            - confidence: Confidence level (0-100)
            - classification: CONFIRMED_C2, LIKELY_C2, NEEDS_REVIEW, etc.
            - evidence_breakdown: Detailed score breakdown
            - recommendation: Analyst action recommendation
        """
        evidence = []
        base_score = 0
        
        # Score individual indicators
        for indicator in indicators:
            weight = INDICATOR_WEIGHTS.get(indicator, 5)  # Default 5 for unknown
            base_score += weight
            evidence.append({
                'indicator': indicator,
                'weight': weight,
                'source': 'signature'
            })
        
        # Add behavioral analysis scores
        if behavioral_data:
            behavioral_score = self._score_behavioral(behavioral_data, evidence)
            base_score += behavioral_score
        
        # Add threat intelligence scores
        if threat_intel:
            ti_score = self._score_threat_intel(threat_intel, evidence)
            base_score += ti_score
        
        # Add ASN/network analysis scores
        if asn_info:
            asn_score = self._score_asn(asn_info, evidence)
            base_score += asn_score
        
        # Apply correlation multiplier
        num_indicators = len(indicators)
        if num_indicators >= 4:
            multiplier = CORRELATION_MULTIPLIERS[4]
        elif num_indicators in CORRELATION_MULTIPLIERS:
            multiplier = CORRELATION_MULTIPLIERS[num_indicators]
        else:
            multiplier = 1.0
        
        # Calculate final score
        total_score = min(100, int(base_score * multiplier))
        
        # Determine classification
        classification = self._classify_detection(total_score, evidence)
        
        # Calculate confidence
        confidence = self._calculate_confidence(total_score, num_indicators, evidence)
        
        # Generate recommendation
        recommendation = self._generate_recommendation(classification, evidence)
        
        return {
            'total_score': total_score,
            'confidence': confidence,
            'classification': classification,
            'evidence_breakdown': evidence,
            'num_indicators': num_indicators,
            'correlation_multiplier': multiplier,
            'recommendation': recommendation,
        }
    
    def _score_behavioral(self, behavioral_data, evidence):
        """Score behavioral analysis indicators"""
        score = 0
        
        # Beaconing regularity
        if behavioral_data.get('beaconing_jitter', 1.0) < 0.1:  # Very regular
            score += INDICATOR_WEIGHTS['regular_beaconing']
            evidence.append({
                'indicator': 'regular_beaconing',
                'weight': INDICATOR_WEIGHTS['regular_beaconing'],
                'source': 'behavioral',
                'details': f"Jitter: {behavioral_data['beaconing_jitter']:.2f}"
            })
        
        # High packet frequency
        if behavioral_data.get('packet_rate', 0) > 100:  # packets/sec
            score += INDICATOR_WEIGHTS['high_packet_frequency']
            evidence.append({
                'indicator': 'high_packet_frequency',
                'weight': INDICATOR_WEIGHTS['high_packet_frequency'],
                'source': 'behavioral',
                'details': f"Rate: {behavioral_data['packet_rate']} pps"
            })
        
        # Data exfiltration pattern (large outbound, small inbound)
        if behavioral_data.get('byte_ratio_out_in', 1.0) > 10:
            score += INDICATOR_WEIGHTS['data_exfiltration_pattern']
            evidence.append({
                'indicator': 'data_exfiltration_pattern',
                'weight': INDICATOR_WEIGHTS['data_exfiltration_pattern'],
                'source': 'behavioral',
                'details': f"Ratio: {behavioral_data['byte_ratio_out_in']:.1f}:1"
            })
        
        # Command & Response pattern (small commands, large responses)
        if behavioral_data.get('byte_ratio_in_out', 1.0) > 10:
            score += INDICATOR_WEIGHTS['command_response_pattern']
            evidence.append({
                'indicator': 'command_response_pattern',
                'weight': INDICATOR_WEIGHTS['command_response_pattern'],
                'source': 'behavioral',
                'details': f"Ratio: {behavioral_data['byte_ratio_in_out']:.1f}:1"
            })
        
        return score
    
    def _score_threat_intel(self, threat_intel, evidence):
        """Score threat intelligence matches"""
        score = 0
        
        if threat_intel.get('is_malicious'):
            # Known malicious IP/domain
            ti_score = threat_intel.get('threat_score', 50)
            score += ti_score
            
            sources = ', '.join(threat_intel.get('sources', []))
            evidence.append({
                'indicator': 'known_c2_ip' if 'ip' in str(threat_intel) else 'known_c2_domain',
                'weight': ti_score,
                'source': 'threat_intel',
                'details': f"Sources: {sources}"
            })
        
        return score
    
    def _score_asn(self, asn_info, evidence):
        """Score ASN and network indicators"""
        score = 0
        
        # Suspicious ASN
        if asn_info.get('is_suspicious'):
            score += INDICATOR_WEIGHTS['suspicious_asn']
            evidence.append({
                'indicator': 'suspicious_asn',
                'weight': INDICATOR_WEIGHTS['suspicious_asn'],
                'source': 'asn',
                'details': f"ASN: {asn_info.get('asn')}, Org: {asn_info.get('org')}"
            })
        
        # Cloud provider with abuse history
        if asn_info.get('cloud_provider') and 'ABUSED' in str(asn_info.get('categories', [])):
            score += INDICATOR_WEIGHTS['cloud_asn_with_abuse']
            evidence.append({
                'indicator': 'cloud_asn_with_abuse',
                'weight': INDICATOR_WEIGHTS['cloud_asn_with_abuse'],
                'source': 'asn',
                'details': f"Cloud: {asn_info['cloud_provider']}"
            })
        
        # Domain/IP mismatch
        if asn_info.get('mismatch'):
            risk = asn_info.get('risk_score', 20)
            score += min(risk, INDICATOR_WEIGHTS['domain_ip_mismatch'])
            evidence.append({
                'indicator': 'domain_ip_mismatch',
                'weight': min(risk, INDICATOR_WEIGHTS['domain_ip_mismatch']),
                'source': 'asn',
                'details': asn_info.get('reason', 'Mismatch detected')
            })
        
        return score
    
    def _classify_detection(self, score, evidence):
        """Classify detection based on score and evidence quality"""
        # Check for strong indicators
        strong_indicators = [
            'known_c2_ip', 'known_c2_domain', 'malicious_ja3',
            'botnet_signature', 'known_exploit_pattern'
        ]
        
        has_strong_evidence = any(
            e['indicator'] in strong_indicators for e in evidence
        )
        
        # Classification logic
        if score >= CONFIDENCE_THRESHOLDS['CONFIRMED_C2'] and has_strong_evidence:
            return 'CONFIRMED_C2'
        elif score >= CONFIDENCE_THRESHOLDS['LIKELY_C2']:
            return 'LIKELY_C2'
        elif score >= CONFIDENCE_THRESHOLDS['NEEDS_REVIEW']:
            return 'NEEDS_REVIEW'
        elif score >= CONFIDENCE_THRESHOLDS['SUSPICIOUS']:
            return 'SUSPICIOUS'
        else:
            return 'BENIGN'
    
    def _calculate_confidence(self, score, num_indicators, evidence):
        """Calculate confidence in the detection (0-100)"""
        # Base confidence from score
        base_confidence = min(100, score)
        
        # Adjust based on number of indicators
        if num_indicators == 0:
            return 0
        elif num_indicators == 1:
            confidence = base_confidence * 0.6  # Lower confidence with single indicator
        elif num_indicators == 2:
            confidence = base_confidence * 0.8
        else:
            confidence = base_confidence * 1.0
        
        # Boost confidence if we have multiple evidence sources
        sources = set(e['source'] for e in evidence)
        if len(sources) >= 3:  # signature + behavioral + threat_intel
            confidence = min(100, confidence * 1.2)
        
        return int(confidence)
    
    def _generate_recommendation(self, classification, evidence):
        """Generate analyst action recommendation"""
        recommendations = {
            'CONFIRMED_C2': {
                'action': 'IMMEDIATE_RESPONSE',
                'priority': 'CRITICAL',
                'steps': [
                    'Isolate affected hosts immediately',
                    'Block C2 communication at firewall',
                    'Capture memory/disk forensics',
                    'Review all traffic to/from this indicator',
                    'Check for lateral movement',
                ]
            },
            'LIKELY_C2': {
                'action': 'INVESTIGATE',
                'priority': 'HIGH',
                'steps': [
                    'Monitor affected hosts closely',
                    'Review full packet captures',
                    'Correlate with SIEM/EDR logs',
                    'Consider temporary blocking',
                    'Escalate to incident response if confirmed',
                ]
            },
            'NEEDS_REVIEW': {
                'action': 'ANALYST_REVIEW',
                'priority': 'MEDIUM',
                'steps': [
                    'Review evidence details carefully',
                    'Check threat intelligence feeds',
                    'Analyze traffic patterns',
                    'Determine if legitimate business traffic',
                    'Add to watchlist if suspicious',
                ]
            },
            'SUSPICIOUS': {
                'action': 'MONITOR',
                'priority': 'LOW',
                'steps': [
                    'Add to monitoring watchlist',
                    'Track for pattern changes',
                    'Review during regular analysis',
                ]
            },
            'BENIGN': {
                'action': 'NO_ACTION',
                'priority': 'INFO',
                'steps': [
                    'Appears legitimate',
                    'No immediate action required',
                ]
            }
        }
        
        return recommendations.get(classification, recommendations['NEEDS_REVIEW'])


# Global instance
_scorer = None

def get_scorer():
    """Get global detection scorer instance"""
    global _scorer
    if _scorer is None:
        _scorer = DetectionScorer()
    return _scorer


# Convenience function
def score_detection(indicators, behavioral_data=None, threat_intel=None, asn_info=None):
    """Score a detection with all available evidence"""
    return get_scorer().score_detection(indicators, behavioral_data, threat_intel, asn_info)


if __name__ == "__main__":
    # Test module
    print("=== Enhanced Detection Scoring Module ===")
    
    # Test Case 1: High confidence C2
    print("\nTest 1: Confirmed C2 (multiple strong indicators)")
    result1 = score_detection(
        indicators=['known_c2_domain', 'malicious_ja3', 'beaconing_detected'],
        behavioral_data={'beaconing_jitter': 0.05, 'packet_rate': 50},
        threat_intel={'is_malicious': True, 'threat_score': 90, 'sources': ['VirusTotal', 'AbuseIPDB']},
    )
    print(f"  Score: {result1['total_score']}")
    print(f"  Classification: {result1['classification']}")
    print(f"  Confidence: {result1['confidence']}%")
    print(f"  Action: {result1['recommendation']['action']}")
    
    # Test Case 2: Needs Review (mixed indicators)
    print("\nTest 2: Needs Review (suspicious but not definitive)")
    result2 = score_detection(
        indicators=['high_entropy_domain', 'unusual_port', 'suspicious_asn'],
        behavioral_data={'packet_rate': 120},
    )
    print(f"  Score: {result2['total_score']}")
    print(f"  Classification: {result2['classification']}")
    print(f"  Confidence: {result2['confidence']}%")
    print(f"  Action: {result2['recommendation']['action']}")
    
    # Test Case 3: Low confidence
    print("\nTest 3: Suspicious (single weak indicator)")
    result3 = score_detection(
        indicators=['high_entropy_domain'],
    )
    print(f"  Score: {result3['total_score']}")
    print(f"  Classification: {result3['classification']}")
    print(f"  Confidence: {result3['confidence']}%")
    print(f"  Action: {result3['recommendation']['action']}")
    
    print("\n✓ Detection scoring module ready")
