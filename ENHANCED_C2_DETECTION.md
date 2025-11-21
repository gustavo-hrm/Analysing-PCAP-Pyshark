# Enhanced C2/Botnet Detection - Implementation Guide

## Overview

This document describes the comprehensive C2/Botnet detection enhancements implemented to reduce false positives and improve detection accuracy across all PCAP analysis areas (TCP, HTTP, DNS, TLS).

## Architecture

### New Modules

#### 1. `asn_enrichment.py` - ASN/IP Enrichment
Provides ASN, organization, and geolocation enrichment for IP addresses.

**Features:**
- Team Cymru DNS-based ASN lookups (no API key required)
- Cloud provider detection (AWS, Google Cloud, Azure, DigitalOcean, etc.)
- Domain/IP ownership correlation
- Suspicious ASN categorization
- Local caching with TTL (24 hours)

**Usage:**
```python
from asn_enrichment import enrich_ip, correlate_domain_ip

# Enrich an IP address
info = enrich_ip("203.0.113.10")
# Returns: {'asn': 12345, 'org': 'Example Org', 'cloud_provider': 'AWS', ...}

# Check domain/IP correlation
correlation = correlate_domain_ip("google.com", "1.2.3.4")
# Returns: {'mismatch': True, 'reason': '...', 'risk_score': 75}
```

#### 2. `threat_intel.py` - Threat Intelligence Integration
Integrates with multiple threat intelligence sources.

**Supported Sources:**
- VirusTotal (requires API key)
- AbuseIPDB (requires API key)
- GreyNoise (requires API key)
- Local IOC lists (no API key needed)

**Features:**
- Multi-source correlation
- Rate limiting and caching
- Configurable via environment variables or `~/.threat_intel_config.json`

**Usage:**
```python
from threat_intel import check_ip, check_domain, add_ioc

# Check IP against threat intelligence
result = check_ip("1.2.3.4")
# Returns: {'is_malicious': True, 'sources': ['VirusTotal', 'AbuseIPDB'], ...}

# Add local IOC
add_ioc('ip', '10.0.0.1')
add_ioc('domain', 'evil-c2.com')
```

**API Key Configuration:**
```bash
# Environment variables
export VT_API_KEY="your_virustotal_key"
export ABUSEIPDB_API_KEY="your_abuseipdb_key"
export GREYNOISE_API_KEY="your_greynoise_key"

# Or create ~/.threat_intel_config.json
{
  "api_keys": {
    "virustotal": "your_key_here",
    "abuseipdb": "your_key_here",
    "greynoise": "your_key_here"
  }
}
```

#### 3. `detection_scoring.py` - Enhanced Detection Scoring
Implements flexible triage system with multi-indicator scoring.

**Classification Levels:**
- **CONFIRMED_C2** (80+ score): High confidence, immediate response required
- **LIKELY_C2** (65+ score): Probable C2, investigation warranted
- **NEEDS_REVIEW** (45+ score): Suspicious, analyst review needed
- **SUSPICIOUS** (30+ score): Low confidence, may be legitimate
- **BENIGN** (< 30 score): Appears legitimate

**Indicator Weights:**
```
Strong Indicators (40-50 points):
- known_c2_ip, known_c2_domain
- malicious_ja3, botnet_signature
- known_exploit_pattern

Moderate Indicators (20-35 points):
- suspicious_asn, cloud_asn_with_abuse
- dga_domain, beaconing_detected
- dns_tunneling, domain_ip_mismatch

Weak Indicators (10-20 points):
- high_entropy_domain, unusual_port
- fast_flux, asymmetric_traffic
```

**Correlation Multipliers:**
- 2 indicators: 1.2x bonus
- 3 indicators: 1.4x bonus  
- 4+ indicators: 1.6x bonus

**Usage:**
```python
from detection_scoring import score_detection

result = score_detection(
    indicators=['known_c2_domain', 'beaconing_detected', 'suspicious_asn'],
    behavioral_data={'beaconing_jitter': 0.05, 'packet_rate': 120},
    threat_intel={'is_malicious': True, 'threat_score': 90},
    asn_info={'is_suspicious': True, 'asn': 12345}
)

# Returns:
{
    'total_score': 95,
    'confidence': 92,
    'classification': 'CONFIRMED_C2',
    'recommendation': {
        'action': 'IMMEDIATE_RESPONSE',
        'priority': 'CRITICAL',
        'steps': ['Isolate affected hosts', '...']
    }
}
```

#### 4. `c2_detection_enhanced.py` - Enhanced C2 Detection Integration
Wraps existing C2 detections with enrichment and scoring.

**Features:**
- Automatic ASN/org enrichment
- Threat intelligence correlation
- Multi-indicator scoring
- Per-host summarization
- Analyst recommendations

**Usage:**
```python
from c2_detection_enhanced import (
    enhance_c2_detection,
    generate_host_summary_report,
    generate_c2_conclusion_report
)

# Enhance existing C2 detections
enhanced = enhance_c2_detection(c2_detections_df)

# Generate per-host summary
host_summary = generate_host_summary_report(enhanced)

# Generate conclusion report
conclusion = generate_c2_conclusion_report(enhanced)
```

## Integration with Main Pipeline

The enhanced detection is automatically integrated into `main.py`:

```python
# Step 11b: Enhanced C2 Detection (automatic)
if ENHANCED_C2_AVAILABLE:
    c2_enhanced = enhance_c2_detection(c2_full, protocol='Mixed')
    c2_host_summary = generate_host_summary_report(c2_enhanced)
    c2_conclusion = generate_c2_conclusion_report(c2_enhanced)
```

## Dashboard Features

### New Dashboard Sections

#### 1. C2 Detection Summary
Visual summary with statistics:
- Total Detections
- Confirmed C2
- Likely C2  
- Needs Review

#### 2. Enhanced C2 Detections Table
Columns:
- Indicator (IP/Domain)
- Type (Detection method)
- Classification (CONFIRMED_C2, LIKELY_C2, etc.)
- Score (0-100)
- Confidence (%)
- ASN
- Organization
- Cloud Provider
- Malicious (Threat Intel status)
- Recommended Action
- Priority

#### 3. Per-Host C2 Summary Table
Aggregated by infected host:
- Source Host
- Number of C2 Destinations
- Classification (highest)
- Average Confidence
- C2 IP List
- Primary Indicators
- Recommended Action
- Priority
- Total Detections

## Detection Workflow

```
1. Parse PCAP → Extract traffic (DNS, HTTP, TCP, TLS)
                ↓
2. Existing Heuristics → Detect potential C2 patterns
                ↓
3. ASN Enrichment → Lookup ASN/Org for destination IPs
                ↓
4. Threat Intelligence → Check against IOC databases
                ↓
5. Enhanced Scoring → Multi-indicator correlation
                ↓
6. Classification → CONFIRMED_C2, LIKELY_C2, NEEDS_REVIEW, etc.
                ↓
7. Per-Host Summary → Aggregate by infected host
                ↓
8. Dashboard → Display with analyst recommendations
```

## Reducing False Positives

### Before Enhancement
- Single indicator triggers (e.g., high entropy alone)
- No context about hosting provider
- No threat intelligence correlation
- All detections treated equally

### After Enhancement
- **Multi-indicator correlation**: Requires multiple suspicious signals
- **ASN context**: Cloud providers flagged only with abuse history
- **Domain/IP mismatch**: Detects phishing/typosquatting
- **Flexible triage**: "Needs Review" vs "Confirmed C2"
- **Threat intelligence**: Cross-references known malicious IPs/domains
- **Behavioral analysis**: Beaconing regularity, packet rates, traffic patterns

### Examples

**Scenario 1: High entropy domain on AWS**
- Before: "High-Entropy DNS" → Score 60
- After: 
  - Indicators: high_entropy_domain (10 pts)
  - ASN: AWS (cloud_provider detected, no abuse history)
  - Classification: SUSPICIOUS (< 30 pts)
  - Recommendation: MONITOR (Low Priority)

**Scenario 2: Known C2 IP with beaconing**
- Before: "Beaconing" → Score 55
- After:
  - Indicators: known_c2_ip (50), beaconing_detected (30)
  - Threat Intel: VirusTotal confirmed malicious
  - Behavioral: Regular beaconing (jitter 0.03)
  - Total Score: 100 (with correlation multiplier)
  - Classification: CONFIRMED_C2
  - Recommendation: IMMEDIATE_RESPONSE (Critical Priority)

**Scenario 3: DGA domain on suspicious ASN**
- Before: "High-Entropy DNS" → Score 60
- After:
  - Indicators: dga_domain (25), suspicious_asn (25)
  - ASN: Known bulletproof hosting
  - Total Score: 60 (1.2x multiplier) = 72
  - Classification: LIKELY_C2
  - Recommendation: INVESTIGATE (High Priority)

## Configuration

### Optional API Keys
All features work without API keys, but adding them improves accuracy:

```bash
# Set environment variables
export VT_API_KEY="your_virustotal_api_key"
export ABUSEIPDB_API_KEY="your_abuseipdb_api_key"
export GREYNOISE_API_KEY="your_greynoise_api_key"
```

### Local IOC Lists
Add custom IOCs to `/tmp/local_iocs.json`:
```json
{
  "ips": ["1.2.3.4", "5.6.7.8"],
  "domains": ["evil-c2.com", "bad-domain.tk"],
  "c2": ["known-c2-server.net"]
}
```

### Cache Configuration
Caches are stored in `/tmp/` with configurable TTLs:
- ASN Cache: 24 hours (86400s)
- Threat Intel Cache: 1 hour (3600s)

## Testing

Run comprehensive tests:
```bash
python3 test_enhanced_c2_detection.py
```

Tests cover:
- ASN enrichment
- Threat intelligence integration
- Detection scoring
- C2 detection enhancement
- Per-host summarization
- Full integration workflow

## Performance Impact

- **Minimal overhead**: Only adds enrichment lookups (cached)
- **Optional features**: Works without API keys (local analysis only)
- **Efficient caching**: Reduces external API calls
- **No PCAP re-parsing**: Uses existing traffic data

## Backward Compatibility

- All existing tables and features preserved
- Enhanced detection is optional (graceful fallback)
- No breaking changes to workflow
- Works with or without API keys

## Analyst Workflow

### Critical Priority (CONFIRMED_C2)
1. Review C2 Detection Summary → Check "Confirmed C2" count
2. Open Enhanced C2 Detections → Filter by Classification: CONFIRMED_C2
3. Check Per-Host Summary → Identify infected hosts
4. Review evidence: ASN, Threat Intel sources, Indicators
5. **Action**: Immediate isolation and incident response

### High Priority (LIKELY_C2)
1. Open Enhanced C2 Detections → Filter by Classification: LIKELY_C2
2. Review evidence details
3. Correlate with SIEM/EDR logs
4. **Action**: Monitor closely, consider blocking

### Medium Priority (NEEDS_REVIEW)
1. Review evidence in Enhanced C2 Detections
2. Check if traffic matches known business applications
3. Verify domain ownership vs hosting provider
4. **Action**: Analyst review required

### Low Priority (SUSPICIOUS)
1. Add to monitoring watchlist
2. Track for pattern changes
3. **Action**: Periodic review during regular analysis

## Troubleshooting

### No enhanced detections showing
- Check: `[INFO] Enhanced C2 detection with ASN/Threat Intel enabled` in logs
- Verify modules are importable: `python3 -c "from c2_detection_enhanced import *"`

### API rate limits exceeded
- Reduce analysis frequency
- Use local IOC lists for known bad IPs/domains
- Cache is working (no re-lookups for same IPs within TTL)

### High false positive rate
- Review classification thresholds in `detection_scoring.py`
- Add legitimate cloud services to exclusion lists
- Increase minimum score for CONFIRMED_C2 classification

## Future Enhancements

Planned features:
1. Automatic IOC feed downloads (abuse.ch, OTX, etc.)
2. Integration with MISP for IOC sharing
3. Historical trend analysis
4. Export to SIEM/SOAR platforms
5. Custom scoring rule configuration UI

## Support

For issues or questions:
1. Review test suite: `python3 test_enhanced_c2_detection.py`
2. Check module documentation in source files
3. Verify API key configuration
4. Review cache files in `/tmp/` for troubleshooting
