# Enhanced C2/Botnet Detection - Quick Start Guide

## What's New

The PCAP analysis tool now includes **enhanced C2/botnet detection** with:
- ✅ ASN/Organization enrichment for all destination IPs
- ✅ Threat intelligence correlation (VirusTotal, AbuseIPDB, GreyNoise)
- ✅ Multi-indicator scoring to reduce false positives
- ✅ Flexible triage: "Confirmed C2" vs "Needs Review" vs "Suspicious"
- ✅ Per-host summary reports with analyst recommendations

## Quick Start (No Configuration Required)

### Basic Usage
```bash
# Run analysis as normal - enhanced detection is automatic
python3 main.py

# Multi-source analysis (cross-network correlation)
python3 main.py --sources office:capture1.pcap datacenter:capture2.pcap
```

The tool works immediately without any configuration. Enhanced features activate automatically when analyzing PCAPs.

## Enhanced Dashboard Features

### New Sections (Look for these in dashboard.html)

1. **🔍 Enhanced C2 Detection & Analysis** section with:
   - C2 Detection Summary (counts by classification)
   - Enhanced C2 Detections table (with ASN/org/threat intel)
   - Per-Host C2 Summary (infected hosts with recommendations)

2. **Classification Levels** (color-coded):
   - 🔴 **CONFIRMED_C2** (Critical) - Immediate response required
   - 🟠 **LIKELY_C2** (High) - Investigation warranted
   - 🟡 **NEEDS_REVIEW** (Medium) - Analyst review needed
   - 🔵 **SUSPICIOUS** (Low) - Monitoring recommended
   - 🟢 **BENIGN** (Info) - Appears legitimate

## Optional: Enable Threat Intelligence APIs

For even better detection accuracy, configure API keys:

### Option 1: Environment Variables
```bash
export VT_API_KEY="your_virustotal_api_key"
export ABUSEIPDB_API_KEY="your_abuseipdb_api_key"
export GREYNOISE_API_KEY="your_greynoise_api_key"

# Then run as normal
python3 main.py
```

### Option 2: Configuration File
Create `~/.threat_intel_config.json`:
```json
{
  "api_keys": {
    "virustotal": "your_virustotal_key_here",
    "abuseipdb": "your_abuseipdb_key_here",
    "greynoise": "your_greynoise_key_here"
  }
}
```

### Get Free API Keys:
- **VirusTotal**: https://www.virustotal.com/gui/join-us (4 requests/minute free)
- **AbuseIPDB**: https://www.abuseipdb.com/register (1000 checks/day free)
- **GreyNoise**: https://www.greynoise.io/plans/community (50 queries/day free)

## Optional: Add Local IOC Lists

Create `/tmp/local_iocs.json` to add known malicious indicators:
```json
{
  "ips": ["1.2.3.4", "5.6.7.8"],
  "domains": ["evil-c2.com", "malicious-domain.tk"],
  "c2": ["known-c2-server.net"]
}
```

These will be automatically detected with high confidence.

## Understanding the Classifications

### CONFIRMED_C2 (Score 80+)
**What it means:** High confidence C2 communication detected
**Triggers:**
- Known malicious IP/domain (threat intel)
- Botnet signature match (JA3, payload pattern)
- Multiple strong indicators (e.g., DGA + beaconing + suspicious ASN)

**Recommended Action:** 
1. Isolate affected hosts immediately
2. Block C2 communication at firewall
3. Begin incident response procedures

### LIKELY_C2 (Score 65-79)
**What it means:** Probable C2, warrants investigation
**Triggers:**
- Several moderate indicators
- Suspicious ASN + behavioral anomalies
- DNS tunneling or data exfiltration patterns

**Recommended Action:**
1. Monitor affected hosts closely
2. Review full packet captures
3. Correlate with SIEM/EDR logs
4. Consider temporary blocking

### NEEDS_REVIEW (Score 45-64)
**What it means:** Suspicious but requires analyst judgment
**Triggers:**
- Mixed indicators (e.g., high entropy domain on cloud provider)
- Domain/IP mismatch
- Unusual but potentially legitimate traffic

**Recommended Action:**
1. Review evidence details
2. Check if matches known business applications
3. Verify domain ownership
4. Add to watchlist if still suspicious

### SUSPICIOUS (Score 30-44)
**What it means:** Low confidence, possibly legitimate
**Triggers:**
- Single weak indicator
- Common cloud hosting without other red flags

**Recommended Action:**
1. Add to monitoring watchlist
2. Track for pattern changes

### BENIGN (Score < 30)
**What it means:** Appears legitimate
**Action:** No action required

## How It Reduces False Positives

### Before Enhancement
Single indicator = Alert
- "High entropy domain" → Alert (even if on AWS)
- "Unusual port" → Alert (even if legitimate service)
- Many false positives, alert fatigue

### After Enhancement
Multiple indicators required for high confidence
- High entropy domain on AWS = SUSPICIOUS (low priority)
- High entropy domain + suspicious ASN + threat intel match = CONFIRMED_C2 (critical)
- Fewer false positives, actionable intelligence

## Example Scenarios

### Scenario 1: Legitimate Cloud Service
**Traffic:** Application using high-entropy API keys on AWS
- Indicators: high_entropy_domain (10 pts)
- ASN: AWS (known cloud provider, no abuse history)
- **Result:** SUSPICIOUS (30 pts) - Low Priority Monitor
- **Outcome:** Not flagged as critical - analyst time saved

### Scenario 2: Confirmed C2
**Traffic:** Known malicious IP with regular beaconing
- Indicators: known_c2_ip (50 pts), beaconing_detected (30 pts)
- Threat Intel: VirusTotal confirmed (90 pts)
- Behavior: Regular beaconing, jitter 0.03
- **Result:** CONFIRMED_C2 (100 pts) - Critical Priority
- **Outcome:** Immediate response triggered

### Scenario 3: Suspicious Hosting
**Traffic:** DGA-like domain on bulletproof hosting ASN
- Indicators: dga_domain (25 pts), suspicious_asn (25 pts)
- ASN: Known for abuse
- **Result:** LIKELY_C2 (72 pts) - High Priority
- **Outcome:** Investigation warranted, added to watchlist

## Dashboard Workflow

### Step 1: Check Summary
Open `dashboard.html` → Scroll to "🔍 Enhanced C2 Detection & Analysis"
- Check "Confirmed C2" count (red)
- Check "Likely C2" count (orange)

### Step 2: Review Critical Detections
Click on "Enhanced C2 Detections" table → Sort by Classification
- Review CONFIRMED_C2 entries first
- Check evidence: ASN, Organization, Threat Intel sources

### Step 3: Review Per-Host Summary
Click on "Per-Host C2 Summary" table
- See which hosts are infected
- Review recommended actions
- Prioritize by Priority column

### Step 4: Take Action
Follow recommended actions based on classification:
- **CRITICAL**: Immediate isolation and response
- **HIGH**: Investigation and monitoring
- **MEDIUM**: Analyst review
- **LOW**: Watchlist

## Troubleshooting

### Issue: No enhanced detections showing
**Solution:** 
- Check console output for `[INFO] Enhanced C2 detection with ASN/Threat Intel enabled`
- Verify modules loaded: `python3 -c "import c2_detection_enhanced"`

### Issue: All detections classified as SUSPICIOUS
**Possible causes:**
- No API keys configured (only local analysis)
- No strong indicators in this capture
- Mostly legitimate cloud traffic

**Solution:** Add API keys for better threat intelligence

### Issue: Too many NEEDS_REVIEW
**Adjustment:** Review `/tmp/local_iocs.json` to add known-good IPs/domains to exclude

## Performance Notes

- **Minimal overhead:** ~5-10% increase in analysis time (due to enrichment lookups)
- **Caching:** Subsequent runs are faster (cached ASN/threat intel)
- **Optional features:** Works offline without API keys

## Getting Help

1. Review full documentation: `ENHANCED_C2_DETECTION.md`
2. Run tests: `python3 test_enhanced_c2_detection.py`
3. Check module help: `python3 -m pydoc asn_enrichment`

## Summary

**Without any configuration:**
- Enhanced detection works automatically
- Reduces false positives
- Provides analyst recommendations

**With optional API keys:**
- Even better accuracy
- Cross-references known malicious indicators
- Higher confidence scores

**Result:**
- Less alert fatigue
- More actionable intelligence
- Faster incident response
