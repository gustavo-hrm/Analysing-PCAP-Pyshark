# Multi-Source PCAP Correlation Implementation Summary

## Overview

This document provides implementation details for the multi-source PCAP correlation feature added in v23.0.

## Architecture

### Data Flow

```
Multiple PCAP Files
    ↓
Command-line Args (--sources/--sources-dir)
    ↓
Pipeline with Multi-Source Support
    ↓
For each source:
  - Parse PCAP with SOURCE_ID
  - Extract features
  - Detect threats
    ↓
Correlation Analysis (if ≥2 sources):
  - Shared C2 Infrastructure
  - Coordinated Attack Patterns
  - Lateral Movement
  - Beacon Synchronization
    ↓
Dashboard Generation
  - Combined analysis
  - Correlation tables
```

### Key Components

#### 1. parse_streams() Enhancement
```python
def parse_streams(pcap_path, source_id='default'):
    # All row dictionaries now include SOURCE_ID
    dns_rows.append({..., 'SOURCE_ID': source_id})
    tcp_rows.append({..., 'SOURCE_ID': source_id})
    # etc.
```

#### 2. Correlation Functions

**correlate_cross_source_c2(source_data)**
- Input: `{source_id: detection_results}`
- Logic: Groups C2 indicators across sources
- Output: DataFrame with shared C2 infrastructure
- Confidence: 60 + (source_count * 10), max 100

**correlate_attack_patterns(source_data)**
- Input: `{source_id: detection_results}`
- Logic: Finds coordinated attacks within time window
- Output: DataFrame with attack correlations
- Confidence: 70 + (source_count * 5), max 100

**detect_lateral_movement_across_sources(source_data)**
- Input: `{source_id: detection_results}`
- Logic: Tracks same attacker IP across sources
- Output: DataFrame with movement chains
- Confidence: 75 + (source_count * 8), max 100

**correlate_beacon_timing(source_data)**
- Input: `{source_id: detection_results}`
- Logic: Groups beacons by destination and interval buckets
- Output: DataFrame with synchronized beacons
- Confidence: 80 + (source_count * 6), max 100

#### 3. Pipeline Modifications

```python
def pipeline(pcap_sources=None):
    # Handle backward compatibility
    if isinstance(pcap_sources, str):
        pcap_sources = [('default', pcap_sources)]
    elif pcap_sources is None:
        pcap_sources = [('default', FILE_PCAP)]
    
    # Process each source
    source_results = {}
    for source_id, pcap_path in pcap_sources:
        # Parse and analyze each source
        source_results[source_id] = {...}
    
    # Perform correlation if enough sources
    if len(source_results) >= MIN_SOURCES_FOR_CORRELATION:
        correlation_results = {
            'c2': correlate_cross_source_c2(source_results),
            'attacks': correlate_attack_patterns(source_results),
            'lateral': detect_lateral_movement_across_sources(source_results),
            'beacons': correlate_beacon_timing(source_results)
        }
```

## Configuration

### Constants

| Constant | Default | Description |
|----------|---------|-------------|
| `MULTI_SOURCE_ENABLED` | True | Enable/disable correlation |
| `CORRELATION_TIME_WINDOW` | 300 | Time window in seconds (5 min) |
| `MIN_SOURCES_FOR_CORRELATION` | 2 | Minimum sources required |
| `CORRELATION_CONFIDENCE_THRESHOLD` | 0.7 | Minimum confidence (0.0-1.0) |

### Tuning Guidelines

**Increase CORRELATION_TIME_WINDOW** (e.g., 600 seconds):
- If attacks are spread over longer periods
- For slower-moving APT campaigns
- When analyzing historical data with clock skew

**Decrease CORRELATION_TIME_WINDOW** (e.g., 120 seconds):
- For real-time monitoring
- Fast-moving attacks (e.g., DDoS)
- Synchronized botnet campaigns

**Adjust MIN_SOURCES_FOR_CORRELATION**:
- Set to 3+ for high-confidence correlations
- Reduces false positives but may miss some patterns
- Useful for large-scale deployments (10+ sensors)

## Usage Examples

### Example 1: Office Network Analysis
```bash
# Three office locations
python3 main.py --sources \
  headquarters:hq-2025-11-19.pcap \
  branch-east:east-2025-11-19.pcap \
  branch-west:west-2025-11-19.pcap
```

**Expected Correlations**:
- Shared C2 if all offices compromised by same malware
- Coordinated attacks if botnet spans locations
- Lateral movement if attacker pivots between offices

### Example 2: Incident Response
```bash
# Multiple sensors during an incident
python3 main.py --sources-dir /incident/2025-11-19/*.pcap
```

**Analysis Focus**:
- Timeline reconstruction from multiple vantage points
- Attack propagation paths
- C2 infrastructure discovery

### Example 3: Security Monitoring
```bash
# Daily captures from DMZ, internal, and guest networks
python3 main.py --sources \
  dmz:/logs/daily/dmz.pcap \
  internal:/logs/daily/internal.pcap \
  guest:/logs/daily/guest.pcap
```

**Detections**:
- Cross-network C2 beaconing
- Compromised guest devices attacking internal
- Coordinated DDoS from multiple segments

## Dashboard Interpretation

### Source Metadata Table
- Shows all analyzed sources
- Packet counts for each source
- Protocols detected per source

### Shared C2 Infrastructure
- **High Priority**: SOURCE_COUNT ≥ 3, CONFIDENCE ≥ 80
- **Medium Priority**: SOURCE_COUNT = 2, CONFIDENCE ≥ 70
- **Action**: Block C2 domain/IP across all networks

### Coordinated Attack Patterns
- **TIME_SPREAD < 60s**: Highly synchronized (botnet)
- **TIME_SPREAD < 300s**: Coordinated campaign
- **Action**: Investigate attack source correlation

### Lateral Movement
- **SOURCE_COUNT ≥ 3**: Advanced persistent threat
- **Multiple protocols**: Sophisticated attacker
- **Action**: Isolate compromised hosts immediately

### Synchronized Beacons
- **Same interval (±10s)**: Shared C2 controller
- **Multiple sources**: Widespread infection
- **Action**: Block beacon destination, hunt for malware

## Confidence Scoring

All correlations include a CONFIDENCE_SCORE (0-100):

- **90-100**: Very High - Immediate action required
- **80-89**: High - Investigate promptly
- **70-79**: Medium - Review and validate
- **60-69**: Low - May be coincidental

**Factors Affecting Confidence**:
1. Number of sources (more sources = higher confidence)
2. Temporal proximity (tighter time window = higher confidence)
3. Indicator similarity (exact match vs. approximate)
4. Threat score of individual detections

## Performance Considerations

### Memory Usage
- Each source processes independently
- Combined DataFrames created after individual processing
- Memory scales linearly with number of sources
- Recommendation: 4GB RAM for 3 sources, 8GB for 10+ sources

### Processing Time
- Single-pass PCAP parsing (same as v22.0)
- Correlation overhead: ~1-2 seconds per source pair
- Total time: (sources * parse_time) + (sources² * correlation_time)

### Disk Space
- Dashboard size increases with more sources
- Typical: 20KB per source
- Keep original PCAPs compressed

## Troubleshooting

### No Correlations Detected

**Possible Causes**:
1. Only 1 source provided (need ≥2)
2. Sources are unrelated (different networks, time periods)
3. No shared threats across sources
4. Time windows don't overlap

**Solutions**:
- Verify source count with source metadata table
- Check that PCAPs are from related networks
- Lower MIN_SOURCES_FOR_CORRELATION temporarily
- Increase CORRELATION_TIME_WINDOW

### False Positive Correlations

**Symptoms**:
- Legitimate services flagged as shared C2
- Normal traffic patterns flagged as attacks

**Solutions**:
- Add domains/IPs to TRUSTED_DOMAINS
- Increase CORRELATION_CONFIDENCE_THRESHOLD
- Review individual source detections first
- Tune protocol-specific thresholds

### Performance Issues

**Symptoms**:
- Long processing times
- High memory usage
- Dashboard slow to load

**Solutions**:
- Process sources in batches
- Use --sources-dir with fewer files
- Increase ML_MIN_TRAINING_SAMPLES to skip ML on small captures
- Filter large PCAPs before analysis (tcpdump/wireshark)

## Integration with Existing Features

### Priority 1 (Enhanced C2 Detection)
- Correlates DNS tunneling across sources
- Tracks JA3 fingerprints across networks
- Detects coordinated beaconing

### Priority 2 (ML-Enhanced Detection)
- Each source analyzed independently with ML
- Correlation operates on ML results
- Change point detection remains per-source

### Priority 3 (Protocol Detection)
- Protocol threats contribute to lateral movement detection
- SMB/RDP/SSH activities tracked across sources
- Botnet C2 channels (IRC, SMTP) correlated

## Testing

Run all tests to verify implementation:

```bash
# Unit tests for correlation functions
python3 test_multi_source.py

# Integration tests for end-to-end workflow
python3 test_integration_multi_source.py

# Verify backward compatibility
python3 test_priority3.py

# Security check
codeql analyze
```

## Future Enhancements

Potential improvements for future versions:

1. **Geographic Correlation**: Add location metadata for sources
2. **Temporal Clustering**: Auto-detect attack time windows
3. **Graph Visualization**: Network topology of correlated threats
4. **Export Formats**: JSON/CSV export of correlation results
5. **Real-time Correlation**: Stream processing for live captures
6. **Machine Learning**: ML-based correlation confidence scoring
7. **Attack Attribution**: Link correlated threats to known APT groups

## Support

For issues or questions:
1. Check test files for usage examples
2. Review README.md for configuration options
3. Consult this implementation guide
4. Open an issue on GitHub

---

**Version**: v23.0  
**Date**: 2025-11-19  
**Author**: GitHub Copilot
