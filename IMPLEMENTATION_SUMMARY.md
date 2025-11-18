# Enhanced C2 Detection with HTTP Payload Analysis - Implementation Summary

## Overview
This implementation adds comprehensive HTTP payload analysis to detect C2 (Command & Control) commands, specifically targeting DDoS attack command patterns as described in the problem statement.

## Implementation Details

### 1. HTTP Payload Extraction
**File**: `main.py` (lines 288-318)
- Modified `parse_streams()` function to capture HTTP payloads
- Payload limit: 2048 bytes (configurable)
- Added `PAYLOAD` column to HTTP dataframe
- Captures both request and response payloads when available

### 2. C2 Detection Functions
**File**: `main.py` (lines 687-864)

#### `extract_ip_port_lists_from_payload(payload_text)`
- Uses regex pattern: `\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)\b`
- Validates IP octets (0-255)
- Returns list of (IP, port) tuples

#### `detect_attack_command_parameters(payload_text)`
- Detects numeric sequences separated by semicolons/commas
- Minimum 5 parameters to flag as attack command
- Returns parameter count and values

#### `detect_base64_payload(payload_text)`
- Detects base64-encoded content (20+ chars)
- Attempts decoding and re-analyzes for IP:port patterns
- Supports obfuscated C2 commands

#### `detect_c2_payload_patterns(http_df, tcp_df)`
- **Main detection function**
- Combines all pattern detection methods
- Scoring system:
  - 5-9 IP:port pairs → SCORE 85
  - 10+ IP:port pairs → SCORE 95
  - IP list + numeric parameters → SCORE 98
  - Known botnet keywords (mirai, gafgyt, qbot, emotet, trickbot) → SCORE 99
- Returns DataFrame with detections including payload excerpts

#### `correlate_c2_commands_to_attacks(c2_commands_df, tcp_df, time_window=300)`
- Correlates C2 commands with subsequent traffic spikes
- Default time window: 300 seconds (5 minutes)
- Tracks source IPs receiving commands and generating attacks

### 3. Integration with C2 Heuristics
**File**: `main.py` (lines 398-421)
- Modified `compute_c2_heuristics()` to accept `http_full` parameter
- Calls `detect_c2_payload_patterns()` for all HTTP traffic
- Merges payload-based detections with existing heuristics
- Maintains SRC_IP/DST_IP for graph visualization

### 4. Dashboard Visualization
**File**: `main.py` (HTML template, line 1748-1751)
- Added "C2 Commands Detected (HTTP Payload Analysis)" section
- Table columns:
  - INDICATOR (source → domain)
  - TYPE (detection type)
  - SCORE (85-99)
  - IP_COUNT (number of targets)
  - PARAM_COUNT (number of parameters)
  - PAYLOAD_EXCERPT (first 200 chars of payload)

**File**: `main.py` (JavaScript, lines 1368-1369, 1597-1599)
- Added `c2CommandsData` variable
- Renders C2 commands table with sorting by SCORE
- Displays payload excerpts for manual analysis

### 5. Pipeline Integration
**File**: `main.py` (lines 1882-1896)
- Step 12: Extract C2 Payload Commands
- Generates detailed detection data with `detect_c2_payload_patterns()`
- Passes data to JavaScript via `%%C2COMMANDS%%` placeholder

## Test Results

### Standalone Test with Example Pattern
**Input**: DDoS C2 Command from problem statement
```
200;40;15;1000;10;600;1024;207.174.105.76:9998;80.75.212.57:9998;207.174.105.86:9998;74.119.149.37:9998;185.91.127.34:9998;207.174.105.87:9998;185.91.127.66:9998;74.119.149.26:9998;207.174.105.102:9998;80.75.212.84:9998;74.119.149.21:9998
```

**Results**:
- ✓ Extracted: 11 IP:port pairs
- ✓ Detected: 7 numeric parameters (200, 40, 15, 1000, 10, 600, 1024)
- ✓ Score: 98/100
- ✓ Detection Type: "C2 Attack Command (IP list + parameters)"

### Current PCAP Analysis
**Note**: The provided PCAP (`ataques_out_novembro_2025.pcapng`) does not contain clear-text HTTP C2 commands. The traffic is encrypted/compressed. The detection functions are ready to identify C2 commands when present in future PCAP files.

## Security Analysis (CodeQL)

### Python Code
- ✓ No security vulnerabilities detected
- ✓ Proper input validation (IP octet checks, payload length limits)
- ✓ Exception handling prevents crashes

### JavaScript/HTML
- ⚠️ 4 warnings: CDN scripts without integrity checks (pre-existing, not introduced)
- Impact: Low (dashboard is for local analysis, not public deployment)

## Performance Considerations

1. **Payload Storage**: Limited to 2048 bytes to prevent memory issues
2. **Regex Efficiency**: IP:port pattern is optimized for common formats
3. **Base64 Decoding**: Limited to first 5 matches to prevent excessive processing
4. **Parameter Detection**: Scans only first 10 lines of payload

## Future Enhancements (Optional)

1. **Machine Learning**: Extract features (IP density, entropy, parameter patterns) for ML classification
2. **Threat Intelligence**: Integration with known C2 server lists
3. **Protocol Analysis**: Support for non-HTTP C2 channels (DNS, ICMP)
4. **Real-time Monitoring**: Adapt for live packet capture analysis

## Files Modified

1. `main.py`: Core implementation (275 lines added/modified)
2. `dashboard.html`: Added C2 Commands section (generated)
3. `dashboard.js`: Added C2 commands rendering (generated)

## Minimal Changes Approach

✓ Only added necessary detection functions
✓ Preserved existing DDoS detection functionality  
✓ No breaking changes to existing code
✓ Backward compatible (works with/without payload data)

---

**Implementation Status**: ✅ Complete and Tested
**Security Review**: ✅ Passed (Python code)
**Functionality**: ✅ Verified with test pattern
