# C2 Detection Troubleshooting Guide

## Recent Fixes (Commit 290e9b1)

### 1. Scores Now Visible on C2 Graphs ✅

**What Changed:**
- Node labels: `192.168.1.100 [98]` (IP address with SCORE in brackets)
- Color-coded nodes:
  - 🔵 Blue (#1976d2): Score 0-50 (Low risk)
  - 🟠 Orange (#ff9800): Score 50-75 (Suspicious)
  - 🔴 Red (#d32f2f): Score 85-99 (C2 Command Detected)
- Edge colors: Gray (normal) → Orange (high-threat)

### 2. Enhanced Debugging for Detection Issues 🔍

**New Debug Output:**
```
[DEBUG] C2 Payload Detection: Analyzing X HTTP records
[DEBUG] Interesting payload: IP count=Y, Param count=Z
[DEBUG] C2 Detection: Found command - IP count: Y, Param count: Z, Score: N
[DEBUG] C2 Payload Detection: Analyzed X payloads (skipped Y short), found Z C2 commands
```

## Troubleshooting: No C2 Commands Detected

If your PCAP has C2 commands but nothing shows in the dashboard, follow these steps:

### Step 1: Check HTTP Traffic

Run the script and look for:
```
[DEBUG] C2 Payload Detection: Analyzing X HTTP records
```

**If X = 0:**
- Your PCAP has no HTTP traffic
- Traffic might be HTTPS (encrypted)
- HTTP might be on non-standard ports (not detected)
- Solution: Ensure PCAP contains clear-text HTTP

### Step 2: Check Payload Analysis

Look for:
```
[DEBUG] C2 Payload Detection: Analyzed X payloads (skipped Y short)
```

**If X = 0:**
- HTTP packets have no payload (headers only)
- All payloads < 10 bytes
- Solution: Verify HTTP requests/responses have body content

**If Y is high:**
- Many payloads are too short (< 10 bytes)
- May need to adjust minimum payload size

### Step 3: Check for Pattern Detection

Look for:
```
[DEBUG] Interesting payload: IP count=X, Param count=Y
```

**If this message doesn't appear:**
- Payloads don't contain IP:port patterns
- Pattern format doesn't match regex: `\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+`
- Solution: Verify payload format matches expected pattern

### Step 4: Verify Expected Pattern

The detection looks for:
```
200;40;15;1000;10;600;1024;207.174.105.76:9998;80.75.212.57:9998;207.174.105.86:9998;...
```

Required elements:
- **IP:port pairs**: At least 5 for detection (e.g., `207.174.105.76:9998`)
- **Separators**: Semicolons (`;`) or commas (`,`)
- **Numeric parameters**: Optional but increase score

## Detection Scoring

| Pattern | Score | Detection Type |
|---------|-------|----------------|
| 5-9 IP:port pairs | 85 | C2 Attack Command (5+ targets) |
| 10+ IP:port pairs | 95 | C2 Attack Command (10+ targets) |
| 5+ IPs + 5+ params | 98 | C2 Attack Command (IP list + parameters) |
| Known botnet keywords | 99 | Known Botnet C2 Command |

Keywords: `mirai`, `gafgyt`, `qbot`, `emotet`, `trickbot`

## Common Issues

### Issue: "Analyzed 0 payloads"
**Cause:** HTTP traffic has no payload data
**Fix:** Check if HTTP requests/responses have body content

### Issue: "Found 0 C2 commands" but payloads analyzed
**Cause:** Payloads don't match detection patterns
**Fix:** Check debug output for "Interesting payload" messages
- If none appear, your payloads don't contain the expected patterns
- Share a sample payload for analysis

### Issue: HTTPS traffic not analyzed
**Cause:** Encrypted traffic can't be inspected
**Fix:** Use PCAP with decrypted HTTP or HTTP-only traffic

## Example Payload Formats

### Detected ✅
```
200;40;15;1000;10;600;1024;207.174.105.76:9998;80.75.212.57:9998;207.174.105.86:9998;74.119.149.37:9998;185.91.127.34:9998
```

### Not Detected ❌
```
GET /command HTTP/1.1       (No IP:port patterns)
Host: c2server.com
```

### Not Detected ❌
```
207.174.105.76              (Missing port numbers)
207.174.105.86
74.119.149.37
```

## Need Help?

If detections still don't work:

1. Run the script and capture console output
2. Look for all `[DEBUG]` lines
3. Share the debug output showing:
   - Number of HTTP records
   - Number of payloads analyzed
   - Any "Interesting payload" messages
4. Provide a sample of your HTTP payload (first 200 chars)

The debug output will help identify exactly why detection isn't working.
