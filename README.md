# Analysing-PCAP-Pyshark

Network traffic analysis tool with ML-enhanced DDoS & C2 detection and comprehensive protocol coverage.

## Version
**Stability v23.0** - Multi-Source PCAP Correlation with ML-Enhanced Detection

## Features

### Core Capabilities
- **PCAP Parsing**: Single-pass packet capture analysis with payload extraction
- **Protocol Detection**: 14+ protocols including TCP, UDP, ICMP, DNS, HTTP, TLS, SMB, RDP, SSH, FTP, SMTP, IRC, P2P
- **Threat Detection**: C2 communications, DDoS attacks, beaconing, data exfiltration, brute force
- **Machine Learning**: Random Forest classification, Isolation Forest anomaly detection
- **Interactive Dashboard**: HTML/JavaScript dashboard with DataTables integration
- DNS tunneling detection with entropy analysis
- HTTP C2 target distribution analysis
- Beaconing detection with jitter tolerance
- JA3 fingerprinting for TLS analysis
- Advanced DGA detection with Levenshtein distance
- Change Point Detection (CPD) with CUSUM algorithm
- Temporal pattern analysis
- Sliding window anomaly detection
- Bidirectional flow analysis
- Flow-level statistical analysis
- **SMB/CIFS** (Ports 445, 139): Lateral movement, ransomware detection
- **RDP** (Port 3389): Brute force attack detection
- **SSH** (Port 22): Scanning, brute force, tunneling detection
- **FTP/SFTP** (Ports 20, 21): Data exfiltration detection
- **SMTP** (Ports 25, 587, 465): Spam botnet detection
- **IRC** (Ports 6667, 6697, 194): C2 channel detection
- **P2P** (BitTorrent DHT): Malware distribution detection

### Multi-Source Correlation
- **Shared C2 Infrastructure**: Detects same C2 IPs, domains, JA3 fingerprints across networks
- **Coordinated Attacks**: Identifies DDoS campaigns and botnet activity across sources
- **Lateral Movement**: Tracks attackers moving between monitored networks
- **Beacon Synchronization**: Detects synchronized C2 beacons (shared heartbeat patterns)
- **Cross-Network Analysis**: Correlates threats across 2+ PCAP sources
- **Confidence Scoring**: ML-based confidence scores for correlation detections

## Installation

### Requirements
```bash
pip install -r requirements.txt
```

### Dependencies
- numpy >= 1.21.0
- pandas >= 1.3.0
- tqdm >= 4.62.0
- scikit-learn >= 1.0.0 (optional, for ML features)
- scipy >= 1.7.0 (optional, for ML features)
- scapy >= 2.4.5 (optional, for PCAP parsing)

## Usage

### Basic Usage (Single File)
```bash
python3 main.py
```

### Multi-Source Analysis
Analyze multiple PCAP files from different network sensors:

```bash
# Multiple sources with custom names
python3 main.py --sources monitor1:capture1.pcap monitor2:capture2.pcap monitor3:capture3.pcap

# Using wildcard pattern
python3 main.py --sources-dir /pcaps/*.pcap

# Simple file list (uses filenames as source IDs)
python3 main.py --sources file1.pcap file2.pcap file3.pcap
```

### Custom PCAP File (Legacy)
Edit `FILE_PCAP` variable in main.py:
```python
FILE_PCAP = "your_capture.pcapng"
```

### Output
Generates two files:
- `dashboard.html` - Interactive web dashboard
- `dashboard.js` - Dashboard data and rendering logic

Open `dashboard.html` in a web browser to view the analysis.

## Dashboard Tables

### Network Traffic
- DNS queries and responses
- HTTP requests and responses
- TLS connections with JA3 fingerprints
- TCP flows with flags and payloads
- UDP traffic
- ICMP traffic

### Threat Detection
- C2 indicators (JA3, high entropy, suspicious domains)
- Advanced heuristics (fanout, cluster analysis)
- Beaconing detection
- DNS tunneling
- DDoS attack indicators

### ML Detection
- ML-based DDoS predictions
- Anomaly detection results
- Traffic feature analysis
- Change point detection
- Temporal patterns
- Flow anomalies

### Protocol Detection
- SMB/CIFS activity with lateral movement scoring
- RDP brute force attempts
- SSH scanning and attacks
- FTP data exfiltration
- SMTP spam campaigns
- IRC C2 channels
- P2P malware distribution
- Protocol threat summary

### Multi-Source Correlation
- Source metadata (file names, packet counts)
- Shared C2 infrastructure across sources
- Coordinated attack patterns (DDoS, botnets)
- Lateral movement detection (cross-network)
- Synchronized beacon timing
- Confidence-scored correlations

## Configuration

### Protocol Analysis
Enable/disable protocol detection in main.py:
```python
PROTOCOL_ANALYSIS = {
    'SMB': True,
    'RDP': True,
    'SSH': True,
    'FTP': True,
    'SMTP': True,
    'IRC': True,
    'P2P': True,
}
```

### Thresholds
Adjust detection thresholds:
```python
SMB_LATERAL_THRESHOLD = 5       # Hosts accessed
RDP_BRUTE_THRESHOLD = 10        # Failed attempts
SSH_BRUTE_THRESHOLD = 10        # Failed attempts
FTP_EXFIL_SIZE = 10485760       # 10MB
SMTP_MASS_MAIL_THRESHOLD = 50   # Emails per minute
```

### Multi-Source Correlation Settings
Configure correlation parameters in main.py:
```python
MULTI_SOURCE_ENABLED = True              # Enable/disable correlation
CORRELATION_TIME_WINDOW = 300            # 5 minutes for temporal correlation
MIN_SOURCES_FOR_CORRELATION = 2          # Minimum sources to correlate
CORRELATION_CONFIDENCE_THRESHOLD = 0.7   # Minimum confidence (0.0-1.0)
```

**How Correlation Works**:
1. **Shared C2**: Same IP/domain/JA3 in 2+ sources → Confidence +10 per source
2. **Attack Patterns**: Same attack type/target within time window → Confidence starts at 70
3. **Lateral Movement**: Same attacker IP in multiple sources → Confidence +8 per source
4. **Beacons**: Similar interval timing (±10s buckets) → Confidence starts at 80

**Minimum Requirements**:
- At least 2 sources required (configurable)
- SOURCE_ID automatically tracked in all packet data
- Temporal correlation uses 5-minute sliding window
FTP_EXFIL_SIZE = 10485760       # 10MB
SMTP_MASS_MAIL_THRESHOLD = 50   # Emails per minute
```

### ML Configuration
```python
ML_ENABLED = True               # Enable/disable ML features
CPD_ENABLED = True              # Enable change point detection
DGA_MIN_SCORE = 60              # DGA detection threshold
```

## Documentation

- `PRIORITY3_IMPLEMENTATION.md` - Detailed protocol detection documentation
- `PRIORITY3_SUMMARY.md` - Implementation summary and metrics
- `IMPLEMENTATION_SUMMARY.md` - Overall implementation details
- `PRIORITY2_IMPLEMENTATION.md` - Priority 2 feature documentation

## Attack Detection Examples

### SMB Lateral Movement (WannaCry/NotPetya)
- Detects one source accessing multiple SMB targets
- Identifies SMBv1 usage (vulnerable to EternalBlue)
- Flags admin share access (ADMIN$, C$, IPC$)
- Score: 95/100 with 10+ targets

### RDP Brute Force
- Detects multiple connection attempts
- Identifies distributed attacks (multiple sources)
- Tracks failed authentication patterns
- Score: 90/100 with 20+ attempts

### SSH Port Scanning
- Detects one source scanning multiple SSH ports
- Identifies SSH-1.x usage (deprecated)
- Tracks brute force patterns
- Score: 85/100 with 20+ targets

### FTP Data Exfiltration
- Detects large file transfers (>10MB)
- Identifies anonymous access attempts
- Tracks unusual upload patterns
- Score: 74/100 for 14MB transfer

### SMTP Spam Botnet
- Detects mass mailing campaigns
- Identifies internal compromised hosts
- Tracks multiple SMTP server usage
- Score: 95/100 with 50+ emails

### IRC C2 Botnet
- Detects IRC channel joining
- Identifies bot command patterns
- Tracks DCC file transfers (malware distribution)
- Score: 90/100 with 5+ bots

### P2P Malware Distribution
- Detects BitTorrent DHT traffic
- Identifies peer-to-peer swarms
- Tracks internal-to-external P2P
- Score: 85/100 with 30+ peers

## Multi-Source Correlation Examples

### Shared C2 Infrastructure Detection
**Scenario**: Same C2 domain detected across 3 different network sensors
```
C2 Indicator: malicious-c2.example.com
Sources: datacenter1, office-network, remote-site
Source Count: 3
Confidence: 90/100
Type: Shared C2 Infrastructure
```
**Interpretation**: All three networks are compromised by the same threat actor using shared C2 infrastructure.

### Coordinated DDoS Attack
**Scenario**: Simultaneous SYN flood detected from multiple locations
```
Attack Pattern: SYN_FLOOD_10.0.0.1
Sources: sensor-east, sensor-west, sensor-central
Source Count: 3
Time Spread: 120s (within 5-minute window)
Confidence: 85/100
Type: Coordinated DDoS Attack
```
**Interpretation**: Distributed attack targeting same victim across network segments - likely botnet activity.

### Lateral Movement Detection
**Scenario**: Attacker IP active in multiple monitored networks
```
Attacker IP: 192.168.100.50
Sources: dmz-network, internal-lan, production-vlan
Source Count: 3
Activities: SMB Lateral, RDP Brute Force, SSH Scanning
Avg Threat Score: 87.5
Confidence: 91/100
```
**Interpretation**: Clear lateral movement pattern - attacker pivoting through networks after initial compromise.

### Synchronized C2 Beacons
**Scenario**: Coordinated C2 check-ins across networks
```
Beacon Destination: 203.0.113.10
Avg Interval: 60.3s
Sources: branch-office-1, branch-office-2, headquarters
Source Count: 3
Confidence: 92/100
Type: Synchronized C2 Beacon
```
**Interpretation**: Multiple infected hosts checking in with C2 on same schedule - coordinated botnet activity.

## Security

### CodeQL Analysis
All code has been scanned with CodeQL:
- 0 security vulnerabilities detected
- Safe handling of user input
- No SQL injection risks
- No command injection risks

### Threat Intelligence
Detection based on:
- Official RFCs for all protocols
- Known attack patterns (WannaCry, NotPetya, Mirai)
- MITRE ATT&CK framework techniques
- Industry best practices
- Botnet family signatures (Emotet, TrickBot, Mirai, Cobalt Strike, Sliver, Qakbot, AsyncRAT, Meterpreter)

## Botnet Family Detection

### Overview
The tool includes an extensible botnet family detection system that scans network traffic for known malware signatures, C2 patterns, and behavioral indicators across multiple protocols (TCP, HTTP, TLS/JA3, DNS, IRC).

### Detected Families
Currently includes signatures for:
- **Emotet** - Banking trojan and malware loader
- **TrickBot** - Banking trojan with lateral movement capabilities
- **Mirai** - IoT botnet for DDoS attacks
- **Cobalt Strike** - Post-exploitation framework (commercial tool, often abused)
- **Sliver** - Open-source C2 framework
- **Qakbot (QBot)** - Banking trojan with worm capabilities
- **AsyncRAT** - Open-source remote access trojan
- **Meterpreter** - Metasploit Framework payload
- **Unknown_Botnet** - Generic placeholder for unknown families

### Adding New Botnet Families

To add a new botnet family to the detection system:

1. **Edit `botnet_signatures.py`** - Add a new entry to the `BOTNET_SIGNATURES` dictionary:

```python
"NewBotnet": {
    "description": "Description of the botnet/malware",
    "family": "NewBotnet",
    "category": "Trojan/Botnet/RAT/C2",
    "ports": [8080, 443],  # Common C2 ports
    "ja3_fingerprints": [
        "abc123...",  # JA3 hash if known
    ],
    "payload_patterns": [
        b"unique_string",  # Byte patterns in payloads
        b"botnet_marker",
    ],
    "http_endpoints": [
        "/gate.php",  # Common C2 endpoints
        "/panel",
    ],
    "http_user_agents": [
        "Mozilla/5.0 custom_ua",  # Specific User-Agents
    ],
    "dns_patterns": [
        r".*\.suspicious-tld$",  # Regex for DNS queries
    ],
    "confidence_base": 85,  # Base confidence score (0-100)
    "severity": "HIGH",  # HIGH, CRITICAL, MEDIUM, LOW
},
```

2. **Signature Fields Explained:**
   - `ports`: List of TCP/UDP ports commonly used by the botnet
   - `ja3_fingerprints`: TLS client fingerprints (use JA3 hash)
   - `payload_patterns`: Byte strings found in network payloads
   - `http_endpoints`: URL paths used for C2 communication
   - `http_user_agents`: Specific User-Agent strings
   - `dns_patterns`: Regex patterns for DNS queries (C2 domains)
   - `magic_bytes`: File headers or protocol magic numbers
   - `beacon_intervals`: Common beacon timing (seconds)
   - `confidence_base`: Starting confidence (adjusted by evidence)
   - `severity`: CRITICAL, HIGH, MEDIUM, or LOW

3. **Detection Scoring:**
   - Multiple matching indicators increase confidence
   - Evidence is logged for each detection
   - Minimum detection threshold: 50% confidence

4. **Test Your Signature:**
```bash
python3 botnet_signatures.py  # View all signatures
python3 main.py  # Run analysis with new signature
```

### Threat Intelligence Feed Integration (TODO)

**Planned Features:**
- Automatic download of IOCs from open-source threat feeds
- Integration with abuse.ch feeds (URLhaus, Feodo Tracker, Malware Bazaar)
- AlienVault OTX integration
- Emerging Threats ruleset support
- Daily/hourly feed updates with local caching
- Automatic signature merging

**Implementation Roadmap:**
1. Create `download_threat_intel_feeds()` function in `botnet_signatures.py`
2. Add feed parsers for common formats (CSV, JSON, STIX)
3. Implement local caching with TTL
4. Add CLI options for feed management
5. Scheduled updates via cron/systemd timer

To contribute threat intelligence integration, see `botnet_signatures.py` TODO comments.

## C2 IP Blocklist Correlation

The tool includes a C2 IP blocklist correlation feature that matches observed traffic against known Command & Control server IPs.

### Features

- **Automatic URL Fetching**: Downloads C2 IPs from known threat intelligence feeds (Feodo Tracker, SSL Blacklist)
- **Multi-Protocol Correlation**: Scan TCP, HTTP, DNS, TLS, and UDP traffic
- **ASN Enrichment**: Show ASN number and owner organization for matched IPs
- **Reputation Scoring**: Classify matches as MALICIOUS, SUSPICIOUS, or UNKNOWN
- **Dashboard Integration**: View matches in the web dashboard
- **CSV Export**: Export matches to CSV for further analysis

### Pre-configured C2 Blocklist Sources

The tool automatically fetches from these well-known threat intelligence sources:

| Source | URL | Description |
|--------|-----|-------------|
| Feodo Tracker | https://feodotracker.abuse.ch/downloads/ipblocklist.txt | Tracks Emotet, Dridex, TrickBot, QakBot, BazarLoader |
| SSL Blacklist | https://sslbl.abuse.ch/blacklist/sslipblacklist.txt | IPs with malicious SSL certificates |
| Abuse.ch Recommended | https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt | Comprehensive botnet C2 list |

### Output Table Columns

| Column | Description |
|--------|-------------|
| PCAP_FILE | Name of the analyzed PCAP file |
| PROTOCOL | Network protocol (TCP, HTTP, DNS, TLS, UDP) |
| SRC_IP | Source IP address |
| DST_IP | Destination IP address |
| DEST_PORT | Destination port |
| MATCHED_C2_IP | The IP that matched the C2 blocklist |
| ASN | Autonomous System Number of the matched IP |
| ASN_OWNER | Organization that owns the ASN |
| REPUTATION | Threat reputation (MALICIOUS, SUSPICIOUS, UNKNOWN) |

### Configuring C2 Blocklist Sources

#### Option 1: Use Pre-configured Sources (Recommended)
The tool automatically fetches from known sources when you run the analysis:
```python
from c2_blocklist import load_c2_blocklist_from_urls

# Load from all known sources (Feodo Tracker, SSL Blacklist, etc.)
c2_ips = load_c2_blocklist_from_urls()
```

#### Option 2: Add Custom URLs
Add your own blocklist URLs to `KNOWN_C2_BLOCKLIST_URLS` in `c2_blocklist.py`:
```python
KNOWN_C2_BLOCKLIST_URLS = {
    'feodo_tracker': 'https://feodotracker.abuse.ch/downloads/ipblocklist.txt',
    'sslbl': 'https://sslbl.abuse.ch/blacklist/sslipblacklist.txt',
    # Add your custom sources here:
    'my_custom_feed': 'https://example.com/my_blocklist.txt',
}
```

#### Option 3: Load from Local File
```python
from c2_blocklist import load_c2_blocklist

# Load from a local file
c2_ips = load_c2_blocklist('my_c2_list.txt')
```

#### Option 4: Add Hardcoded IPs
Add IPs to `DEFAULT_C2_IPS` set in `c2_blocklist.py`:
```python
DEFAULT_C2_IPS = {
    "45.33.32.156",
    "104.131.74.14",
    # Add more IPs here
}
```

### Usage Example

```python
from c2_blocklist import load_c2_blocklist_from_urls, correlate_c2_ips_from_pcap

# Load blocklist from all known sources + defaults
c2_ips = load_c2_blocklist_from_urls()

# Correlate with parsed traffic
hits = correlate_c2_ips_from_pcap(
    tcp_df=tcp_data,
    http_df=http_data, 
    c2_ips=c2_ips,
    pcap_file='capture.pcap'
)

# Print results
print_c2_hits_table(hits)

# Export to CSV
export_c2_hits_csv(hits, 'c2_matches.csv')
```

## Performance

- Single-pass PCAP parsing
- Efficient DataFrame operations
- Memory-limited payload storage (5000 bytes max)
- Graceful handling of large captures
- Optimized aggregation queries

## License

See repository license file.

## Contributing

See CONTRIBUTING.md for development guidelines.

## Authors

- Original implementation: gustavo-hrm
