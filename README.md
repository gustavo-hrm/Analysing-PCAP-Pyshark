# Analysing-PCAP-Pyshark

Network traffic analysis tool with ML-enhanced DDoS & C2 detection and comprehensive protocol coverage.

## Version
**Stability v22.0** - ML-Enhanced DDoS & C2 Detection with Priority 3 Protocol Coverage

## Features

### Core Capabilities
- **PCAP Parsing**: Single-pass packet capture analysis with payload extraction
- **Protocol Detection**: 14+ protocols including TCP, UDP, ICMP, DNS, HTTP, TLS, SMB, RDP, SSH, FTP, SMTP, IRC, P2P
- **Threat Detection**: C2 communications, DDoS attacks, beaconing, data exfiltration, brute force
- **Machine Learning**: Random Forest classification, Isolation Forest anomaly detection
- **Interactive Dashboard**: HTML/JavaScript dashboard with DataTables integration

### Priority 1: Enhanced C2 Detection
- DNS tunneling detection with entropy analysis
- HTTP C2 target distribution analysis
- Beaconing detection with jitter tolerance
- JA3 fingerprinting for TLS analysis
- Advanced DGA detection with Levenshtein distance

### Priority 2: ML-Enhanced Features
- Change Point Detection (CPD) with CUSUM algorithm
- Temporal pattern analysis
- Sliding window anomaly detection
- Bidirectional flow analysis
- Flow-level statistical analysis

### Priority 3: Expanded Protocol Coverage ✨ NEW
- **SMB/CIFS** (Ports 445, 139): Lateral movement, ransomware detection
- **RDP** (Port 3389): Brute force attack detection
- **SSH** (Port 22): Scanning, brute force, tunneling detection
- **FTP/SFTP** (Ports 20, 21): Data exfiltration detection
- **SMTP** (Ports 25, 587, 465): Spam botnet detection
- **IRC** (Ports 6667, 6697, 194): C2 channel detection
- **P2P** (BitTorrent DHT): Malware distribution detection

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

### Basic Usage
```bash
python3 main.py
```

### Custom PCAP File
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

### Protocol Detection (Priority 3)
- SMB/CIFS activity with lateral movement scoring
- RDP brute force attempts
- SSH scanning and attacks
- FTP data exfiltration
- SMTP spam campaigns
- IRC C2 channels
- P2P malware distribution
- Protocol threat summary

## Testing

### Run All Tests
```bash
# Priority 2 tests
python3 test_priority2.py

# Priority 3 tests
python3 test_priority3.py

# Integration tests
python3 test_integration_priority3.py
```

### Test Coverage
- 8 Priority 2 tests (change point detection, DGA, flow analysis)
- 10 Priority 3 tests (protocol detection functions)
- 7 Integration tests (synthetic attack scenarios)

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
- Priority 3 enhancement: GitHub Copilot

## Changelog

### v22.0 (2025-11-19) - Priority 3: Expanded Protocol Coverage
- Added SMB/CIFS lateral movement detection
- Added RDP brute force detection
- Added SSH scanning and attack detection
- Added FTP/SFTP exfiltration detection
- Added SMTP spam botnet detection
- Added IRC C2 channel detection
- Added P2P malware distribution detection
- Added protocol threat aggregation
- Added 8 new dashboard tables
- Created comprehensive test suite (17 tests)
- 0 security vulnerabilities

### v21.0 - Priority 2: ML-Enhanced Detection
- ML-based DDoS classification
- Anomaly detection with Isolation Forest
- Change point detection with CUSUM
- Temporal pattern analysis
- Flow-level statistical analysis

### v20.0 - Priority 1: Enhanced C2 Detection
- DNS tunneling detection
- HTTP C2 target distribution
- Beaconing detection with jitter
- JA3 fingerprinting
- Advanced DGA detection
