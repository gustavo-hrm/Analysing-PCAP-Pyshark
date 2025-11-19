# ML-Enhanced DDoS & C2 Detection - Priority 1 Features

## Overview

This implementation adds machine learning capabilities to the PCAP analysis tool, enhancing DDoS and C2 detection with:

1. **Random Forest Classifier** for DDoS attack classification
2. **Isolation Forest** for zero-day anomaly detection
3. **Adaptive Baseline Profiling** with dynamic thresholds
4. **Jitter-Tolerant Beaconing** detection using autocorrelation

## Features Implemented

### 1. Machine Learning Models

#### Random Forest DDoS Classifier
- **Function**: `ml_ddos_detection(features)`
- **Purpose**: Classifies traffic as ATTACK or NORMAL using supervised learning
- **Training**: Heuristic-based labeling (high packet rate + destination diversity + SYN ratio)
- **Output**: Predictions with ML confidence scores (0-100)

#### Isolation Forest Anomaly Detector
- **Function**: `anomaly_detection(features)`
- **Purpose**: Detects zero-day attacks and novel traffic patterns
- **Method**: Unsupervised outlier detection with StandardScaler normalization
- **Output**: Anomaly scores (0-100) and baseline deviation indicators

### 2. Feature Engineering

#### Traffic Features Extracted (20+)
The `extract_ml_features()` function extracts comprehensive features from network traffic:

**Temporal Features:**
- Packet rate (packets/sec)
- Duration
- Inter-arrival time statistics (mean, std, min, max)

**Volume Features:**
- Total packets and bytes
- Average packet size
- Standard deviation of packet sizes
- Byte rate

**Diversity Features:**
- Unique destination IPs
- Unique source/destination ports
- Port entropy
- Destination IP entropy

**TCP-Specific Features:**
- SYN count and ratio (SYN/ACK)
- ACK count
- RST count

**Protocol Features:**
- Protocol type (TCP/UDP/ICMP)
- Per-protocol statistics

### 3. Baseline Profiling with Adaptive Thresholds

#### Baseline Establishment
- **Function**: `establish_baseline(traffic_df, window='300s')`
- **Statistics Calculated**: Mean, Median, Std Dev, 95th & 99th percentiles, Min/Max
- **Granularity**: Per-source IP for all numeric features
- **Use Case**: Create normal traffic profiles for comparison

#### Adaptive Thresholds
- **Function**: `calculate_adaptive_threshold(baseline, metric, sensitivity=3)`
- **Formula**: `threshold = mean + (sensitivity × std)`
- **Benefit**: Automatically adjusts to network behavior vs. static thresholds
- **Example**: If normal packet rate is 100±15 pps, threshold = 100 + (3×15) = 145 pps

### 4. Jitter-Tolerant Beaconing Detection

#### Enhanced Beaconing Algorithm
- **Function**: `detect_jittered_beaconing(times, max_jitter=0.5)`
- **Methods**:
  1. **Low CV Analysis**: Traditional coefficient of variation (CV ≤ 0.35)
  2. **Autocorrelation**: Detects periodic patterns even with 10-50% jitter
- **Supports**: Cobalt Strike sleep jitter, randomized beaconing
- **Output**: Period, jitter percentage, confidence score, detection method

#### How Autocorrelation Works
1. Computes correlation between time series and lagged versions
2. Identifies peaks indicating periodicity
3. Tolerates timing variance while detecting underlying patterns
4. Minimum 5 lags required for robust detection

## Configuration

### New Configuration Parameters

```python
# ML & Advanced Detection Configuration
ML_ENABLED = True                       # Enable ML-based detection
BASELINE_WINDOW = 300                   # Baseline window in seconds (5 min)
ADAPTIVE_THRESHOLD_SENSITIVITY = 3      # Standard deviations for thresholds
JITTER_TOLERANCE = 0.5                  # Max jitter tolerance (0.0-1.0)
ML_MIN_TRAINING_SAMPLES = 10            # Minimum samples for ML training
AUTOCORR_MIN_LAGS = 5                   # Minimum lags for autocorrelation
```

## Installation

### Dependencies

Install required packages:
```bash
pip install -r requirements.txt
```

Core dependencies:
- `numpy` - Numerical computing
- `pandas` - Data manipulation
- `scikit-learn` - Machine learning models
- `tqdm` - Progress bars

### Graceful Degradation

If scikit-learn is not available:
- ML features automatically disable
- Script falls back to heuristics-only detection
- All other features continue to work

## Usage

### Running the Analysis

```bash
python3 main.py
```

The script will automatically:
1. Parse PCAP files
2. Extract ML features (if enabled)
3. Establish traffic baselines
4. Run ML classification and anomaly detection
5. Detect jittered beacons
6. Generate enhanced dashboard

### Pipeline Steps

The ML-enhanced pipeline has 20 steps:

1-5: PCAP parsing and aggregation
6: **ML feature extraction** (20+ features)
7: **Baseline profiling** (per-IP statistics)
8: **Random Forest DDoS classification**
9: **Isolation Forest anomaly detection**
10-19: Traditional heuristics (C2, DDoS, beaconing, etc.)
20: Dashboard generation

### Output

The dashboard (`dashboard.html`) includes:

1. **ML Detection Summary Card**
   - Total ML detections count
   - Feature status indicators

2. **ML DDoS Classification Table**
   - Source IP, Protocol, Prediction
   - ML Score (confidence)
   - Packet rate, Destination diversity

3. **ML Anomaly Detection Table**
   - Source IP, Protocol
   - Anomaly Score, Baseline Deviation
   - Traffic characteristics

4. **Enhanced Beaconing Table**
   - Period, CV, Jitter percentage
   - Detection method (cv_analysis or autocorrelation)

## Testing

### Run All Tests

```bash
# IPv6 support tests
python3 test_ipv6.py

# ML features tests
python3 test_ml_features.py
```

### Test Coverage

**test_ipv6.py** (existing):
- ✅ IPv6 private address detection
- ✅ Unified IPv4/IPv6 handling
- ✅ IP layer extraction

**test_ml_features.py** (new):
- ✅ ML feature extraction (22 features)
- ✅ Baseline establishment
- ✅ Adaptive threshold calculation
- ✅ Jittered beaconing detection
- ✅ Random Forest DDoS classification
- ✅ Isolation Forest anomaly detection

## Performance Considerations

### Computational Complexity

- **Feature Extraction**: O(n) where n = packet count
- **Random Forest**: O(n × trees × log(samples)) ≈ O(n log n) with 50 trees
- **Isolation Forest**: O(n × trees × log(samples)) ≈ O(n log n) with 100 trees
- **Beaconing (Autocorr)**: O(n × lags) ≈ O(n) with limited lags

### Memory Usage

- Features stored per source IP (not per packet)
- Baselines maintain statistics (not raw data)
- ML models trained on aggregated features only

### Scalability

- **Small PCAPs (<1GB)**: Full ML analysis in <1 minute
- **Medium PCAPs (1-10GB)**: 1-5 minutes
- **Large PCAPs (>10GB)**: Consider increasing `ML_MIN_TRAINING_SAMPLES` threshold

## Examples

### Example 1: DDoS Detection with ML

```
[ML] Random Forest trained on 45 samples, detected 8 potential attacks
[ML] Isolation Forest detected 5 anomalies from 45 samples

=== Detection Summary ===
C2 Indicators: 12
DDoS Attacks: 23
Beacons Detected: 4
ML DDoS Predictions: 8
ML Anomalies: 5
```

### Example 2: Jittered Beacon Detection

Traditional CV-based detection misses beacons with >35% jitter.

**Before (v20.4)**: Beacon with 40% jitter → Not detected
**After (v21.0)**: Beacon with 40% jitter → Detected via autocorrelation

```
INDICATOR: 192.168.1.100 → 8.8.8.8
TYPE: Jittered beaconing (autocorrelation)
SCORE: 85
MEAN_PERIOD: 60.2s
JITTER: 41.5%
METHOD: autocorrelation
```

### Example 3: Adaptive Thresholds

**Static Threshold** (old):
- SYN flood threshold: 100 packets (fixed)
- Problem: False positives on busy networks

**Adaptive Threshold** (new):
- Normal traffic: 80±20 SYN packets
- Adaptive threshold: 80 + (3×20) = 140 packets
- Benefit: Adjusts to actual network baseline

## Troubleshooting

### "ML libraries not available"

**Cause**: scikit-learn not installed

**Solution**:
```bash
pip install scikit-learn
```

### "Insufficient data for ML"

**Cause**: Less than `ML_MIN_TRAINING_SAMPLES` (default: 10) sources

**Solution**:
- Normal for small PCAPs
- ML predictions skipped, heuristics still work
- Consider lowering threshold if needed

### "Insufficient class diversity for RF training"

**Cause**: All traffic looks similar (all normal or all attack)

**Solution**:
- Expected on homogeneous traffic
- Isolation Forest may still detect outliers
- Heuristics provide primary detection

## Backward Compatibility

### Maintained Features

✅ All existing detection methods work unchanged
✅ IPv4 and IPv6 support preserved
✅ Dashboard layout compatible
✅ Existing configurations valid

### Graceful Degradation

✅ Works without scikit-learn (heuristics only)
✅ Works without numpy (limited functionality)
✅ Empty ML tables when disabled

### Migration Notes

No breaking changes - existing workflows continue working.

To enable ML features:
1. Install dependencies: `pip install -r requirements.txt`
2. Restart analysis: `python3 main.py`

## Security Considerations

### Validated Features

- ✅ No code execution from PCAP data
- ✅ Input validation on all numeric features
- ✅ NaN/Inf handling in ML pipelines
- ✅ Division by zero protection

### Privacy

- Features extracted per-IP (no payload content)
- Baselines stored as statistics (no raw packets)
- Dashboard shows aggregated results only

## Future Enhancements

Potential additions for Priority 2+:

1. **Deep Learning Models**: LSTM for sequence analysis
2. **Feature Importance Visualization**: Charts showing top features
3. **Model Persistence**: Save/load trained models
4. **Real-time Classification**: Streaming PCAP analysis
5. **Ensemble Methods**: Combine multiple ML models
6. **Explainable AI**: SHAP values for predictions

## References

### Algorithms

- **Random Forest**: Breiman, L. (2001). "Random Forests". Machine Learning.
- **Isolation Forest**: Liu, F.T., et al. (2008). "Isolation Forest". ICDM.
- **Autocorrelation**: Box, G.E.P., Jenkins, G.M. (1976). Time Series Analysis.

### Threat Detection

- **Cobalt Strike Jitter**: Techniques used by modern C2 frameworks
- **DDoS Classification**: Network traffic-based ML approaches
- **Beaconing Detection**: Periodic communication pattern analysis

## License

Same as parent project.

## Contributors

Generated by GitHub Copilot for gustavo-hrm/Analysing-PCAP-Pyshark
