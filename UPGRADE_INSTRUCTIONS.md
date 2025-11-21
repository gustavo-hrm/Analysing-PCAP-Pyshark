# Upgrade Instructions for Botnet Detection Enhancement

## Files Modified in This PR

This PR modifies the following files. **You must update ALL of them** for the feature to work:

### Required Files:
1. **`botnet_detector.py`** ⚠️ CRITICAL
   - Updated all detection functions to accept `source_id` and `pcap_file` parameters
   - Without this file, you'll get: `detect_botnet_in_tcp() takes 1 positional argument but 3 were given`

2. **`main.py`** ⚠️ CRITICAL
   - Updated to call detection functions with new parameters
   - Added new evidence table to dashboard

### Optional Files:
3. **`test_botnet_report.py`** (new)
   - Test suite for source tracking functionality
   
4. **`BOTNET_REPORT_ENHANCEMENT.md`** (new)
   - Complete documentation of the feature

## Upgrade Steps

### Step 1: Pull/Copy All Files
```bash
# If using git
git pull origin copilot/update-botnet-report-feature

# Or manually copy all 4 files listed above
```

### Step 2: Clear Python Cache
```bash
# Clear cached Python modules
rm -rf __pycache__
rm -f *.pyc
```

### Step 3: Run the Analysis
```bash
python3 main.py [your_arguments]
```

## Verification

After upgrade, you should see output like:
```
[28/42] Detecting botnet families across protocols...
  - Source 'default' (your_file.pcap): X detections
  - Total unique botnet detections: X
```

**No errors** - If you see this error, you're missing the updated `botnet_detector.py`:
```
❌ detect_botnet_in_tcp() takes 1 positional argument but 3 were given
```

## Troubleshooting

### Issue: Function signature error
**Problem:** `detect_botnet_in_tcp() takes 1 positional argument but 3 were given`

**Solution:** You have the new `main.py` but the old `botnet_detector.py`. Copy the updated `botnet_detector.py` file and clear Python cache.

### Issue: Tables are empty
**Problem:** Botnet detection tables show no data

**Possible causes:**
1. Your PCAP file doesn't contain traffic matching botnet signatures (most common - normal traffic won't trigger detections)
2. BOTNET_DETECTION_AVAILABLE is False (check console output)
3. Error in detection (check console for error messages)

**To verify:** Check the console output for:
```
[28/42] Detecting botnet families across protocols...
  - Source 'xxx' (file.pcap): 0 detections
```
If you see "0 detections", it means your PCAP doesn't have botnet traffic.

### Issue: Module import errors
**Problem:** `ModuleNotFoundError: No module named 'botnet_detector'`

**Solution:** Make sure `botnet_detector.py` is in the same directory as `main.py`.

## What This Feature Does

This enhancement adds:
1. **Source tracking** - Each detection shows which PCAP file it came from
2. **Evidence table** - Detailed table with PCAP File, Source ID, Family, Severity, Confidence, Evidence, IPs, Protocol, Payload Sample
3. **Multi-source support** - Analyze multiple PCAP files and correlate findings

## Dashboard Changes

### New Table: "Botnet Detection Evidence Details"
Shows detailed evidence for each detection with source file tracking.

### Updated Table: "Botnet Family Detection" 
Now includes a "PCAP File" column showing which file each detection came from.

## Need Help?

If you're still having issues after following these steps, please provide:
1. Console output from running `python3 main.py`
2. Which files you updated
3. Output of `ls -la botnet_detector.py main.py`
