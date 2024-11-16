# NSL-KDD Feature Extractor

## **Introduction**

The **NSL-KDD Feature Extractor** is a Python-based tool designed to process network traffic packets and extract features compliant with the NSL-KDD dataset format. It enables researchers and developers to analyze network traffic and apply machine learning models for intrusion detection, anomaly detection, or other cybersecurity applications.

## **Features**

1. **Packet Analysis**
   - Supports live packet capture using `scapy`.
   - Processes TCP, UDP, ICMP, ARP, and DNS packets.

2. **Feature Extraction**
   - Generates NSL-KDD dataset-compatible features for machine learning.
   - Includes connection-based and statistical features such as `same_srv_rate`, `srv_serror_rate`, and more.

3. **Customizable and Scalable**
   - Easily extendable for new protocols or custom features.
   - Handles both live traffic and offline packet captures.

4. **Internal Traffic Filtering**
   - Option to exclude internal traffic during feature extraction.

## **How It Works**

### **Workflow Diagram**

```
                      +------------------+
                      |   Network Traffic|
                      +------------------+
                               |
                               v
               +-------------------------------+
               |    Packet Capturing           |
               |  (Using Scapy Framework)      |
               +-------------------------------+
                               |
                               v
          +----------------------------------------+
          |    NSL-KDD Feature Extraction          |
          |  (network_feature_extractor.py)        |
          +----------------------------------------+
                               |
                               v
          +----------------------------------------+
          |        Generated Feature Set           |
          | - Duration, Protocol Type, Service     |
          | - Flag, Src Bytes, Dst Bytes           |
          | - Statistical Features (e.g.,          |
          |   srv_serror_rate, same_srv_rate)      |
          +----------------------------------------+
```

## **Setup**

### **Prerequisites**

- **Python 3.11** or later
- **Scapy** for packet capture
- **Pandas** for data manipulation

### **Installation**

1. Clone the repository:
   ```bash
   git clone <repository_url>
   cd nsl-kdd-feature-extractor
   ```

2. Install required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## **Usage**

### **1. Extracting Features**

```python
from network_feature_extractor import NetworkFeatureExtractor

# Initialize the extractor
extractor = NetworkFeatureExtractor(interface="eth0", timeout=60)

# Capture live traffic and extract features
def process_packet(packet):
    features = extractor.extract_features(packet)
    if features:
        print(features)

extractor.start_capture(callback=process_packet)
```

### **2. Example Output**

Extracted features will include:

```json
{
  "duration": 1.23,
  "protocol_type": "tcp",
  "service": "http",
  "flag": "SF",
  "src_bytes": 345,
  "dst_bytes": 512,
  "same_srv_rate": 0.75,
  "srv_serror_rate": 0.0,
  ...
}
```

## **Customization**

1. **Add New Features**:
   - Extend the `extract_features()` method to compute additional metrics.

2. **Handle Custom Protocols**:
   - Add specific processing for protocols like DNS or HTTP in `_extract_ip_features()` or `_extract_arp_features()`.

3. **Exclude Internal Traffic**:
   - Enable internal traffic detection using the `detect_internal=True` parameter.

## **Development Notes**

- This feature extractor aligns with the NSL-KDD dataset specification, enabling seamless integration with machine learning models trained on similar datasets.
- The modular structure makes it adaptable for other datasets or real-world scenarios.

## **Contributing**

We welcome contributions! If you’d like to extend the functionality or report a bug, feel free to submit a pull request or open an issue.

## **License**

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more details.
