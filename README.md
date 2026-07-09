# 🛡️ Network Traffic Analyzer & Threat Detection System

## 📌 Overview

Network Traffic Analyzer is a Python-based cybersecurity project that analyzes captured network traffic (PCAP files) using Scapy. The project extracts useful network information such as protocols, IP addresses, destination ports, and detects suspicious traffic based on predefined thresholds.

---

## 🚀 Features

- Analyze PCAP files captured using Wireshark
- Count total network packets
- Protocol statistics (TCP, UDP, ICMP)
- Top Source IP Analysis
- Top Destination IP Analysis
- Top Destination Port Analysis
- Suspicious IP Detection
- Generate CSV Reports
- Generate Protocol Distribution Pie Chart

---

## 🛠️ Technologies Used

- Python
- Scapy
- Wireshark
- Pandas
- Matplotlib

---

## 📂 Project Structure

```
Network-Traffic-Analysis/

│

├── captures/

│ └── traffic.pcapng

│

├── reports/

│ ├── traffic_report.csv

│ ├── suspicious_ips.csv

│ └── protocol_chart.png

│

├── scripts/

│ └── analyzer.py

│

├── README.md

└── requirements.txt
```

---

## 📊 Output

The project generates:

- Protocol Statistics
- Source/Destination IP Analysis
- Destination Port Analysis
- Suspicious IP Alerts
- CSV Reports
- Pie Chart Visualization

---

## 🎯 Future Improvements

- Real-Time Packet Capture
- Port Scan Detection
- DDoS Detection
- Email Alert System
- Web Dashboard using Flask

---

## 👨‍💻 Developed By

**Kirankumar Thakor**