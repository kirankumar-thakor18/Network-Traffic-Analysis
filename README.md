# 🛡️ Network Traffic Analyzer & Threat Detection System

## 📌 Overview

Network Traffic Analyzer is a Python-based cybersecurity project that analyzes captured network traffic (PCAP/PCAPNG files) using Scapy. The tool extracts network insights (protocols, IP addresses, ports, timing) and applies anomaly-detection heuristics to flag potentially suspicious traffic.

---

## 🚀 Features

- Analyze PCAP/PCAPNG files captured using Wireshark
- Count total network packets
- Protocol statistics (TCP, UDP, ICMP, ARP, other)
- **IPv4 and IPv6 support**
- Capture time analysis (duration, average packet rate)
- Top Source IP Analysis
- Top Destination IP Analysis
- Top Destination Port Analysis
- **Anomaly / threat detection:**
  - Traffic flood detection using a **dynamic statistical threshold** (mean + 3σ)
  - Port scan detection using a probe-style heuristic (many destination ports, few packets each)
  - Address classification (Private / Public / Link-local / Loopback) for context
- Generate CSV reports
- Generate visualization charts (protocol pie chart + top ports bar chart)

---

## 🛠️ Technologies Used

- Python
- Scapy
- Wireshark
- Pandas
- Matplotlib
- ipaddress (stdlib)

---

## 📂 Project Structure

```
Network-Traffic-Analysis/

│
├── captures/

│   └── traffic.pcapng

│
├── reports/

│   ├── traffic_report.csv

│   ├── top_source_ips.csv

│   ├── top_destination_ips.csv

│   ├── top_destination_ports.csv

│   ├── suspicious_ips.csv

│   ├── protocol_chart.png

│   └── top_ports_chart.png

│
├── scripts/

│   └── analyzer.py

│
├── README.md

└── requirements.txt
```

---

## 🚀 How to Run

```bash
# From the project root
python scripts/analyzer.py

# Analyse a different capture file (run from anywhere)
python scripts/analyzer.py --capture captures/traffic.pcapng

# Custom top-N results
python scripts/analyzer.py --top 5
```

### CLI Options

| Argument          | Default  | Description                                        |
|-------------------|----------|----------------------------------------------------|
| `--capture`       | `captures/traffic.pcapng` | Path to capture file (PCAP/PCAPNG)   |
| `--top`           | `10`     | Number of top entries to display                   |
| `--scan-ports`    | `25`     | Distinct ports to flag as a possible port scan     |
| `--std-mult`      | `3.0`    | Std-dev multiplier for flood threshold             |
| `--min-packets`   | `50`     | Minimum packets for flood detection                |

---

## 🧠 How It Works

1. **Packet loading** — reads the capture file with Scapy (`rdpcap`).
2. **Protocol statistics** — classifies each packet as TCP, UDP, ICMP, ARP, or Other (works for both IPv4 and IPv6).
3. **IP / port analysis** — counts packets per source IP, destination IP, and destination port.
4. **Time analysis** — computes capture duration and average packet rate.
5. **Anomaly detection**:
   - **Traffic flood** — an IP whose traffic exceeds `mean + (3 × std-dev)` of all hosts is flagged. The threshold is dynamic, not a fixed number.
   - **Port scan** — a source IP that contacts many distinct destination ports with mostly one-to-three packets (probe-style) is flagged as a possible scan.
   - Address class (private/public) is included so results can be interpreted in context.
6. **Reports** — all results are saved as CSVs and charts, so the analysis is reproducible and shareable.

> **Note:** Alerts indicate *suspicious behaviour* worth verifying — in real SOC tools not every alert is a confirmed attack. For example, a NAT router can briefly look like a port scanner when relaying many short connections.

---

## 📊 Output

The project generates:

- Protocol Statistics (with percentage)
- Capture Time Analysis
- Source/Destination IP Analysis
- Destination Port Analysis
- Suspicious IP Alerts (with severity + address class)
- CSV Reports (`traffic_report.csv`, `top_source_ips.csv`, `top_destination_ips.csv`, `top_destination_ports.csv`, `suspicious_ips.csv`)
- Charts (`protocol_chart.png`, `top_ports_chart.png`)

---

## 🎯 Future Improvements

- Real-Time Packet Capture
- Email/Slack Alert System
- Web Dashboard using Flask
- Machine-learning based anomaly scoring
- Integration with known threat-intelligence IP feeds (e.g., AlienVault OTX)

---

## 👨‍💻 Developed By

**Kirankumar Thakor**