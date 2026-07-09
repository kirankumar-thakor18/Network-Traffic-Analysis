from scapy.all import rdpcap
from collections import Counter
import pandas as pd
import matplotlib.pyplot as plt

# Read the PCAP file
packets = rdpcap("../captures/traffic.pcapng")

# Display total packets
print("=" * 40)
print("Network Traffic Analyzer")
print("=" * 40)
print(f"Total Packets Captured : {len(packets)}")

# ==============================
# Protocol Statistics
# ==============================

protocol_counter = Counter()

for packet in packets:

    if packet.haslayer("TCP"):
        protocol_counter["TCP"] += 1

    elif packet.haslayer("UDP"):
        protocol_counter["UDP"] += 1

    elif packet.haslayer("ICMP"):
        protocol_counter["ICMP"] += 1

    else:
        protocol_counter["Other"] += 1

print("\n===== Protocol Statistics =====")

for protocol, count in protocol_counter.items():
    print(f"{protocol} : {count}")

# ==============================
# Top Source IPs
# ==============================

print("\n===== Top Source IPs =====")

ip_counter = Counter()

for packet in packets:
    if packet.haslayer("IP"):
        ip_counter[packet["IP"].src] += 1

for ip, count in ip_counter.most_common(10):
    print(f"{ip} : {count} packets")

# ==============================
# Top Destination IPs
# ==============================

print("\n===== Top Destination IPs =====")

destination_counter = Counter()

for packet in packets:
    if packet.haslayer("IP"):
        destination_counter[packet["IP"].dst] += 1

for ip, count in destination_counter.most_common(10):
    print(f"{ip} : {count} packets")

# ==============================
# Top Destination Ports
# ==============================

print("\n===== Top Destination Ports =====")

port_counter = Counter()

for packet in packets:

    if packet.haslayer("TCP"):
        port_counter[packet["TCP"].dport] += 1

    elif packet.haslayer("UDP"):
        port_counter[packet["UDP"].dport] += 1

for port, count in port_counter.most_common(10):
    print(f"Port {port} : {count} packets")
# ==============================
# Suspicious IP Detection
# ==============================

print("\n===== Suspicious IP Detection =====")

THRESHOLD = 100

suspicious_ips = []

for ip, count in ip_counter.items():

    if count >= THRESHOLD:

        suspicious_ips.append([ip, count])

        print(f"🚨 ALERT : {ip} --> {count} packets")

if not suspicious_ips:
    print("✅ No Suspicious IPs Found")

# Save suspicious IPs

suspicious_df = pd.DataFrame(
    suspicious_ips,
    columns=["IP Address", "Packets"]
)

suspicious_df.to_csv(
    "../reports/suspicious_ips.csv",
    index=False
)
# ==============================
# Save CSV Report
# ==============================

report = pd.DataFrame({
    "Protocol": list(protocol_counter.keys()),
    "Count": list(protocol_counter.values())
})

report.to_csv("../reports/traffic_report.csv", index=False)

print("\n✅ Report saved successfully!")
# ==============================
# Protocol Pie Chart
# ==============================

plt.figure(figsize=(6,6))

plt.pie(
    protocol_counter.values(),
    labels=protocol_counter.keys(),
    autopct="%1.1f%%",
    startangle=90
)

plt.title("Protocol Distribution")

plt.savefig("../reports/protocol_chart.png")

plt.show()

print("📊 Protocol chart saved successfully!")