import argparse
import ipaddress
import sys
from collections import Counter, defaultdict
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd

from scapy.all import rdpcap

BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_CAPTURE = BASE_DIR / "captures" / "traffic.pcapng"
REPORTS_DIR = BASE_DIR / "reports"

ALERT_COLUMNS = ["IP Address", "Type", "Packets", "Threshold", "Severity", "Address Class", "Detail"]

SEPARATOR = "=" * 45


def load_packets(capture_path):
    capture_path = Path(capture_path)
    if not capture_path.is_file():
        raise FileNotFoundError(f"Capture file not found: {capture_path}")
    try:
        return rdpcap(str(capture_path))
    except Exception as exc:
        raise ValueError(f"Failed to read capture file: {exc}")


def get_ip_layer(packet):
    if packet.haslayer("IP"):
        return packet["IP"]
    if packet.haslayer("IPv6"):
        return packet["IPv6"]
    return None


def classify_protocol(packet):
    if packet.haslayer("TCP"):
        return "TCP"
    if packet.haslayer("UDP"):
        return "UDP"
    if packet.haslayer("ICMP") or packet.haslayer("ICMPv6"):
        return "ICMP"
    if packet.haslayer("ARP"):
        return "ARP"
    if get_ip_layer(packet):
        return "Other IP"
    return "Other"


def analyze_protocols(packets):
    counter = Counter()
    for packet in packets:
        counter[classify_protocol(packet)] += 1
    return counter


def analyze_ips_ports(packets):
    src_counter = Counter()
    dst_counter = Counter()
    port_counter = Counter()

    for packet in packets:
        layer = get_ip_layer(packet)
        if layer:
            src_counter[layer.src] += 1
            dst_counter[layer.dst] += 1

        dport = None
        if packet.haslayer("TCP"):
            dport = packet["TCP"].dport
        elif packet.haslayer("UDP"):
            dport = packet["UDP"].dport
        if dport is not None:
            port_counter[dport] += 1

    return src_counter, dst_counter, port_counter


def analyze_time(packets):
    timestamps = [float(packet.time) for packet in packets if getattr(packet, "time", None)]
    if not timestamps:
        return None
    start = min(timestamps)
    end = max(timestamps)
    duration = end - start
    return {
        "start": start,
        "end": end,
        "duration": duration,
        "packets_per_second": len(packets) / duration if duration > 0 else 0.0,
    }


def dynamic_threshold(counter, std_multiplier, min_packets=0):
    values = list(counter.values())
    if not values:
        return 0.0, 0.0
    mean = sum(values) / len(values)
    variance = sum((v - mean) ** 2 for v in values) / len(values)
    std = variance ** 0.5
    return mean, max(min_packets, mean + std_multiplier * std)


def address_class(ip):
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return "Unknown"
    if address.is_loopback:
        return "Loopback"
    if address.is_link_local:
        return "Link-local"
    if address.is_private or address.is_reserved:
        return "Private"
    return "Public"


def detect_anomalies(packets, src_counter, dst_counter, scan_ports, std_multiplier, min_packets):
    alerts = []

    _, threshold = dynamic_threshold(src_counter, std_multiplier, min_packets)
    for ip, count in src_counter.items():
        if count >= threshold:
            severity = "HIGH" if count >= threshold * 2 else "MEDIUM"
            alerts.append({
                "IP Address": ip,
                "Type": "Traffic Flood (Source)",
                "Packets": count,
                "Threshold": round(threshold, 1),
                "Severity": severity,
                "Address Class": address_class(ip),
                "Detail": f"{count} packets sent (threshold {threshold:.1f})",
            })

    _, threshold = dynamic_threshold(dst_counter, std_multiplier, min_packets)
    for ip, count in dst_counter.items():
        if count >= threshold:
            severity = "HIGH" if count >= threshold * 2 else "MEDIUM"
            alerts.append({
                "IP Address": ip,
                "Type": "Traffic Flood (Destination)",
                "Packets": count,
                "Threshold": round(threshold, 1),
                "Severity": severity,
                "Address Class": address_class(ip),
                "Detail": f"{count} packets received (threshold {threshold:.1f})",
            })

    port_counts = defaultdict(Counter)
    dest_by_src = defaultdict(set)
    for packet in packets:
        layer = get_ip_layer(packet)
        if not layer:
            continue
        dport = None
        if packet.haslayer("TCP"):
            dport = packet["TCP"].dport
        elif packet.haslayer("UDP"):
            dport = packet["UDP"].dport
        if dport is not None:
            port_counts[layer.src][dport] += 1
            dest_by_src[layer.src].add(layer.dst)

    for ip, ports in port_counts.items():
        distinct_ports = len(ports)
        probe_ports = sum(1 for count in ports.values() if count <= 3)
        if distinct_ports >= scan_ports and probe_ports >= scan_ports:
            severity = "HIGH" if distinct_ports >= scan_ports * 2 else "MEDIUM"
            alerts.append({
                "IP Address": ip,
                "Type": "Possible Port Scan",
                "Packets": src_counter.get(ip, 0),
                "Threshold": scan_ports,
                "Severity": severity,
                "Address Class": address_class(ip),
                "Detail": (
                    f"{distinct_ports} distinct dest ports ({probe_ports} probe-style) "
                    f"across {len(dest_by_src[ip])} dest IP(s)"
                ),
            })

    return alerts, threshold


def save_report_csv(protocol_counter):
    total = sum(protocol_counter.values())
    report = pd.DataFrame({
        "Protocol": list(protocol_counter.keys()),
        "Count": list(protocol_counter.values()),
        "Percentage": [round(c / total * 100, 2) if total else 0 for c in protocol_counter.values()],
    })
    report.to_csv(REPORTS_DIR / "traffic_report.csv", index=False)


def save_top_csv(filename, rows, columns):
    df = pd.DataFrame(rows, columns=columns)
    df.to_csv(REPORTS_DIR / filename, index=False)


def save_alerts_csv(alerts):
    df = pd.DataFrame(alerts, columns=ALERT_COLUMNS)
    df.to_csv(REPORTS_DIR / "suspicious_ips.csv", index=False)


def save_charts(protocol_counter, port_counter, top_n):
    plt.figure(figsize=(6, 6))
    plt.pie(
        protocol_counter.values(),
        labels=protocol_counter.keys(),
        autopct="%1.1f%%",
        startangle=90,
    )
    plt.title("Protocol Distribution")
    plt.tight_layout()
    plt.savefig(REPORTS_DIR / "protocol_chart.png", dpi=150)

    plt.figure(figsize=(8, 5))
    for port, count in port_counter.most_common(top_n):
        plt.bar(str(port), count)
    plt.title(f"Top {top_n} Destination Ports")
    plt.xlabel("Port")
    plt.ylabel("Packets")
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    plt.savefig(REPORTS_DIR / "top_ports_chart.png", dpi=150)


def print_section(title):
    print(f"\n{title}")
    print(SEPARATOR)


def main():
    parser = argparse.ArgumentParser(description="Network Traffic Analyzer and Threat Detection System")
    parser.add_argument("--capture", type=Path, default=DEFAULT_CAPTURE, help="Path to capture file (PCAP/PCAPNG)")
    parser.add_argument("--top", type=int, default=10, help="Number of top entries to display (default: 10)")
    parser.add_argument("--scan-ports", type=int, default=25, help="Distinct ports to flag as port scan (default: 25)")
    parser.add_argument("--std-mult", type=float, default=3.0, help="Std dev multiplier for flood threshold (default: 3.0)")
    parser.add_argument("--min-packets", type=int, default=50, help="Minimum packets for flood detection (default: 50)")
    args = parser.parse_args()

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    packets = load_packets(args.capture)

    print(SEPARATOR)
    print("Network Traffic Analyzer - Threat Detection System")
    print(SEPARATOR)
    print(f"Capture File     : {args.capture}")
    print(f"Total Packets    : {len(packets)}")

    protocol_counter = analyze_protocols(packets)
    src_counter, dst_counter, port_counter = analyze_ips_ports(packets)
    time_info = analyze_time(packets)

    print_section("Protocol Statistics")
    for protocol, count in protocol_counter.most_common():
        print(f"{protocol:<12} : {count}")

    if time_info:
        print_section("Capture Time Analysis")
        print(f"Capture Start      : {time_info['start']:.2f}")
        print(f"Capture End        : {time_info['end']:.2f}")
        print(f"Capture Duration   : {time_info['duration']:.2f} seconds")
        print(f"Avg Packet Rate    : {time_info['packets_per_second']:.2f} packets/sec")

    print_section(f"Top {args.top} Source IPs")
    for ip, count in src_counter.most_common(args.top):
        print(f"{ip:<20} : {count} packets")

    print_section(f"Top {args.top} Destination IPs")
    for ip, count in dst_counter.most_common(args.top):
        print(f"{ip:<20} : {count} packets")

    print_section(f"Top {args.top} Destination Ports")
    for port, count in port_counter.most_common(args.top):
        print(f"Port {port:<6} : {count} packets")

    print_section("Anomaly / Threat Detection")
    alerts, flood_threshold = detect_anomalies(
        packets,
        src_counter,
        dst_counter,
        args.scan_ports,
        args.std_mult,
        args.min_packets,
    )

    print(f"Flood threshold (mean + {args.std_mult}x std, min {args.min_packets} packets): {flood_threshold:.1f}")
    print(f"Port scan threshold: {args.scan_ports} distinct/probe destination ports")

    if alerts:
        for alert in alerts:
            print(
                f"ALERT [{alert['Severity']}] {alert['Type']} : {alert['IP Address']} "
                f"({alert['Address Class']}) -> {alert['Packets']} packets [{alert['Detail']}]"
            )
    else:
        print("No anomalies detected in captured traffic")

    save_report_csv(protocol_counter)
    save_top_csv("top_source_ips.csv", src_counter.most_common(), ["IP Address", "Packets"])
    save_top_csv("top_destination_ips.csv", dst_counter.most_common(), ["IP Address", "Packets"])
    save_top_csv("top_destination_ports.csv", port_counter.most_common(), ["Port", "Packets"])
    save_alerts_csv(alerts)
    save_charts(protocol_counter, port_counter, args.top)

    print_section("Output Files")
    print(f"reports/traffic_report.csv")
    print(f"reports/top_source_ips.csv")
    print(f"reports/top_destination_ips.csv")
    print(f"reports/top_destination_ports.csv")
    print(f"reports/suspicious_ips.csv")
    print(f"reports/protocol_chart.png")
    print(f"reports/top_ports_chart.png")
    print(f"\nAnalysis completed successfully.")


if __name__ == "__main__":
    main()