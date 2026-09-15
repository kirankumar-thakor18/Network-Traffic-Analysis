import io
import os
import uuid
import base64
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from flask import Flask, render_template, request, redirect, url_for, session
from werkzeug.utils import secure_filename

from scripts.analyzer import (
    load_packets,
    analyze_protocols,
    analyze_ips_ports,
    analyze_time,
    detect_anomalies,
)

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config["UPLOAD_FOLDER"] = Path(__file__).parent / "uploads"
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024  # 100MB max

ALLOWED_EXTENSIONS = {"pcap", "pcapng"}

UPLOADS_DIR = Path(__file__).parent / "uploads"
UPLOADS_DIR.mkdir(exist_ok=True)


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def generate_chart_base64(protocol_counter, port_counter, top_n=10):
    charts = {}

    # Protocol Pie Chart
    fig, ax = plt.subplots(figsize=(6, 6))
    colors = ["#00d2ff", "#0a85ff", "#7b61ff", "#ff6b6b", "#ffd93d", "#6bcb77"]
    ax.pie(
        protocol_counter.values(),
        labels=protocol_counter.keys(),
        autopct="%1.1f%%",
        startangle=90,
        colors=colors[: len(protocol_counter)],
        textprops={"fontsize": 12},
    )
    ax.set_title("Protocol Distribution", fontsize=14, fontweight="bold")
    plt.tight_layout()
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=150, bbox_inches="tight", facecolor="#1a1a2e")
    plt.close(fig)
    buf.seek(0)
    charts["protocol"] = base64.b64encode(buf.read()).decode("utf-8")

    # Ports Bar Chart
    top_ports = port_counter.most_common(top_n)
    if top_ports:
        fig, ax = plt.subplots(figsize=(10, 5))
        ports = [str(p) for p, _ in top_ports]
        counts = [c for _, c in top_ports]
        bars = ax.bar(ports, counts, color="#0a85ff", edgecolor="#00d2ff", linewidth=0.5)
        ax.set_title(f"Top {top_n} Destination Ports", fontsize=14, fontweight="bold")
        ax.set_xlabel("Port", fontsize=12)
        ax.set_ylabel("Packets", fontsize=12)
        ax.tick_params(axis="x", rotation=45, colors="white")
        ax.tick_params(axis="y", colors="white")
        ax.set_facecolor("#16213e")
        fig.patch.set_facecolor("#1a1a2e")
        ax.spines["bottom"].set_color("#444")
        ax.spines["left"].set_color("#444")
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)
        for bar in bars:
            ax.text(
                bar.get_x() + bar.get_width() / 2.0,
                bar.get_height() + 20,
                f"{int(bar.get_height()):,}",
                ha="center",
                va="bottom",
                fontsize=8,
                color="white",
            )
        plt.tight_layout()
        buf = io.BytesIO()
        fig.savefig(buf, format="png", dpi=150, bbox_inches="tight", facecolor="#1a1a2e")
        plt.close(fig)
        buf.seek(0)
        charts["ports"] = base64.b64encode(buf.read()).decode("utf-8")

    # Top Source IPs Bar Chart
    return charts


def run_analysis(capture_path, top_n=10, scan_ports=25, std_mult=3.0, min_packets=50):
    packets = load_packets(capture_path)
    protocol_counter = analyze_protocols(packets)
    src_counter, dst_counter, port_counter = analyze_ips_ports(packets)
    time_info = analyze_time(packets)
    alerts, flood_threshold = detect_anomalies(
        packets, src_counter, dst_counter, scan_ports, std_mult, min_packets
    )

    charts = generate_chart_base64(protocol_counter, port_counter, top_n)

    total = sum(protocol_counter.values())
    protocol_stats = []
    for proto, count in protocol_counter.most_common():
        protocol_stats.append(
            {"name": proto, "count": count, "percentage": round(count / total * 100, 1) if total else 0}
        )

    src_ips = [{"ip": ip, "packets": count} for ip, count in src_counter.most_common(top_n)]
    dst_ips = [{"ip": ip, "packets": count} for ip, count in dst_counter.most_common(top_n)]
    dst_ports = [{"port": port, "packets": count} for port, count in port_counter.most_common(top_n)]

    time_stats = {}
    if time_info:
        time_stats = {
            "duration": round(time_info["duration"], 2),
            "pps": round(time_info["packets_per_second"], 2),
            "start": time_info["start"],
            "end": time_info["end"],
        }

    return {
        "total_packets": len(packets),
        "protocols": protocol_stats,
        "time_stats": time_stats,
        "src_ips": src_ips,
        "dst_ips": dst_ips,
        "dst_ports": dst_ports,
        "alerts": alerts,
        "flood_threshold": round(flood_threshold, 1),
        "charts": charts,
        "capture_name": Path(capture_path).name,
    }


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    if "capture" not in request.files:
        return redirect(url_for("index"))

    file = request.files["capture"]
    if file.filename == "":
        return redirect(url_for("index"))

    if not allowed_file(file.filename):
        return render_template("index.html", error="Only .pcap and .pcapng files are allowed!")

    filename = secure_filename(file.filename)
    unique_name = f"{uuid.uuid4().hex[:8]}_{filename}"
    filepath = UPLOADS_DIR / unique_name
    file.save(str(filepath))

    try:
        top_n = int(request.form.get("top_n", 10))
        scan_ports = int(request.form.get("scan_ports", 25))
        std_mult = float(request.form.get("std_mult", 3.0))
        min_packets = int(request.form.get("min_packets", 50))

        results = run_analysis(filepath, top_n, scan_ports, std_mult, min_packets)
        return render_template("dashboard.html", results=results)
    except Exception as e:
        return render_template("index.html", error=f"Analysis failed: {str(e)}")
    finally:
        filepath.unlink(missing_ok=True)


@app.route("/demo")
def demo():
    default_capture = Path(__file__).parent / "captures" / "traffic.pcapng"
    if not default_capture.exists():
        return render_template("index.html", error="Demo capture file not found!")

    try:
        results = run_analysis(default_capture)
        return render_template("dashboard.html", results=results)
    except Exception as e:
        return render_template("index.html", error=f"Demo failed: {str(e)}")


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
