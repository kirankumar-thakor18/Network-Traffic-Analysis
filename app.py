import io
import os
import uuid
import base64
import logging
import traceback
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    send_file,
)
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.utils import secure_filename

from scripts.analyzer import (
    load_packets,
    analyze_protocols,
    analyze_ips_ports,
    analyze_time,
    detect_anomalies,
    save_report_csv,
    save_top_csv,
    save_alerts_csv,
    save_charts,
)
from scripts.make_pdf import save_pdf_report

logging.basicConfig(level=logging.WARNING, format="%(asctime)s %(levelname)s %(message)s")
logging.getLogger("matplotlib").setLevel(logging.WARNING)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "dev-secret-key-change-in-production")
app.config["UPLOAD_FOLDER"] = Path(__file__).parent / "uploads"
app.config["MAX_CONTENT_LENGTH"] = 40 * 1024 * 1024  # 40MB max
MAX_UPLOAD_SIZE = 40 * 1024 * 1024

ALLOWED_EXTENSIONS = {"pcap", "pcapng"}

UPLOADS_DIR = Path(__file__).parent / "uploads"
UPLOADS_DIR.mkdir(exist_ok=True)
REPORTS_DIR = Path(__file__).parent / "reports"


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def generate_chart_base64(protocol_counter, port_counter, top_n=10):
    charts = {}

    # Dashboard-style palette
    NAVY_BG = "#0d1426"
    PANEL_BG = "#101a30"
    CYAN = "#00d2ff"
    BLUE = "#0a85ff"
    PURPLE = "#7b61ff"
    RED = "#ff6b6b"
    YELLOW = "#ffd93d"
    GREEN = "#6bcb77"
    LIGHT = "#dbe6f7"
    MUTED = "#7a8bb0"
    GRID = "#1c2b4a"

    colors = [CYAN, BLUE, PURPLE, RED, YELLOW, GREEN,
              "#ff9f43", "#e056fd", "#00cec9", "#fdcb6e"]

    # Protocol Pie Chart
    fig, ax = plt.subplots(figsize=(6, 5.6))
    fig.patch.set_facecolor(PANEL_BG)
    ax.set_facecolor(PANEL_BG)

    pie_colors = colors[: len(protocol_counter)]
    wedges, texts, autotexts = ax.pie(
        protocol_counter.values(),
        labels=protocol_counter.keys(),
        autopct="%1.1f%%",
        startangle=90,
        colors=pie_colors,
        pctdistance=0.78,
        labeldistance=1.08,
        wedgeprops={"edgecolor": PANEL_BG, "linewidth": 2, "width": 0.42},
        textprops={"fontsize": 11, "color": LIGHT, "fontweight": "bold"},
    )
    for autotext in autotexts:
        autotext.set_color("#ffffff")
        autotext.set_fontsize(10.5)
        autotext.set_fontweight(700)
        autotext.set_fontfamily("DejaVu Sans")

    ax.set_title(
        "Protocol Distribution",
        fontsize=14,
        fontweight=700,
        color="#ffffff",
        pad=18,
        fontfamily="DejaVu Sans",
    )
    ax.text(
        0, 0, f"{sum(protocol_counter.values()):,}\npackets",
        ha="center", va="center", fontsize=12, fontweight=700, color=LIGHT,
    )
    plt.tight_layout()
    buf = io.BytesIO()
    fig.savefig(buf, format="png", dpi=160, bbox_inches="tight", facecolor=PANEL_BG)
    plt.close(fig)
    buf.seek(0)
    charts["protocol"] = base64.b64encode(buf.read()).decode("utf-8")

    # Ports Bar Chart
    top_ports = port_counter.most_common(top_n)
    if top_ports:
        fig, ax = plt.subplots(figsize=(10, 5.2))
        fig.patch.set_facecolor(PANEL_BG)
        ax.set_facecolor(PANEL_BG)

        ports = [str(p) for p, _ in top_ports]
        counts = [c for _, c in top_ports]
        bar_colors = [BLUE] * len(ports)
        for i in range(len(ports)):
            bar_colors[i] = colors[i % len(colors)]

        bars = ax.bar(ports, counts, color=bar_colors, width=0.62,
                      edgecolor=PANEL_BG, linewidth=1.2, zorder=3)

        ax.set_title(f"Top {top_n} Destination Ports", fontsize=14, fontweight=700, color="#ffffff", pad=14)
        ax.set_xlabel("Port", fontsize=11, color=MUTED, labelpad=8)
        ax.set_ylabel("Packets", fontsize=11, color=MUTED, labelpad=8)

        ax.tick_params(axis="x", rotation=30, colors=LIGHT, labelsize=10)
        ax.tick_params(axis="y", colors=LIGHT, labelsize=10)
        ax.grid(axis="y", color=GRID, linewidth=0.8, alpha=0.7, zorder=0)
        ax.set_axisbelow(True)
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)
        ax.spines["bottom"].set_color(GRID)
        ax.spines["left"].set_color(GRID)

        max_count = max(counts) if counts else 1
        for bar, count in zip(bars, counts):
            ax.text(
                bar.get_x() + bar.get_width() / 2.0,
                count if count > 0 else 0,
                f"{int(count):,}",
                ha="center",
                va="bottom",
                fontsize=9,
                color=LIGHT,
                fontweight="bold",
                zorder=4,
            )
        ax.set_ylim(0, max_count * 1.18)

        plt.tight_layout()
        buf = io.BytesIO()
        fig.savefig(buf, format="png", dpi=160, bbox_inches="tight", facecolor=PANEL_BG)
        plt.close(fig)
        buf.seek(0)
        charts["ports"] = base64.b64encode(buf.read()).decode("utf-8")

    return charts


def run_analysis(capture_path, top_n=10, scan_ports=25, std_mult=3.0, min_packets=50):
    packets = load_packets(capture_path)
    protocol_counter = analyze_protocols(packets)
    src_counter, dst_counter, port_counter = analyze_ips_ports(packets)
    time_info = analyze_time(packets)
    alerts, flood_threshold = detect_anomalies(
        packets, src_counter, dst_counter, scan_ports, std_mult, min_packets
    )

    charts = {}
    try:
        charts = generate_chart_base64(protocol_counter, port_counter, top_n)
    except Exception as e:
        logger.warning("Chart generation failed for %s: %s", capture_path, e)
        charts = {}

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

    try:
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        save_report_csv(protocol_counter)
        save_top_csv("top_source_ips.csv", src_counter.most_common(top_n), ["IP Address", "Packets"])
        save_top_csv("top_destination_ips.csv", dst_counter.most_common(top_n), ["IP Address", "Packets"])
        save_top_csv("top_destination_ports.csv", port_counter.most_common(top_n), ["Port", "Packets"])
        save_alerts_csv(alerts)
        save_charts(protocol_counter, port_counter, top_n)
    except Exception as e:
        logger.warning("Report file saving failed for %s: %s", capture_path, e)

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


@app.errorhandler(500)
def internal_error(error):
    logger.error("Internal Server Error:\n%s", traceback.format_exc())
    return render_template(
        "index.html",
        error="Something went wrong while analyzing. This usually happens with very large captures "
        "(memory limit) or unsupported packet formats. Try a smaller capture.",
    ), 500


@app.errorhandler(RequestEntityTooLarge)
def file_too_large(error):
    return render_template(
        "index.html",
        error="File is too large! Maximum upload size is 40 MB. "
        "Real-time captures get large fast - capture for a shorter duration "
        "or use Wireshark 'File > Export Specified Packets' to trim it.",
    ), 413


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

    file.seek(0, os.SEEK_END)
    file_size = file.tell()
    file.seek(0)
    if file_size > MAX_UPLOAD_SIZE:
        return render_template(
            "index.html",
            error=f"File is {(file_size / (1024 * 1024)):.1f} MB - over the {MAX_UPLOAD_SIZE // (1024 * 1024)} MB limit. "
            "Real-time captures get large fast. Capture for a shorter duration or use Wireshark's "
            "'File > Export Specified Packets' to trim it.",
        ), 413

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
        logger.error(
            "Analysis failed for %s: %s\n%s",
            file.filename,
            e,
            traceback.format_exc(),
        )
        return render_template("index.html", error=f"Analysis failed: {str(e)}")
    finally:
        filepath.unlink(missing_ok=True)


@app.route("/download-pdf")
def download_pdf():
    try:
        pdf_path = save_pdf_report()
        return send_file(
            pdf_path,
            as_attachment=True,
            download_name="network_traffic_report.pdf",
            mimetype="application/pdf",
        )
    except Exception as e:
        return render_template("index.html", error=f"PDF export failed: {str(e)}")


if __name__ == "__main__":
    debug = os.getenv("FLASK_DEBUG", "0") == "1"
    host = os.getenv("HOST", "127.0.0.1")
    port = int(os.getenv("PORT", 5000))
    app.run(debug=debug, host=host, port=port)
