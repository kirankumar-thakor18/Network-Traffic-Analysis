import subprocess
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

BASE_DIR = Path(__file__).resolve().parent.parent
SCRIPTS = BASE_DIR / "scripts"
SCREENSHOTS = BASE_DIR / "screenshots"


def capture_output():
    result = subprocess.run(
        ["python", str(SCRIPTS / "analyzer.py")],
        cwd=str(BASE_DIR),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    output = result.stdout
    if result.returncode != 0:
        output = output or result.stderr
    output = output.rstrip("\n")
    return output.splitlines()


def to_image(lines, out_path):
    max_chars = max(len(line) for line in lines) + 6
    n_lines = len(lines)
    fig_width = max_chars * 0.085 + 1.2
    fig_height = n_lines * 0.165 + 0.7

    fig, ax = plt.subplots(figsize=(fig_width, fig_height))
    fig.patch.set_facecolor("#0B1020")
    ax.set_facecolor("#0B1020")
    ax.axis("off")
    ax.set_xlim(0, max_chars)
    ax.set_ylim(0, n_lines + 1)
    ax.invert_yaxis()

    title_bar = 0.45
    ax.add_patch(plt.Rectangle((0, 0), max_chars, title_bar, color="#1A2440"))
    for i, color in enumerate(["#FF5F57", "#FEBC2E", "#28C840"]):
        ax.scatter(1.2 + i * 2.4, title_bar / 2, s=38, c=color, zorder=5)
    ax.text(
        8.4,
        title_bar / 2,
        "Network Traffic Analyzer - terminal",
        fontsize=11,
        color="#8F9BB8",
        fontfamily="monospace",
        ha="left",
        va="center",
    )

    for i, line in enumerate(lines):
        y = title_bar + 0.55 + i
        text_color = "#D6E2F0"
        if "ALERT" in line and "MEDIUM" in line:
            text_color = "#FFB34D"
        elif "ALERT" in line and "HIGH" in line:
            text_color = "#FF7A6E"
        elif "Total Packets" in line or "Analysis completed" in line:
            text_color = "#4FD6A5"
        ax.text(
            1.0,
            y,
            line,
            fontsize=9.5,
            color=text_color,
            fontfamily="monospace",
            va="top",
            ha="left",
        )
    plt.subplots_adjust(left=0.01, right=0.99, top=0.995, bottom=0.005)
    plt.savefig(out_path, dpi=170, facecolor=fig.get_facecolor())
    plt.close(fig)
    return n_lines


def main():
    SCREENSHOTS.mkdir(parents=True, exist_ok=True)
    lines = capture_output()
    drawn = to_image(lines, SCREENSHOTS / "terminal_output.png")
    print(f"Saved: {SCREENSHOTS / 'terminal_output.png'}")
    print(f"Lines drawn: {drawn} of {len(lines)}")


if __name__ == "__main__":
    main()