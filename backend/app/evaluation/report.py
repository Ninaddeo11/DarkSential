"""Run the Phase 7 evaluation and write CSVs, plots and a summary.

    python -m app.cli evaluate [--calibration-seeds 1-10] [--eval-seeds 11-30]

Method: thresholds are derived on the calibration seeds (``harness.calibrate``),
then every metric is measured on *different* seeds, under both the shipped and
the calibrated thresholds, so the reported numbers are not fitted to the data
they describe. Output goes to ``docs/evaluation/phase7``.
"""

from __future__ import annotations

import csv
import json
import os
import platform
import statistics
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.core.config import REPO_ROOT
from app.evaluation import harness
from app.evaluation.ws_latency import WsSample, measure

OUT = REPO_ROOT / "docs" / "evaluation" / "phase7"
# The thresholds shipped before Phase 7, kept as the comparison baseline.
PHASE3_THRESHOLDS = {"low": 0.0, "medium": 25.0, "high": 50.0, "critical": 75.0}

# Reference palette (dataviz skill), validated for the light surface: identity, not rank.
SURFACE = "#fcfcfb"
INK = "#0b0b0b"
INK_2 = "#52514e"
GRID = "#e4e3df"
BENIGN = "#2a78d6"  # slot 1 (blue)
MALICIOUS = "#eb6834"  # slot 2 (orange)
VULNERABLE = "#1baf7a"  # slot 3 (aqua; < 3:1 contrast -> legend + table carry it)
CLASS_COLOR = {
    "benign": BENIGN, "unknown": BENIGN, "vulnerable": VULNERABLE, "malicious": MALICIOUS,
}  # fmt: skip


def parse_seeds(spec: str) -> list[int]:
    out: list[int] = []
    for part in spec.split(","):
        if "-" in part:
            lo, hi = part.split("-")
            out += list(range(int(lo), int(hi) + 1))
        elif part.strip():
            out.append(int(part))
    return out


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    if not rows:
        return
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def _style(ax: Any) -> None:
    ax.set_facecolor(SURFACE)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    for side in ("left", "bottom"):
        ax.spines[side].set_color(GRID)
    ax.tick_params(colors=INK_2, labelsize=9)
    ax.yaxis.grid(True, color=GRID, linewidth=0.8)
    ax.set_axisbelow(True)


def plot_scores(
    path: Path, results: harness.Results, current: dict[str, float], calibrated: dict[str, float]
) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    from matplotlib.lines import Line2D

    scenarios = list(harness.SCENARIOS)
    fig, ax = plt.subplots(figsize=(9, 4.8), dpi=150, facecolor=SURFACE)
    _style(ax)
    for x, name in enumerate(scenarios):
        rows = [d for d in results.devices if d.scenario == name]
        for d in rows:
            jitter = ((hash((d.seed, d.device)) % 1000) / 1000 - 0.5) * 0.5
            ax.scatter(
                x + jitter, d.max_score, s=26, color=CLASS_COLOR[d.truth],
                edgecolors=SURFACE, linewidths=1.0, zorder=3,
            )  # fmt: skip
    right = len(scenarios) - 0.45
    for level, style in (("medium", (0, (4, 3))), ("critical", "solid")):
        # Calibrated label sits above its line, the Phase 3 label below its own, so the
        # two never overlap even when the values are close (26.4 vs 25).
        ax.axhline(calibrated[level], color=INK, linewidth=1.2, linestyle=style, zorder=2)
        ax.text(
            right, calibrated[level] + 0.6, f"calibrated {level} {calibrated[level]:g}",
            va="bottom", ha="left", fontsize=8, color=INK,
        )  # fmt: skip
        ax.axhline(current[level], color=INK_2, linewidth=0.8, linestyle=(0, (1, 2)), zorder=2)
        ax.text(
            right, current[level] - 0.6, f"Phase 3 {level} {current[level]:g}",
            va="top", ha="left", fontsize=8, color=INK_2,
        )  # fmt: skip
    ax.set_xticks(range(len(scenarios)), [s.replace("_", " ") for s in scenarios], color=INK)
    ax.set_xlim(-0.6, len(scenarios) + 1.2)
    ax.set_ylim(-3, max(80, max(d.max_score for d in results.devices) + 5))
    ax.set_ylabel("highest risk score in the scenario", color=INK_2, fontsize=9)
    ax.set_title(
        "Risk score per device and scenario (held-out seeds)", loc="left", color=INK, fontsize=11
    )
    handles = [
        Line2D([], [], marker="o", linestyle="", color=BENIGN, label="benign or unknown device"),
        Line2D(
            [], [], marker="o", linestyle="", color=VULNERABLE, label="vulnerable, not attacked"
        ),
        Line2D([], [], marker="o", linestyle="", color=MALICIOUS, label="attacked device"),
    ]
    ax.legend(handles=handles, frameon=False, fontsize=8, loc="upper left")
    fig.tight_layout()
    fig.savefig(path, facecolor=SURFACE)
    plt.close(fig)


def plot_latency(path: Path, results: harness.Results) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    scenarios = [
        s for s in harness.SCENARIOS if s in ("mqtt_flood", "kev_ioc", "quarantine_recovery")
    ]
    fig, ax = plt.subplots(figsize=(7.5, 4), dpi=150, facecolor=SURFACE)
    _style(ax)
    series = (
        ("first_detection_s", "first detection", BENIGN, -0.12),
        ("first_alert_s", "first alert (medium+)", MALICIOUS, 0.12),
    )
    for attr, label, color, dx in series:
        xs, ys = [], []
        for x, name in enumerate(scenarios):
            for d in results.devices:
                v = getattr(d, attr)
                if d.scenario == name and d.truth == "malicious" and v is not None:
                    xs.append(x + dx)
                    ys.append(v)
        ax.scatter(
            xs, ys, s=24, color=color, edgecolors=SURFACE, linewidths=1.0, label=label, zorder=3
        )
    ax.set_xticks(range(len(scenarios)), [s.replace("_", " ") for s in scenarios], color=INK)
    ax.set_ylabel("seconds after the attack started (simulated time)", color=INK_2, fontsize=9)
    ax.set_ylim(bottom=0)
    ax.set_title(
        "Detection latency per attack (calibrated thresholds)", loc="left", color=INK, fontsize=11
    )
    ax.legend(frameon=False, fontsize=8, loc="upper left")
    fig.tight_layout()
    fig.savefig(path, facecolor=SURFACE)
    plt.close(fig)


def plot_ws(path: Path, samples: list[WsSample]) -> None:
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    fig, ax = plt.subplots(figsize=(7.5, 3.8), dpi=150, facecolor=SURFACE)
    _style(ax)
    for mode, label, color in (
        ("steady", "steady 50 events/s", BENIGN),
        ("burst", "burst of 2,000", MALICIOUS),
    ):
        v = sorted(s.latency_ms for s in samples if s.mode == mode)
        if not v:
            continue
        ax.step(
            v,
            [(i + 1) / len(v) for i in range(len(v))],
            where="post",
            color=color,
            linewidth=2,
            label=label,
        )
    ax.set_xlabel("bus.emit → client callback (ms, loopback WebSocket)", color=INK_2, fontsize=9)
    ax.set_ylabel("share of events delivered", color=INK_2, fontsize=9)
    ax.set_ylim(0, 1.02)
    ax.set_xlim(left=0)
    ax.set_title("Live event latency (cumulative)", loc="left", color=INK, fontsize=11)
    ax.legend(frameon=False, fontsize=8, loc="lower right")
    fig.tight_layout()
    fig.savefig(path, facecolor=SURFACE)
    plt.close(fig)


def _fmt(v: Any, digits: int = 1, pct: bool = False) -> str:
    if v is None:
        return "n/a"
    if pct:
        return f"{v * 100:.{digits}f}%"
    return f"{v:.{digits}f}" if isinstance(v, float) else str(v)


def _dist(d: dict[str, Any], digits: int = 1) -> str:
    if not d.get("n"):
        return "n/a"
    return f"{_fmt(d['p50'], digits)} / {_fmt(d['p95'], digits)} / {_fmt(d['max'], digits)} (n={d['n']})"


def write_summary(
    path: Path,
    meta: dict[str, Any],
    calib: dict[str, Any],
    cur: dict[str, Any],
    cal: dict[str, Any],
    ws: dict[str, Any],
) -> None:
    lines = [
        "# Phase 7 evaluation (generated)",
        "",
        f"Generated {meta['generated']} by `python -m app.cli evaluate` on {meta['platform']}, "
        f"Python {meta['python']}, {meta['cpus']} CPUs. Every number below was measured by that run; "
        "see the CSVs in this folder for the raw rows.",
        "",
        f"* Calibration seeds: {meta['calibration_seeds']}; evaluation (held-out) seeds: {meta['eval_seeds']}.",
        "* Traffic is simulated (`app.simulation.traffic`); latencies marked *simulated time* are",
        "  domain-time differences (attack start → event timestamp), bounded below by the 60 s window.",
        "  Compute timings are wall-clock on the machine above.",
        "",
        "## Threshold calibration",
        "",
        "Rule (`harness.calibrate`): alert threshold midway between the highest score that must not",
        "alert (benign, unknown device) and the lowest that must (vulnerable or attacked); critical",
        "midway between the strongest single-signal attack (flood alone) and the weakest corroborated",
        "compromise (KEV + C2, flood + C2). Automatic quarantine additionally requires observed",
        "evidence of compromise (behavior anomaly or indicator contact): an exposure-only device can be",
        "critical but is sent to operator review instead.",
        "",
        "| | Phase 3 thresholds | calibrated (seeds " + meta["calibration_seeds"] + ") |",
        "|---|---|---|",
    ]
    sug = calib.get("suggested") or {}
    for level in ("medium", "high", "critical"):
        lines.append(f"| {level} | {PHASE3_THRESHOLDS[level]} | {sug.get(level, 'n/a')} |")
    margins = calib.get("margins") or {}
    lines += [
        "",
        f"Calibration scores: must-not-alert max {calib.get('max_must_not_alert')}, must-alert min "
        f"{calib.get('min_must_alert')}, single-signal max {calib.get('max_single_signal')}, "
        f"corroborated min {calib.get('min_corroborated')}. Margins: alert {margins.get('alert')}, "
        f"quarantine {margins.get('quarantine')} points.",
        "",
        "## Detection quality (held-out seeds)",
        "",
        "| metric | Phase 3 thresholds | calibrated thresholds |",
        "|---|---|---|",
        f"| attacked devices that alerted (TPR) | {_fmt(cur['alert_tpr'], pct=True)} | {_fmt(cal['alert_tpr'], pct=True)} |",
        f"| benign devices that alerted (FPR) | {_fmt(cur['alert_fpr'], pct=True)} | {_fmt(cal['alert_fpr'], pct=True)} |",
        f"| multi-signal compromises recommended for automatic quarantine | {_fmt(cur['quarantine_tpr'], pct=True)} | {_fmt(cal['quarantine_tpr'], pct=True)} |",
        f"| single-signal attacks (flood alone) recommended for automatic quarantine | {_fmt(cur['single_signal_quarantined'], pct=True)} | {_fmt(cal['single_signal_quarantined'], pct=True)} |",
        f"| non-attacked devices recommended for automatic quarantine | {_fmt(cur['quarantine_fpr'], pct=True)} | {_fmt(cal['quarantine_fpr'], pct=True)} |",
        f"| unknown device flagged and not quarantined | {_fmt(cur['unknown_flagged'], pct=True)} | {_fmt(cal['unknown_flagged'], pct=True)} |",
        f"| vulnerable-only device alerted | {_fmt(cur['vulnerable_alerted'], pct=True)} | {_fmt(cal['vulnerable_alerted'], pct=True)} |",
        f"| vulnerable-only device recommended for automatic quarantine | {_fmt(cur['vulnerable_quarantined'], pct=True)} | {_fmt(cal['vulnerable_quarantined'], pct=True)} |",
        f"| attack windows flagged (window TPR) | {_fmt(cur['window_tpr'], pct=True)} | {_fmt(cal['window_tpr'], pct=True)} |",
        f"| normal windows flagged (window FPR) | {_fmt(cur['window_fpr'], 2, pct=True)} | {_fmt(cal['window_fpr'], 2, pct=True)} |",
        "",
        f"Devices evaluated (per threshold set): {cal['devices']}. Windows after warm-up: {cal['windows']}.",
        f"Highest held-out score of a device that must not alert: {meta.get('heldout_max_quiet')} "
        f"(calibration saw {calib.get('max_must_not_alert')}); alert threshold {calib.get('suggested', {}).get('medium')}.",
        "Window TPR counts every window containing an attack event, including the three single C2",
        "contacts, which are threat-intel signals rather than behavior anomalies.",
        "",
        "**Correlation accuracy** (each C2 contact vs. each decoy contact to a non-indicator IP; same",
        f"for both threshold sets): accuracy {_fmt(cal['correlation']['accuracy'], pct=True)}, "
        f"precision {_fmt(cal['correlation']['precision'], pct=True)}, recall "
        f"{_fmt(cal['correlation']['recall'], pct=True)} (TP {cal['correlation']['tp']}, FN "
        f"{cal['correlation']['fn']}, FP {cal['correlation']['fp']}, TN {cal['correlation']['tn']}).",
        "",
        "## Latency (calibrated thresholds; p50 / p95 / max)",
        "",
        "| scenario | first detection (s, simulated) | first alert (s, simulated) | IOC correlation (s, simulated) |",
        "|---|---|---|---|",
    ]
    for name, d in cal["latency_s"].items():
        lines.append(
            f"| {name.replace('_', ' ')} | {_dist(d['first_detection'], 0)} | {_dist(d['first_alert'], 0)} | {_dist(d['correlation'], 0)} |"
        )
    t = cal["timing"]
    lines += [
        "",
        "| measurement | p50 / p95 / max |",
        "|---|---|",
        f"| risk assessment per device (ms, wall-clock) | {_dist(t['risk_assess_ms'], 2)} |",
        f"| quarantine call, incl. audit + DB + status-node command (ms, wall-clock, dry-run driver) | {_dist(t['quarantine_ms'], 2)} |",
        f"| recovery after expiry, 60 s sweep only (s, simulated) | {_dist(t['recovery_s'], 1)} |",
        f"| unknown device discovery, first packet → DEVICE_CONNECTED (s, simulated) | {_dist(t['discovery_s'], 1)} |",
        f"| live event delivery, steady 50/s (ms, loopback WebSocket) | {_dist(ws['steady'], 1)} |",
        f"| live event delivery, burst of {ws['burst_size']} (ms, loopback WebSocket) | {_dist(ws['burst'], 1)} |",
        "",
        "Quarantine timings here use the dry-run driver; the real nftables path and device",
        "reconnection are measured in the virtual lab (`lab_runs.csv`, if present).",
        "",
        "![Risk scores](score_distribution.png)",
        "",
        "![Detection latency](detection_latency.png)",
        "",
        "![Live event latency](ws_latency.png)",
        "",
    ]
    path.write_text("\n".join(lines), encoding="utf-8", newline="\n")


def evaluate(
    calibration_seeds: list[int],
    eval_seeds: list[int],
    out: Path = OUT,
    ws: bool = True,
    progress: Any = print,
) -> dict[str, Any]:
    out.mkdir(parents=True, exist_ok=True)
    progress(f"calibration: {len(calibration_seeds)} seeds x {len(harness.SCENARIOS)} scenarios")
    calib_results = harness.run_all(calibration_seeds, thresholds=PHASE3_THRESHOLDS)
    calib = harness.calibrate(calib_results)
    current = dict(PHASE3_THRESHOLDS)
    suggested = calib.get("suggested")
    if not suggested:
        raise RuntimeError(f"scores not separable on the calibration seeds: {calib}")

    progress(f"evaluation, Phase 3 thresholds: {len(eval_seeds)} seeds")
    res_cur = harness.run_all(eval_seeds, thresholds=PHASE3_THRESHOLDS)
    progress(f"evaluation, calibrated thresholds: {len(eval_seeds)} seeds")
    res_cal = harness.run_all(eval_seeds, thresholds=suggested)

    samples: list[WsSample] = []
    if ws:
        progress("live event latency (Socket.IO, loopback)")
        samples = measure()

    def wsd(mode: str) -> dict[str, Any]:
        v = sorted(s.latency_ms for s in samples if s.mode == mode)
        if not v:
            return {"n": 0}
        return {
            "n": len(v),
            "p50": statistics.median(v),
            "p95": v[min(len(v) - 1, round(0.95 * (len(v) - 1)))],
            "max": v[-1],
        }

    summary_cur = harness.summarize(res_cur)
    summary_cal = harness.summarize(res_cal)
    ws_summary = {
        "steady": wsd("steady"),
        "burst": wsd("burst"),
        "burst_size": sum(s.mode == "burst" for s in samples),
    }

    for name, res in (("phase3", res_cur), ("calibrated", res_cal)):
        _write_csv(out / f"devices_{name}.csv", harness.rows(res.devices))
        _write_csv(out / f"timings_{name}.csv", harness.rows(res.timings))
        _write_csv(out / f"windows_{name}.csv", harness.rows(res.windows))
    _write_csv(out / "contacts.csv", harness.rows(res_cal.contacts))
    _write_csv(out / "calibration_devices.csv", harness.rows(calib_results.devices))
    _write_csv(out / "ws_latency.csv", [asdict(s) for s in samples])

    meta = {
        "generated": datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
        "platform": f"{platform.system()} {platform.release()} ({platform.machine()})",
        "python": platform.python_version(),
        "cpus": os.cpu_count(),
        "calibration_seeds": f"{calibration_seeds[0]}-{calibration_seeds[-1]}",
        "eval_seeds": f"{eval_seeds[0]}-{eval_seeds[-1]}",
        "heldout_max_quiet": max(
            (d.max_score for d in res_cal.devices if d.truth in ("benign", "unknown")), default=None
        ),
    }
    report = {
        "meta": meta,
        "calibration": calib,
        "phase3": summary_cur,
        "calibrated": summary_cal,
        "ws_latency_ms": ws_summary,
    }
    (out / "summary.json").write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    plot_scores(out / "score_distribution.png", res_cal, current, suggested)
    plot_latency(out / "detection_latency.png", res_cal)
    if samples:
        plot_ws(out / "ws_latency.png", samples)
    write_summary(out / "README.md", meta, calib, summary_cur, summary_cal, ws_summary)
    return report


def _load_devices(path: Path) -> list[harness.DeviceRow]:
    def num(v: str) -> float | None:
        return float(v) if v not in ("", "None") else None

    rows = []
    with path.open(encoding="utf-8") as fh:
        for r in csv.DictReader(fh):
            rows.append(
                harness.DeviceRow(
                    scenario=r["scenario"],
                    seed=int(r["seed"]),
                    device=r["device"],
                    truth=r["truth"],  # type: ignore[arg-type]
                    max_score=float(r["max_score"]),
                    max_level=r["max_level"],
                    final_score=float(r["final_score"]),
                    final_level=r["final_level"],
                    alerted=r["alerted"] == "True",
                    quarantine_worthy=r["quarantine_worthy"] == "True",
                    quarantined=r["quarantined"] == "True",
                    flagged_unknown=r["flagged_unknown"] == "True",
                    attack_start_s=num(r["attack_start_s"]),
                    first_detection_s=num(r["first_detection_s"]),
                    first_alert_s=num(r["first_alert_s"]),
                    correlation_s=num(r["correlation_s"]),
                )
            )
    return rows


def regenerate(out: Path = OUT) -> None:
    """Rebuild plots + README from the saved CSV/JSON (no re-simulation)."""
    report = json.loads((out / "summary.json").read_text(encoding="utf-8"))
    if "shipped" in report:  # files written before the key was renamed
        report["phase3"] = report.pop("shipped")
    devices = _load_devices(out / "devices_calibrated.csv")
    meta = report["meta"]
    meta.setdefault(
        "heldout_max_quiet",
        max((d.max_score for d in devices if d.truth in ("benign", "unknown")), default=None),
    )
    res = harness.Results(devices=devices)
    plot_scores(
        out / "score_distribution.png", res, PHASE3_THRESHOLDS, report["calibration"]["suggested"]
    )
    plot_latency(out / "detection_latency.png", res)
    samples = []
    ws_csv = out / "ws_latency.csv"
    if ws_csv.exists():
        with ws_csv.open(encoding="utf-8") as fh:
            samples = [
                WsSample(r["mode"], int(r["index"]), float(r["latency_ms"]))
                for r in csv.DictReader(fh)
            ]
    if samples:
        plot_ws(out / "ws_latency.png", samples)
    (out / "summary.json").write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    write_summary(
        out / "README.md", meta, report["calibration"], report.get("phase3") or report["shipped"], report["calibrated"],
        report["ws_latency_ms"],
    )  # fmt: skip
