"""Confidence calibration from labeled scan results.

NOTE: This is a utility module, not a plugin detector.
It has no BasePlugin subclass and is not loaded by the plugin discovery system.

Transfers the weight profile methodology: instead of static confidence scores,
calibrate from actual true positive / false positive rates observed in real scans.

Usage:
    from detect_secrets.plugins.calibrate import calibrate_from_baseline

    # Given a baseline where secrets are marked as true/false positives:
    results = calibrate_from_baseline('.secrets.baseline')
    # Returns: {detector_type: {tp: N, fp: N, total: N, tp_rate: float, suggested_confidence: float}}
"""
import json
import os
from pathlib import Path
from .confidence import DETECTOR_CONFIDENCE


def calibrate_from_baseline(baseline_path: str) -> dict:
    """Analyze a labeled baseline to compute per-detector TP rates.

    A labeled baseline has secrets marked with is_secret: true/false
    (from `detect-secrets audit`). This function computes the actual
    TP rate per detector type and suggests confidence adjustments.
    """
    path = Path(baseline_path)
    if not path.exists():
        return {"error": f"Baseline not found: {baseline_path}"}

    data = json.loads(path.read_text())
    results = data.get("results", {})

    stats = {}  # {secret_type: {tp: 0, fp: 0, unlabeled: 0}}

    for filename, secrets in results.items():
        for secret in secrets:
            stype = secret.get("type", "unknown")
            if stype not in stats:
                stats[stype] = {"tp": 0, "fp": 0, "unlabeled": 0, "total": 0}

            stats[stype]["total"] += 1
            is_secret = secret.get("is_secret")
            if is_secret is True:
                stats[stype]["tp"] += 1
            elif is_secret is False:
                stats[stype]["fp"] += 1
            else:
                stats[stype]["unlabeled"] += 1

    # Compute TP rates and suggested confidence
    calibration = {}
    for stype, s in stats.items():
        labeled = s["tp"] + s["fp"]
        tp_rate = s["tp"] / labeled if labeled > 0 else None
        current_conf = DETECTOR_CONFIDENCE.get(stype, 0.5)

        calibration[stype] = {
            "true_positives": s["tp"],
            "false_positives": s["fp"],
            "unlabeled": s["unlabeled"],
            "total": s["total"],
            "labeled": labeled,
            "tp_rate": round(tp_rate, 3) if tp_rate is not None else None,
            "current_confidence": current_conf,
            "suggested_confidence": round(tp_rate, 2) if tp_rate is not None and labeled >= 5 else current_conf,
            "sample_sufficient": labeled >= 5,
        }

    return calibration


def format_calibration_report(calibration: dict) -> str:
    """Format calibration results as a readable report."""
    lines = ["# Confidence Calibration Report", ""]
    lines.append(f"{'Detector':<35} {'TP':>4} {'FP':>4} {'Rate':>6} {'Current':>8} {'Suggested':>9} {'Sufficient':>10}")
    lines.append("-" * 85)

    for stype, c in sorted(calibration.items(), key=lambda x: x[1].get("tp_rate") or 0, reverse=True):
        tp_rate = f"{c['tp_rate']:.1%}" if c['tp_rate'] is not None else "N/A"
        sufficient = "yes" if c["sample_sufficient"] else "no"
        lines.append(
            f"{stype:<35} {c['true_positives']:>4} {c['false_positives']:>4} "
            f"{tp_rate:>6} {c['current_confidence']:>8.2f} {c['suggested_confidence']:>9.2f} {sufficient:>10}"
        )

    return "\n".join(lines)


def save_calibration(calibration: dict, output_path: str) -> str:
    """Write calibration results to a JSON file atomically (tmp + rename).

    Ensures a crash mid-write never leaves a corrupt calibration file.
    Returns the output path on success.
    """
    tmp_path = output_path + '.tmp'
    with open(tmp_path, 'w') as f:
        json.dump(calibration, f, indent=2)
        f.write('\n')
    os.rename(tmp_path, output_path)
    return output_path
