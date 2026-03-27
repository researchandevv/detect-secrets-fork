"""Tests for utility modules: sarif_output, multi_provider, calibrate, confidence, baseline_stamp."""
import json
import tempfile
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# 1. SARIF output
# ---------------------------------------------------------------------------
class TestSarifOutput:
    """Tests for detect_secrets.util.sarif_output.to_sarif."""

    @staticmethod
    def _make_baseline():
        """Mock baseline: 2 files, 3 secrets (two share a type)."""
        return {
            "results": {
                "src/config.py": [
                    {"type": "AWS Access Key", "line_number": 10},
                    {"type": "Slack Token", "line_number": 25},
                ],
                "deploy/env.sh": [
                    {"type": "AWS Access Key", "line_number": 3},
                ],
            }
        }

    def test_sarif_version(self):
        from detect_secrets.util.sarif_output import to_sarif
        sarif = to_sarif(self._make_baseline())
        assert sarif["version"] == "2.1.0"

    def test_rules_deduplicated(self):
        from detect_secrets.util.sarif_output import to_sarif
        sarif = to_sarif(self._make_baseline())
        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        rule_ids = [r["id"] for r in rules]
        # 2 secrets of type "AWS Access Key" should produce only 1 rule
        assert rule_ids.count("aws_access_key") == 1
        # Total: AWS Access Key + Slack Token = 2 rules
        assert len(rules) == 2

    def test_result_count_matches_input(self):
        from detect_secrets.util.sarif_output import to_sarif
        sarif = to_sarif(self._make_baseline())
        results = sarif["runs"][0]["results"]
        assert len(results) == 3

    def test_results_have_physical_location(self):
        from detect_secrets.util.sarif_output import to_sarif
        sarif = to_sarif(self._make_baseline())
        for result in sarif["runs"][0]["results"]:
            loc = result["locations"][0]["physicalLocation"]
            assert "artifactLocation" in loc
            assert "uri" in loc["artifactLocation"]
            assert "region" in loc
            assert "startLine" in loc["region"]


# ---------------------------------------------------------------------------
# 2. Multi-provider concentration
# ---------------------------------------------------------------------------
class TestMultiProvider:
    """Tests for detect_secrets.plugins.multi_provider."""

    @staticmethod
    def _scan_results():
        """One file with 4 distinct types, one file with 1 type."""
        return {
            "supply_chain.py": [
                {"type": "Anthropic API Key"},
                {"type": "AWS Access Key"},
                {"type": "GitHub Token"},
                {"type": "Slack Token"},
            ],
            "simple.py": [
                {"type": "Hex High Entropy String"},
            ],
        }

    def test_concentrated_file_flagged(self):
        from detect_secrets.plugins.multi_provider import find_concentrated_files
        hits = find_concentrated_files(self._scan_results())
        flagged_files = [h["file"] for h in hits]
        assert "supply_chain.py" in flagged_files

    def test_single_type_file_not_flagged(self):
        from detect_secrets.plugins.multi_provider import find_concentrated_files
        hits = find_concentrated_files(self._scan_results())
        flagged_files = [h["file"] for h in hits]
        assert "simple.py" not in flagged_files

    def test_concentration_score_positive(self):
        from detect_secrets.plugins.multi_provider import calculate_concentration_score
        types = {"Anthropic API Key", "AWS Access Key", "GitHub Token", "Slack Token"}
        score = calculate_concentration_score(types)
        assert 0.0 < score <= 1.0

    def test_concentration_score_empty(self):
        from detect_secrets.plugins.multi_provider import calculate_concentration_score
        assert calculate_concentration_score(set()) == 0.0

    def test_threshold_parameter(self):
        from detect_secrets.plugins.multi_provider import find_concentrated_files
        # Default threshold=3: the 4-type file is caught
        hits_default = find_concentrated_files(self._scan_results())
        assert len(hits_default) == 1

        # Lower threshold=2: same result (only one file has >=2 distinct types here).
        # Add a 2-type file to show the threshold catches more.
        data = self._scan_results()
        data["two_types.py"] = [
            {"type": "OpenAI Token"},
            {"type": "Firebase API Key"},
        ]
        hits_low = find_concentrated_files(data, threshold=2)
        flagged = [h["file"] for h in hits_low]
        assert "two_types.py" in flagged
        assert "supply_chain.py" in flagged
        # With default threshold=3, two_types.py is NOT flagged
        hits_high = find_concentrated_files(data, threshold=3)
        flagged_high = [h["file"] for h in hits_high]
        assert "two_types.py" not in flagged_high


# ---------------------------------------------------------------------------
# 3. Calibrate
# ---------------------------------------------------------------------------
class TestCalibrate:
    """Tests for detect_secrets.plugins.calibrate."""

    @staticmethod
    def _write_mock_baseline(tmp_path: Path) -> str:
        """3 TP, 2 FP, 1 unlabeled -- all same type for simplicity."""
        baseline = {
            "results": {
                "file_a.py": [
                    {"type": "AWS Access Key", "is_secret": True, "line_number": 1},
                    {"type": "AWS Access Key", "is_secret": True, "line_number": 5},
                    {"type": "AWS Access Key", "is_secret": False, "line_number": 10},
                ],
                "file_b.py": [
                    {"type": "AWS Access Key", "is_secret": True, "line_number": 2},
                    {"type": "AWS Access Key", "is_secret": False, "line_number": 7},
                    {"type": "AWS Access Key", "line_number": 15},  # unlabeled
                ],
            }
        }
        p = tmp_path / "labeled.baseline"
        p.write_text(json.dumps(baseline))
        return str(p)

    def test_tp_fp_unlabeled_counts(self, tmp_path):
        from detect_secrets.plugins.calibrate import calibrate_from_baseline
        path = self._write_mock_baseline(tmp_path)
        cal = calibrate_from_baseline(path)
        entry = cal["AWS Access Key"]
        assert entry["true_positives"] == 3
        assert entry["false_positives"] == 2
        assert entry["unlabeled"] == 1

    def test_tp_rate(self, tmp_path):
        from detect_secrets.plugins.calibrate import calibrate_from_baseline
        path = self._write_mock_baseline(tmp_path)
        cal = calibrate_from_baseline(path)
        entry = cal["AWS Access Key"]
        # 3 TP out of 5 labeled = 0.6
        assert entry["tp_rate"] == 0.6

    def test_sample_sufficient_true(self, tmp_path):
        from detect_secrets.plugins.calibrate import calibrate_from_baseline
        path = self._write_mock_baseline(tmp_path)
        cal = calibrate_from_baseline(path)
        # 5 labeled >= 5 threshold
        assert cal["AWS Access Key"]["sample_sufficient"] is True

    def test_sample_sufficient_false(self, tmp_path):
        from detect_secrets.plugins.calibrate import calibrate_from_baseline
        baseline = {
            "results": {
                "f.py": [
                    {"type": "Slack Token", "is_secret": True, "line_number": 1},
                    {"type": "Slack Token", "is_secret": False, "line_number": 2},
                ],
            }
        }
        p = tmp_path / "small.baseline"
        p.write_text(json.dumps(baseline))
        cal = calibrate_from_baseline(str(p))
        # 2 labeled < 5
        assert cal["Slack Token"]["sample_sufficient"] is False

    def test_format_calibration_report(self, tmp_path):
        from detect_secrets.plugins.calibrate import calibrate_from_baseline, format_calibration_report
        path = self._write_mock_baseline(tmp_path)
        cal = calibrate_from_baseline(path)
        report = format_calibration_report(cal)
        assert isinstance(report, str)
        assert "Calibration Report" in report
        assert "Detector" in report
        assert "AWS Access Key" in report


# ---------------------------------------------------------------------------
# 4. Confidence rapid-dismiss
# ---------------------------------------------------------------------------
class TestRapidDismiss:
    """Tests for detect_secrets.plugins.confidence.should_rapid_dismiss."""

    @pytest.mark.parametrize("filename,expected", [
        ("package-lock.json", True),
        ("yarn.lock", True),
        ("src/app.py", False),
        ("node_modules/x/y.js", True),
    ])
    def test_should_rapid_dismiss(self, filename, expected):
        from detect_secrets.plugins.confidence import should_rapid_dismiss
        assert should_rapid_dismiss(filename) is expected


# ---------------------------------------------------------------------------
# 5. Baseline stamp
# ---------------------------------------------------------------------------
class TestBaselineStamp:
    """Tests for detect_secrets.util.baseline_stamp."""

    def test_get_current_stamp_keys(self):
        from detect_secrets.util.baseline_stamp import get_current_stamp
        stamp = get_current_stamp()
        assert "version" in stamp
        assert "plugins" in stamp
        assert "stamp_time" in stamp
        assert isinstance(stamp["plugins"], list)

    def test_stamp_baseline_adds_generated_by(self, tmp_path):
        from detect_secrets.util.baseline_stamp import stamp_baseline
        baseline = {"version": "1.5.0", "results": {}}
        p = tmp_path / "test.baseline"
        p.write_text(json.dumps(baseline))

        stamp_baseline(str(p))

        data = json.loads(p.read_text())
        assert "generated_by" in data
        assert "version" in data["generated_by"]
        assert "plugins" in data["generated_by"]

    def test_check_baseline_compat_with_stamped(self, tmp_path):
        from detect_secrets.util.baseline_stamp import stamp_baseline, check_baseline_compat
        baseline = {"version": "1.5.0", "results": {}}
        p = tmp_path / "compat.baseline"
        p.write_text(json.dumps(baseline))

        stamp_baseline(str(p))
        result = check_baseline_compat(str(p))

        # Same detector produced the stamp, so it should be compatible
        assert result["compatible"] is True
        assert result["version_match"] is True
        assert result["added_plugins"] == []
        assert result["removed_plugins"] == []
