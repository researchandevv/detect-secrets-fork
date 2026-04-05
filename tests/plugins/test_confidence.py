"""Tests for the confidence scoring module.

Covers: DETECTOR_CONFIDENCE lookup, get_confidence resolution order,
get_contextual_confidence file-path adjustments, and edge cases.
"""
import pytest
from detect_secrets.plugins.confidence import (
    DETECTOR_CONFIDENCE,
    get_confidence,
    get_contextual_confidence,
)


class TestDetectorConfidence:
    """Tests for the DETECTOR_CONFIDENCE calibration table."""

    def test_high_confidence_detectors_above_080(self):
        """High-confidence detectors (specific prefixes) should score >= 0.80."""
        high_conf = ['Anthropic API Key', 'GitHub Token', 'AWS Access Key',
                     'Slack Token', 'Stripe Access Key']
        for det in high_conf:
            assert DETECTOR_CONFIDENCE.get(det, 0) >= 0.80, f"{det} should be >= 0.80"

    def test_low_confidence_detectors_below_040(self):
        """Entropy-based detectors should score < 0.40."""
        low_conf = ['Hex High Entropy String', 'Base64 High Entropy String']
        for det in low_conf:
            score = DETECTOR_CONFIDENCE.get(det, 0.5)
            assert score < 0.40, f"{det} should be < 0.40, got {score}"

    def test_all_scores_in_valid_range(self):
        """Every score must be in (0.0, 1.0) exclusive."""
        for det, score in DETECTOR_CONFIDENCE.items():
            assert 0.0 < score < 1.0, f"{det}: {score} out of range"

    def test_no_duplicate_detector_names(self):
        """Detector names should be unique (dict keys enforce this, but verify)."""
        assert len(DETECTOR_CONFIDENCE) == len(set(DETECTOR_CONFIDENCE.keys()))


class TestGetConfidence:
    """Tests for the get_confidence() function."""

    def test_known_detector_returns_calibrated_score(self):
        score = get_confidence('Anthropic API Key')
        assert score == 0.95

    def test_unknown_detector_returns_default(self):
        score = get_confidence('SomeNewDetector2026')
        assert score == 0.5  # default for unknown

    def test_empty_string_returns_default(self):
        score = get_confidence('')
        assert score == 0.5

    def test_return_type_is_float(self):
        for det in list(DETECTOR_CONFIDENCE.keys())[:5]:
            assert isinstance(get_confidence(det), float)


class TestGetContextualConfidence:
    """Tests for file-path-aware confidence adjustments."""

    def test_test_file_reduces_confidence(self):
        """Secrets in test files should have lower confidence."""
        base = get_confidence('AWS Access Key')
        ctx = get_contextual_confidence('AWS Access Key', 'tests/test_config.py')
        assert ctx <= base, "Test file should not increase confidence"

    def test_lock_file_reduces_confidence(self):
        """Lock files (package-lock.json etc.) should reduce confidence."""
        base = get_confidence('Hex High Entropy String')
        ctx = get_contextual_confidence('Hex High Entropy String', 'package-lock.json')
        assert ctx <= base

    def test_normal_file_no_reduction(self):
        """Source files in src/ should not reduce confidence."""
        base = get_confidence('GitHub Token')
        ctx = get_contextual_confidence('GitHub Token', 'src/config.py')
        assert ctx == base or abs(ctx - base) < 0.01

    def test_vendor_dir_reduces_confidence(self):
        """Vendor/third-party dirs should reduce confidence."""
        base = get_confidence('Slack Token')
        ctx = get_contextual_confidence('Slack Token', 'vendor/lib/client.py')
        assert ctx <= base

    def test_return_type_is_float(self):
        assert isinstance(
            get_contextual_confidence('AWS Access Key', 'main.py'), float)
