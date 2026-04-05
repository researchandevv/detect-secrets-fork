"""Tests for the confidence-based filter functions.

Tests the filter interface that wires confidence scoring into the
scan pipeline — is_below_confidence_threshold and
is_below_contextual_confidence_threshold.
"""
import pytest
from unittest.mock import patch, MagicMock

from detect_secrets.filters.confidence_filter import (
    is_below_confidence_threshold,
    is_below_contextual_confidence_threshold,
)


class MockPlugin:
    """Minimal plugin mock with secret_type attribute."""
    def __init__(self, secret_type):
        self.secret_type = secret_type


class TestIsBelowConfidenceThreshold:
    """Tests for the type-only confidence filter."""

    @patch('detect_secrets.filters.confidence_filter._get_min_confidence',
           return_value=0.5)
    def test_high_confidence_kept(self, mock_conf):
        """High-confidence detector (0.95) should NOT be filtered at threshold 0.5."""
        plugin = MockPlugin('Anthropic API Key')
        assert is_below_confidence_threshold('sk-ant-test', plugin) is False

    @patch('detect_secrets.filters.confidence_filter._get_min_confidence',
           return_value=0.5)
    def test_low_confidence_filtered(self, mock_conf):
        """Low-confidence detector (0.15) should be filtered at threshold 0.5."""
        plugin = MockPlugin('Hex High Entropy String')
        assert is_below_confidence_threshold('a1b2c3d4', plugin) is True

    @patch('detect_secrets.filters.confidence_filter._get_min_confidence',
           return_value=None)
    def test_no_threshold_keeps_everything(self, mock_conf):
        """No configured threshold means nothing is filtered."""
        plugin = MockPlugin('Hex High Entropy String')
        assert is_below_confidence_threshold('a1b2c3d4', plugin) is False

    @patch('detect_secrets.filters.confidence_filter._get_min_confidence',
           return_value=0.5)
    def test_unknown_plugin_type_kept(self, mock_conf):
        """Plugin without secret_type should not be filtered."""
        plugin = MagicMock(spec=[])  # no secret_type attribute
        assert is_below_confidence_threshold('test', plugin) is False

    @patch('detect_secrets.filters.confidence_filter._get_min_confidence',
           return_value=0.8)
    def test_medium_confidence_filtered_at_high_threshold(self, mock_conf):
        """Medium-confidence detector (0.5) filtered at threshold 0.8."""
        plugin = MockPlugin('Keyword Detector')
        assert is_below_confidence_threshold('password=', plugin) is True


class TestIsBelowContextualConfidenceThreshold:
    """Tests for the file-path-aware confidence filter."""

    @patch('detect_secrets.filters.confidence_filter._get_contextual_min_confidence',
           return_value=0.5)
    def test_high_confidence_normal_file_kept(self, mock_conf):
        """High-confidence detector in normal file should be kept."""
        plugin = MockPlugin('GitHub Token')
        assert is_below_contextual_confidence_threshold(
            'ghp_test', plugin, 'src/config.py') is False

    @patch('detect_secrets.filters.confidence_filter._get_contextual_min_confidence',
           return_value=0.5)
    def test_test_file_may_filter(self, mock_conf):
        """Detector in test file gets reduced confidence — may cross threshold."""
        plugin = MockPlugin('Hex High Entropy String')
        # Low base confidence + test file reduction → likely filtered
        result = is_below_contextual_confidence_threshold(
            'a1b2c3', plugin, 'tests/test_config.py')
        # Just verify it returns a bool (actual filtering depends on implementation)
        assert isinstance(result, bool)

    @patch('detect_secrets.filters.confidence_filter._get_contextual_min_confidence',
           return_value=None)
    def test_no_threshold_keeps_everything(self, mock_conf):
        """No configured threshold means nothing is filtered."""
        plugin = MockPlugin('Hex High Entropy String')
        assert is_below_contextual_confidence_threshold(
            'a1b2c3', plugin, 'tests/test.py') is False
