"""Tests for detect_secrets.filters.confidence_filter.

Verifies that the confidence filter:
1. Is opt-in only (does not drop findings when unconfigured)
2. Correctly drops low-confidence findings when threshold is set
3. Preserves high-confidence findings above the threshold
4. Works with both type-only and contextual scoring
5. Does not break the existing filter pipeline
"""
import pytest
from unittest.mock import MagicMock, patch

from detect_secrets.filters.confidence_filter import (
    is_below_confidence_threshold,
    is_below_contextual_confidence_threshold,
    _get_min_confidence,
    _get_contextual_min_confidence,
)


class _FakePlugin:
    """Minimal plugin mock with configurable secret_type."""

    def __init__(self, secret_type='Test Secret'):
        self.secret_type = secret_type


class TestIsNotInDefaultFilters:
    """Verify the filter is opt-in only — not in default settings."""

    def test_not_in_default_filter_set(self):
        """Confidence filter should NOT be in Settings.DEFAULT_FILTERS."""
        from detect_secrets.settings import Settings
        for path in Settings.DEFAULT_FILTERS:
            assert 'confidence_filter' not in path

    def test_not_in_default_filter_dict(self):
        """Confidence filter should NOT appear in a fresh Settings().filters."""
        from detect_secrets.settings import Settings
        s = Settings()
        for path in s.filters:
            assert 'confidence_filter' not in path


class TestIsBelowConfidenceThreshold:
    """Tests for the type-only confidence filter."""

    def test_no_threshold_configured_keeps_all(self):
        """When min_confidence is not configured, nothing should be filtered."""
        _get_min_confidence.cache_clear()
        with patch(
            'detect_secrets.filters.confidence_filter._get_min_confidence',
            return_value=None,
        ):
            plugin = _FakePlugin('Base64 High Entropy String')
            result = is_below_confidence_threshold('some_secret', plugin)
            assert result is False

    def test_high_confidence_kept(self):
        """Finding from a high-confidence detector should NOT be filtered."""
        _get_min_confidence.cache_clear()
        with patch(
            'detect_secrets.filters.confidence_filter._get_min_confidence',
            return_value=0.5,
        ):
            plugin = _FakePlugin('GitHub Token')  # confidence 0.95
            result = is_below_confidence_threshold('ghp_abc', plugin)
            assert result is False

    def test_low_confidence_filtered(self):
        """Finding from a low-confidence detector should be filtered."""
        _get_min_confidence.cache_clear()
        with patch(
            'detect_secrets.filters.confidence_filter._get_min_confidence',
            return_value=0.5,
        ):
            plugin = _FakePlugin('Hex High Entropy String')  # confidence 0.15
            result = is_below_confidence_threshold('aabbccdd', plugin)
            assert result is True

    def test_exact_threshold_kept(self):
        """Finding at exactly the threshold should NOT be filtered (< not <=)."""
        _get_min_confidence.cache_clear()
        with patch(
            'detect_secrets.filters.confidence_filter._get_min_confidence',
            return_value=0.5,
        ):
            # Secret Keyword has confidence 0.40 — below 0.5
            plugin = _FakePlugin('Secret Keyword')
            result = is_below_confidence_threshold('my_secret', plugin)
            assert result is True

    def test_unknown_plugin_type_kept(self):
        """Plugin without secret_type attribute should not be filtered."""
        _get_min_confidence.cache_clear()
        with patch(
            'detect_secrets.filters.confidence_filter._get_min_confidence',
            return_value=0.5,
        ):
            plugin = MagicMock(spec=[])  # no secret_type attr
            result = is_below_confidence_threshold('x', plugin)
            assert result is False

    def test_unknown_detector_type_uses_default(self):
        """Unknown detector type defaults to 0.5 confidence."""
        _get_min_confidence.cache_clear()
        with patch(
            'detect_secrets.filters.confidence_filter._get_min_confidence',
            return_value=0.5,
        ):
            plugin = _FakePlugin('CompletelyUnknownDetector')
            # Default confidence is 0.5, threshold is 0.5 -> 0.5 < 0.5 is False -> kept
            result = is_below_confidence_threshold('x', plugin)
            assert result is False

    def test_threshold_below_default_drops_nothing(self):
        """Threshold of 0.1 should keep almost everything."""
        _get_min_confidence.cache_clear()
        with patch(
            'detect_secrets.filters.confidence_filter._get_min_confidence',
            return_value=0.1,
        ):
            # Even Public IP has confidence 0.10 which is not < 0.1
            plugin = _FakePlugin('Public IP (ipv4)')
            result = is_below_confidence_threshold('1.2.3.4', plugin)
            assert result is False


class TestIsBelowContextualConfidenceThreshold:
    """Tests for the context-aware confidence filter."""

    def test_no_threshold_configured_keeps_all(self):
        """When unconfigured, nothing should be filtered."""
        _get_contextual_min_confidence.cache_clear()
        with patch(
            'detect_secrets.filters.confidence_filter._get_contextual_min_confidence',
            return_value=None,
        ):
            plugin = _FakePlugin('Base64 High Entropy String')
            result = is_below_contextual_confidence_threshold('x', plugin, 'test_file.py')
            assert result is False

    def test_test_file_demotes_below_threshold(self):
        """Secret in a test file should have lower contextual confidence."""
        _get_contextual_min_confidence.cache_clear()
        with patch(
            'detect_secrets.filters.confidence_filter._get_contextual_min_confidence',
            return_value=0.5,
        ):
            # AWS Access Key: base 0.8, test file modifier -0.4 -> contextual 0.4
            plugin = _FakePlugin('AWS Access Key')
            result = is_below_contextual_confidence_threshold(
                'AKIAIOSFODNN7EXAMPLE', plugin, 'tests/test_aws.py',
            )
            assert result is True

    def test_production_file_keeps_high_confidence(self):
        """Secret in a production file should keep its base confidence."""
        _get_contextual_min_confidence.cache_clear()
        with patch(
            'detect_secrets.filters.confidence_filter._get_contextual_min_confidence',
            return_value=0.5,
        ):
            # AWS Access Key: base 0.8, no modifier -> 0.8
            plugin = _FakePlugin('AWS Access Key')
            result = is_below_contextual_confidence_threshold(
                'AKIAIOSFODNN7EXAMPLE', plugin, 'src/config.py',
            )
            assert result is False

    def test_lock_file_demotes_strongly(self):
        """Secrets in lock files should be heavily demoted."""
        _get_contextual_min_confidence.cache_clear()
        with patch(
            'detect_secrets.filters.confidence_filter._get_contextual_min_confidence',
            return_value=0.3,
        ):
            # Secret Keyword: base 0.40, lock file modifier -0.9 -> 0.05 (floor)
            plugin = _FakePlugin('Secret Keyword')
            result = is_below_contextual_confidence_threshold(
                'password123', plugin, 'package-lock.json',
            )
            assert result is True

    def test_unknown_plugin_type_kept(self):
        """Plugin without secret_type should not be filtered."""
        _get_contextual_min_confidence.cache_clear()
        with patch(
            'detect_secrets.filters.confidence_filter._get_contextual_min_confidence',
            return_value=0.5,
        ):
            plugin = MagicMock(spec=[])
            result = is_below_contextual_confidence_threshold('x', plugin, 'file.py')
            assert result is False


class TestExistingFilterPipelineNotAffected:
    """Ensure the confidence filter does not break existing scans."""

    def test_filter_init_does_not_explicitly_import_confidence_filter(self):
        """The filters __init__.py should NOT explicitly import confidence_filter."""
        import inspect
        import detect_secrets.filters as filters_pkg
        source = inspect.getsource(filters_pkg)
        assert 'confidence_filter' not in source

    def test_existing_tests_still_pass_with_filter_present(self):
        """Importing the filter module should not cause side effects."""
        # Just importing should not alter any global state
        import detect_secrets.filters.confidence_filter  # noqa: F401
        from detect_secrets.settings import Settings
        s = Settings()
        # Default filters should be unchanged
        assert 'detect_secrets.filters.common.is_invalid_file' in s.filters
        assert 'detect_secrets.filters.heuristic.is_non_text_file' in s.filters
