import json
import os
import tempfile

import pytest

from detect_secrets.util.rotation_check import (
    compare_baseline_dicts,
    check_rotation_compliance,
    rotation_summary,
)


def _make_baseline(results):
    """Helper to create a baseline dict."""
    return {
        'version': '1.5.0',
        'plugins_used': [],
        'results': results,
    }


def _make_secret(hashed_secret, line_number=1, secret_type='Secret Keyword'):
    return {
        'type': secret_type,
        'filename': 'test.py',
        'hashed_secret': hashed_secret,
        'is_verified': False,
        'line_number': line_number,
    }


class TestCompareBaselines:

    def test_unchanged_secrets(self):
        old = _make_baseline({
            'test.py': [_make_secret('abc123', line_number=5)],
        })
        new = _make_baseline({
            'test.py': [_make_secret('abc123', line_number=5)],
        })
        result = compare_baseline_dicts(old, new)
        assert len(result['unchanged']) == 1
        assert len(result['rotated']) == 0
        assert len(result['added']) == 0
        assert len(result['removed']) == 0

    def test_rotated_secret(self):
        old = _make_baseline({
            'test.py': [_make_secret('old_hash', line_number=5)],
        })
        new = _make_baseline({
            'test.py': [_make_secret('new_hash', line_number=5)],
        })
        result = compare_baseline_dicts(old, new)
        assert len(result['rotated']) == 1
        assert result['rotated'][0]['old_hash'] == 'old_hash'
        assert result['rotated'][0]['new_hash'] == 'new_hash'

    def test_added_secret(self):
        old = _make_baseline({})
        new = _make_baseline({
            'test.py': [_make_secret('abc123', line_number=10)],
        })
        result = compare_baseline_dicts(old, new)
        assert len(result['added']) == 1
        assert result['added'][0]['filename'] == 'test.py'

    def test_removed_secret(self):
        old = _make_baseline({
            'test.py': [_make_secret('abc123', line_number=10)],
        })
        new = _make_baseline({})
        result = compare_baseline_dicts(old, new)
        assert len(result['removed']) == 1

    def test_mixed_changes(self):
        old = _make_baseline({
            'a.py': [_make_secret('hash1', line_number=1)],
            'b.py': [_make_secret('hash2', line_number=2)],
            'c.py': [_make_secret('hash3', line_number=3)],
        })
        new = _make_baseline({
            'a.py': [_make_secret('hash1_rotated', line_number=1)],  # rotated
            'b.py': [_make_secret('hash2', line_number=2)],          # unchanged
            # c.py removed
            'd.py': [_make_secret('hash4', line_number=4)],          # added
        })
        result = compare_baseline_dicts(old, new)
        assert len(result['rotated']) == 1
        assert len(result['unchanged']) == 1
        assert len(result['removed']) == 1
        assert len(result['added']) == 1


class TestRotationSummary:

    def test_summary_format(self):
        comparison = {
            'rotated': [{'filename': 'a.py', 'line_number': 1, 'type': 'AWS', 'old_hash': 'x', 'new_hash': 'y'}],
            'added': [],
            'removed': [],
            'unchanged': [{'filename': 'b.py', 'line_number': 2, 'type': 'GitHub', 'hash': 'z'}],
        }
        report = rotation_summary(comparison)
        assert 'Rotated:   1' in report
        assert 'Unchanged: 1' in report
        assert '50.0%' in report


class TestRotationCompliance:

    def test_compliant_when_all_rotated(self):
        comparison = {
            'rotated': [{'filename': 'a.py', 'line_number': 1, 'type': 'AWS', 'old_hash': 'x', 'new_hash': 'y'}],
            'added': [],
            'removed': [],
            'unchanged': [],
        }
        result = check_rotation_compliance(
            comparison,
            expected_rotations=[('a.py', 1)],
        )
        assert result['compliant'] is True
        assert len(result['not_rotated']) == 0

    def test_non_compliant_when_not_rotated(self):
        comparison = {
            'rotated': [],
            'added': [],
            'removed': [],
            'unchanged': [{'filename': 'a.py', 'line_number': 1, 'type': 'AWS', 'hash': 'x'}],
        }
        result = check_rotation_compliance(
            comparison,
            expected_rotations=[('a.py', 1)],
        )
        assert result['compliant'] is False
        assert len(result['not_rotated']) == 1


class TestCompareBaselinesExtended:
    """Extended tests for edge cases in baseline comparison."""

    def test_multiple_secrets_same_file(self):
        """Multiple secrets in one file should be tracked independently."""
        old = _make_baseline({
            'config.py': [
                _make_secret('hash_a', line_number=5, secret_type='AWS'),
                _make_secret('hash_b', line_number=10, secret_type='GitHub'),
            ],
        })
        new = _make_baseline({
            'config.py': [
                _make_secret('hash_a_rotated', line_number=5, secret_type='AWS'),
                _make_secret('hash_b', line_number=10, secret_type='GitHub'),
            ],
        })
        result = compare_baseline_dicts(old, new)
        assert len(result['rotated']) == 1
        assert len(result['unchanged']) == 1
        assert result['rotated'][0]['type'] == 'AWS'
        assert result['unchanged'][0]['type'] == 'GitHub'

    def test_empty_baselines(self):
        """Comparing two empty baselines produces all-zero results."""
        old = _make_baseline({})
        new = _make_baseline({})
        result = compare_baseline_dicts(old, new)
        assert len(result['rotated']) == 0
        assert len(result['added']) == 0
        assert len(result['removed']) == 0
        assert len(result['unchanged']) == 0

    def test_missing_results_key(self):
        """Baseline without 'results' key should not crash."""
        old = {'version': '1.0'}
        new = {'version': '1.0'}
        result = compare_baseline_dicts(old, new)
        assert len(result['rotated']) == 0

    def test_secret_with_missing_line_number_defaults_to_zero(self):
        """Secret missing line_number should default to 0 in index."""
        old = _make_baseline({
            'test.py': [{'type': 'SK', 'hashed_secret': 'abc'}],
        })
        new = _make_baseline({
            'test.py': [{'type': 'SK', 'hashed_secret': 'abc'}],
        })
        result = compare_baseline_dicts(old, new)
        assert len(result['unchanged']) == 1
        assert result['unchanged'][0]['line_number'] == 0

    def test_same_hash_different_types_are_distinct_slots(self):
        """Same file+line but different type should be separate entries."""
        old = _make_baseline({
            'test.py': [
                _make_secret('hash1', line_number=5, secret_type='AWS'),
                _make_secret('hash2', line_number=5, secret_type='GitHub'),
            ],
        })
        new = _make_baseline({
            'test.py': [
                _make_secret('hash1', line_number=5, secret_type='AWS'),
                _make_secret('hash2_new', line_number=5, secret_type='GitHub'),
            ],
        })
        result = compare_baseline_dicts(old, new)
        assert len(result['unchanged']) == 1
        assert len(result['rotated']) == 1


class TestRotationSummaryExtended:

    def test_summary_with_added_and_removed(self):
        """Summary should include New Secrets and Removed Secrets sections."""
        comparison = {
            'rotated': [],
            'added': [{'filename': 'new.py', 'line_number': 1, 'type': 'SK', 'hash': 'x'}],
            'removed': [{'filename': 'old.py', 'line_number': 1, 'type': 'SK', 'hash': 'y'}],
            'unchanged': [],
        }
        report = rotation_summary(comparison)
        assert 'New Secrets' in report
        assert 'Removed Secrets' in report
        assert 'new.py' in report
        assert 'old.py' in report

    def test_summary_zero_old_secrets(self):
        """Zero-division safe when no old secrets existed."""
        comparison = {
            'rotated': [],
            'added': [{'filename': 'a.py', 'line_number': 1, 'type': 'SK', 'hash': 'x'}],
            'removed': [],
            'unchanged': [],
        }
        report = rotation_summary(comparison)
        assert 'Rotation rate' not in report  # no old secrets to calculate rate from


class TestLoadBaselineAndCompareFiles:
    """Tests for file-based load_baseline and compare_baselines (not dict-based)."""

    def test_load_baseline_from_file(self, tmp_path):
        """load_baseline should read and parse a JSON file."""
        from detect_secrets.util.rotation_check import load_baseline
        path = str(tmp_path / 'baseline.json')
        with open(path, 'w') as f:
            json.dump({'version': '1.0', 'results': {'a.py': []}}, f)
        data = load_baseline(path)
        assert data['version'] == '1.0'

    def test_compare_baselines_from_files(self, tmp_path):
        """compare_baselines (file paths) should produce identical results to dict version."""
        from detect_secrets.util.rotation_check import compare_baselines
        old_path = str(tmp_path / 'old.json')
        new_path = str(tmp_path / 'new.json')
        with open(old_path, 'w') as f:
            json.dump({'results': {'a.py': [_make_secret('h1', 1)]}}, f)
        with open(new_path, 'w') as f:
            json.dump({'results': {'a.py': [_make_secret('h2', 1)]}}, f)
        result = compare_baselines(old_path, new_path)
        assert len(result['rotated']) == 1
        assert result['rotated'][0]['old_hash'] == 'h1'
        assert result['rotated'][0]['new_hash'] == 'h2'

    def test_load_baseline_invalid_json(self, tmp_path):
        """load_baseline with invalid JSON should raise."""
        from detect_secrets.util.rotation_check import load_baseline
        path = str(tmp_path / 'bad.json')
        with open(path, 'w') as f:
            f.write('not json{{{')
        with pytest.raises(json.JSONDecodeError):
            load_baseline(path)

    def test_compare_baselines_large_diff(self, tmp_path):
        """Many added and removed secrets across files should be categorized correctly."""
        from detect_secrets.util.rotation_check import compare_baselines
        old_results = {
            f'old_{i}.py': [_make_secret(f'hash_{i}', 1)] for i in range(10)
        }
        new_results = {
            f'new_{i}.py': [_make_secret(f'hash_new_{i}', 1)] for i in range(10)
        }
        old_path = str(tmp_path / 'old.json')
        new_path = str(tmp_path / 'new.json')
        with open(old_path, 'w') as f:
            json.dump({'results': old_results}, f)
        with open(new_path, 'w') as f:
            json.dump({'results': new_results}, f)
        result = compare_baselines(old_path, new_path)
        assert len(result['removed']) == 10
        assert len(result['added']) == 10
        assert len(result['rotated']) == 0
        assert len(result['unchanged']) == 0


class TestComplianceExtended:

    def test_no_expected_rotations_all_rotated_is_compliant(self):
        """With expected_rotations=None, compliance requires 0 unchanged."""
        comparison = {
            'rotated': [{'filename': 'a.py', 'line_number': 1, 'type': 'AWS', 'old_hash': 'x', 'new_hash': 'y'}],
            'added': [],
            'removed': [],
            'unchanged': [],
        }
        result = check_rotation_compliance(comparison)
        assert result['compliant'] is True
        assert result['rotated_count'] == 1
        assert result['unchanged_count'] == 0

    def test_no_expected_rotations_unchanged_means_noncompliant(self):
        """With expected_rotations=None, any unchanged secret is noncompliant."""
        comparison = {
            'rotated': [],
            'added': [],
            'removed': [],
            'unchanged': [{'filename': 'a.py', 'line_number': 1, 'type': 'AWS', 'hash': 'x'}],
        }
        result = check_rotation_compliance(comparison)
        assert result['compliant'] is False
        assert len(result['not_rotated']) == 1

    def test_unexpected_rotations_reported(self):
        """Rotations not in expected list should appear in unexpected_changes."""
        comparison = {
            'rotated': [
                {'filename': 'a.py', 'line_number': 1, 'type': 'AWS', 'old_hash': 'x', 'new_hash': 'y'},
                {'filename': 'b.py', 'line_number': 2, 'type': 'SK', 'old_hash': 'p', 'new_hash': 'q'},
            ],
            'added': [],
            'removed': [],
            'unchanged': [],
        }
        result = check_rotation_compliance(comparison, expected_rotations=[('a.py', 1)])
        assert result['compliant'] is True
        assert len(result['unexpected_changes']) == 1
        assert result['unexpected_changes'][0]['filename'] == 'b.py'
