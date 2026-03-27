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
