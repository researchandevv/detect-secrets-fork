import pytest

from unittest.mock import patch
from detect_secrets.util.scan_stats import (
    compute_stats, format_report, compare_stats,
    _compute_confidence_tiers, _compute_contextual_confidence_tiers,
    _compute_context_impact, _tier_for_score,
)


def _make_baseline(results):
    return {
        'version': '1.5.0',
        'plugins_used': [{'name': 'KeywordDetector'}],
        'results': results,
    }


class TestComputeStats:

    def test_empty_baseline(self):
        stats = compute_stats(baseline_dict=_make_baseline({}))
        assert stats['total_secrets'] == 0
        assert stats['total_files'] == 0

    def test_counts_by_type(self):
        stats = compute_stats(baseline_dict=_make_baseline({
            'a.py': [
                {'type': 'AWS Access Key', 'hashed_secret': 'h1', 'line_number': 1},
                {'type': 'AWS Access Key', 'hashed_secret': 'h2', 'line_number': 2},
            ],
            'b.py': [
                {'type': 'GitHub Token', 'hashed_secret': 'h3', 'line_number': 1},
            ],
        }))
        assert stats['total_secrets'] == 3
        assert stats['total_files'] == 2
        assert stats['by_type']['AWS Access Key'] == 2
        assert stats['by_type']['GitHub Token'] == 1

    def test_top_files(self):
        stats = compute_stats(baseline_dict=_make_baseline({
            'many.py': [
                {'type': 'SK', 'hashed_secret': f'h{i}', 'line_number': i}
                for i in range(5)
            ],
            'few.py': [
                {'type': 'SK', 'hashed_secret': 'single', 'line_number': 1},
            ],
        }))
        assert stats['top_files'][0] == ('many.py', 5)
        assert stats['top_files'][1] == ('few.py', 1)

    def test_review_status_breakdown(self):
        stats = compute_stats(baseline_dict=_make_baseline({
            'test.py': [
                {'type': 'SK', 'hashed_secret': 'h1', 'line_number': 1, 'is_secret': True},
                {'type': 'SK', 'hashed_secret': 'h2', 'line_number': 2, 'is_secret': False},
                {'type': 'SK', 'hashed_secret': 'h3', 'line_number': 3},
            ],
        }))
        assert stats['by_review_status']['confirmed'] == 1
        assert stats['by_review_status']['allowlisted'] == 1
        assert stats['by_review_status']['unreviewed'] == 1

    def test_verified_count(self):
        stats = compute_stats(baseline_dict=_make_baseline({
            'test.py': [
                {'type': 'SK', 'hashed_secret': 'h1', 'line_number': 1, 'is_verified': True},
                {'type': 'SK', 'hashed_secret': 'h2', 'line_number': 2, 'is_verified': False},
            ],
        }))
        assert stats['verified_count'] == 1
        assert stats['unverified_count'] == 1


class TestFormatReport:

    def test_report_contains_sections(self):
        stats = compute_stats(baseline_dict=_make_baseline({
            'test.py': [
                {'type': 'AWS Access Key', 'hashed_secret': 'h1', 'line_number': 1},
            ],
        }))
        report = format_report(stats)
        assert 'Scan Statistics Report' in report
        assert 'Total secrets: 1' in report
        assert 'AWS Access Key' in report


class TestCompareStats:

    def test_improved(self):
        old = compute_stats(baseline_dict=_make_baseline({
            'a.py': [
                {'type': 'SK', 'hashed_secret': 'h1', 'line_number': 1},
                {'type': 'SK', 'hashed_secret': 'h2', 'line_number': 2},
            ],
        }))
        new = compute_stats(baseline_dict=_make_baseline({
            'a.py': [
                {'type': 'SK', 'hashed_secret': 'h1', 'line_number': 1},
            ],
        }))
        diff = compare_stats(old, new)
        assert diff['delta_total'] == -1
        assert diff['direction'] == 'improved'

    def test_new_type_detected(self):
        old = compute_stats(baseline_dict=_make_baseline({
            'a.py': [{'type': 'SK', 'hashed_secret': 'h1', 'line_number': 1}],
        }))
        new = compute_stats(baseline_dict=_make_baseline({
            'a.py': [{'type': 'SK', 'hashed_secret': 'h1', 'line_number': 1}],
            'b.py': [{'type': 'AWS Access Key', 'hashed_secret': 'h2', 'line_number': 1}],
        }))
        diff = compare_stats(old, new)
        assert 'AWS Access Key' in diff['new_types']


class TestTierForScore:
    """Tests for _tier_for_score helper — previously untested."""

    def test_high_threshold(self):
        assert _tier_for_score(0.8) == 'high'
        assert _tier_for_score(1.0) == 'high'

    def test_medium_threshold(self):
        assert _tier_for_score(0.4) == 'medium'
        assert _tier_for_score(0.79) == 'medium'

    def test_low_threshold(self):
        assert _tier_for_score(0.0) == 'low'
        assert _tier_for_score(0.39) == 'low'


class TestComputeConfidenceTiers:
    """Tests for _compute_confidence_tiers — previously untested."""

    def test_tiers_with_real_types(self):
        """Using real detector types, secrets should be categorized into tiers."""
        secrets = [
            {'type': 'AWS Access Key', 'filename': 'prod.py', 'line_number': 1},
        ]
        tiers = _compute_confidence_tiers(secrets)
        assert 'error' not in tiers
        # AWS Access Key has confidence 0.8, so should be high
        assert tiers.get('high', 0) >= 1

    def test_empty_list(self):
        tiers = _compute_confidence_tiers([])
        assert 'error' not in tiers
        assert sum(tiers.values()) == 0


class TestComputeContextualConfidenceTiers:
    """Tests for _compute_contextual_confidence_tiers — previously untested."""

    def test_test_file_demotes_confidence(self):
        """Secrets in test files should get lower contextual confidence."""
        secrets = [
            {'type': 'AWS Access Key', 'filename': 'tests/test_aws.py', 'line_number': 1},
        ]
        tiers = _compute_contextual_confidence_tiers(secrets)
        assert 'error' not in tiers
        # AWS Access Key is 0.8 base, but test file context should demote it
        # to medium (0.4) or lower
        assert tiers.get('high', 0) == 0

    def test_prod_file_keeps_high_confidence(self):
        """Secrets in production files should keep their base confidence."""
        secrets = [
            {'type': 'AWS Access Key', 'filename': 'src/config.py', 'line_number': 1},
        ]
        tiers = _compute_contextual_confidence_tiers(secrets)
        assert tiers.get('high', 0) >= 1


class TestComputeContextImpact:
    """Tests for _compute_context_impact — previously untested."""

    def test_reclassification_detected(self):
        """Secrets in test_ file paths should show as reclassified."""
        secrets = [
            {'type': 'AWS Access Key', 'filename': 'tests/test_aws.py', 'line_number': 1},
            {'type': 'AWS Access Key', 'filename': 'src/deploy.py', 'line_number': 5},
        ]
        impact = _compute_context_impact(secrets)
        assert 'error' not in impact
        assert impact['total_evaluated'] == 2
        # At least the test file should be reclassified
        assert impact['reclassified'] >= 1
        assert impact['demotions'] >= 1

    def test_empty_list_no_division_error(self):
        """Empty input should not cause zero-division."""
        impact = _compute_context_impact([])
        assert impact['reclassified_pct'] == 0.0
        assert impact['total_evaluated'] == 0

    def test_examples_capped_at_five(self):
        """Examples should be limited to 5 entries."""
        secrets = [
            {'type': 'AWS Access Key', 'filename': f'tests/test_{i}.py', 'line_number': 1}
            for i in range(20)
        ]
        impact = _compute_context_impact(secrets)
        assert len(impact['examples']) <= 5


class TestCompareStatsExtended:
    """Extended tests for compare_stats edge cases."""

    def test_unchanged_direction(self):
        """Same baseline compared to itself should show 'unchanged'."""
        baseline = _make_baseline({
            'a.py': [{'type': 'SK', 'hashed_secret': 'h1', 'line_number': 1}],
        })
        stats = compute_stats(baseline_dict=baseline)
        diff = compare_stats(stats, stats)
        assert diff['direction'] == 'unchanged'
        assert diff['delta_total'] == 0

    def test_worse_direction(self):
        """More secrets in new baseline should show 'worse'."""
        old = compute_stats(baseline_dict=_make_baseline({
            'a.py': [{'type': 'SK', 'hashed_secret': 'h1', 'line_number': 1}],
        }))
        new = compute_stats(baseline_dict=_make_baseline({
            'a.py': [
                {'type': 'SK', 'hashed_secret': 'h1', 'line_number': 1},
                {'type': 'SK', 'hashed_secret': 'h2', 'line_number': 2},
            ],
            'b.py': [{'type': 'AWS', 'hashed_secret': 'h3', 'line_number': 1}],
        }))
        diff = compare_stats(old, new)
        assert diff['direction'] == 'worse'
        assert diff['delta_total'] == 2
        assert diff['delta_files'] == 1

    def test_removed_type_detected(self):
        """Type that no longer appears should be in removed_types."""
        old = compute_stats(baseline_dict=_make_baseline({
            'a.py': [{'type': 'Obsolete', 'hashed_secret': 'h1', 'line_number': 1}],
        }))
        new = compute_stats(baseline_dict=_make_baseline({}))
        diff = compare_stats(old, new)
        assert 'Obsolete' in diff['removed_types']


class TestComputeStatsExtended:

    def test_raises_on_no_input(self):
        """Should raise ValueError when neither path nor dict provided."""
        with pytest.raises(ValueError, match='Provide either'):
            compute_stats()

    def test_baseline_version_and_plugins(self):
        """Stats should include baseline_version and plugins_used count."""
        baseline = {
            'version': '2.0.0',
            'plugins_used': [{'name': 'A'}, {'name': 'B'}],
            'results': {},
        }
        stats = compute_stats(baseline_dict=baseline)
        assert stats['baseline_version'] == '2.0.0'
        assert stats['plugins_used'] == 2


class TestComputeStatsFromFile:
    """Tests for compute_stats using file path instead of dict."""

    def test_compute_from_file_path(self, tmp_path):
        import json
        path = str(tmp_path / 'baseline.json')
        baseline = _make_baseline({
            'src/app.py': [
                {'type': 'AWS Access Key', 'hashed_secret': 'h1', 'line_number': 1},
            ],
        })
        with open(path, 'w') as f:
            json.dump(baseline, f)
        stats = compute_stats(baseline_path=path)
        assert stats['total_secrets'] == 1
        assert stats['total_files'] == 1
        assert stats['by_type']['AWS Access Key'] == 1

    def test_missing_version_defaults_to_unknown(self):
        """Baseline without version key should default to 'unknown'."""
        stats = compute_stats(baseline_dict={'results': {}, 'plugins_used': []})
        assert stats['baseline_version'] == 'unknown'

    def test_missing_plugins_used_defaults_to_zero(self):
        """Baseline without plugins_used key should default to 0."""
        stats = compute_stats(baseline_dict={'version': '1.0', 'results': {}})
        assert stats['plugins_used'] == 0


class TestCompareStatsTypeDelta:
    """Test type_deltas detail in compare_stats."""

    def test_type_delta_includes_old_and_new_counts(self):
        old = compute_stats(baseline_dict=_make_baseline({
            'a.py': [
                {'type': 'SK', 'hashed_secret': 'h1', 'line_number': 1},
                {'type': 'SK', 'hashed_secret': 'h2', 'line_number': 2},
            ],
        }))
        new = compute_stats(baseline_dict=_make_baseline({
            'a.py': [
                {'type': 'SK', 'hashed_secret': 'h1', 'line_number': 1},
            ],
        }))
        diff = compare_stats(old, new)
        assert 'SK' in diff['type_deltas']
        assert diff['type_deltas']['SK']['old'] == 2
        assert diff['type_deltas']['SK']['new'] == 1
        assert diff['type_deltas']['SK']['delta'] == -1

    def test_no_type_delta_when_counts_match(self):
        stats = compute_stats(baseline_dict=_make_baseline({
            'a.py': [{'type': 'SK', 'hashed_secret': 'h1', 'line_number': 1}],
        }))
        diff = compare_stats(stats, stats)
        assert len(diff['type_deltas']) == 0


class TestFormatReportExtended:

    def test_report_includes_contextual_tiers(self):
        """Report should include contextual confidence tier section when available."""
        stats = compute_stats(baseline_dict=_make_baseline({
            'tests/test_aws.py': [
                {'type': 'AWS Access Key', 'hashed_secret': 'h1', 'line_number': 1},
            ],
        }))
        report = format_report(stats)
        assert 'Contextual Confidence Tiers' in report

    def test_report_includes_context_impact(self):
        """Report should include context impact section."""
        stats = compute_stats(baseline_dict=_make_baseline({
            'tests/test_aws.py': [
                {'type': 'AWS Access Key', 'hashed_secret': 'h1', 'line_number': 1},
            ],
        }))
        report = format_report(stats)
        assert 'Context Impact' in report
