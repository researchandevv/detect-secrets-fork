import pytest

from detect_secrets.util.scan_stats import compute_stats, format_report, compare_stats


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
