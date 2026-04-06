"""Tests for multi_provider credential concentration analysis."""
import pytest

from detect_secrets.plugins.multi_provider import (
    AI_PROVIDER_TYPES,
    CI_CD_TYPES,
    CLOUD_PROVIDER_TYPES,
    COMMS_TYPES,
    calculate_concentration_score,
    find_concentrated_files,
    format_report,
    _categorize,
)


class TestFindConcentratedFiles:
    """Test file-level concentration detection."""

    def test_empty_scan_results(self):
        assert find_concentrated_files({}) == []

    def test_single_type_per_file_not_flagged(self):
        results = {
            'config.py': [{'type': 'AWS Access Key'}],
            'app.py': [{'type': 'GitHub Token'}],
        }
        assert find_concentrated_files(results) == []

    def test_two_types_below_threshold(self):
        results = {
            'config.py': [
                {'type': 'AWS Access Key'},
                {'type': 'GitHub Token'},
            ],
        }
        assert find_concentrated_files(results) == []

    def test_three_types_flagged(self):
        results = {
            'leaked.env': [
                {'type': 'AWS Access Key'},
                {'type': 'GitHub Token'},
                {'type': 'Slack Token'},
            ],
        }
        hits = find_concentrated_files(results)
        assert len(hits) == 1
        assert hits[0]['file'] == 'leaked.env'
        assert hits[0]['distinct_types'] == 3
        assert hits[0]['count'] == 3

    def test_duplicate_types_counted_once(self):
        results = {
            'config.py': [
                {'type': 'AWS Access Key'},
                {'type': 'AWS Access Key'},
                {'type': 'GitHub Token'},
            ],
        }
        # Only 2 distinct types, below threshold
        assert find_concentrated_files(results) == []

    def test_multiple_files_sorted_by_score(self):
        results = {
            'low.py': [
                {'type': 'AWS Access Key'},
                {'type': 'GitHub Token'},
                {'type': 'Slack Token'},
            ],
            'high.py': [
                {'type': 'Anthropic API Key'},
                {'type': 'AWS Access Key'},
                {'type': 'GitHub Token'},
                {'type': 'Slack Token'},
            ],
        }
        hits = find_concentrated_files(results)
        assert len(hits) == 2
        # Both should score high; sorted by score descending
        assert hits[0]['score'] >= hits[1]['score']
        # Verify both files are present
        files = {h['file'] for h in hits}
        assert files == {'low.py', 'high.py'}

    def test_custom_threshold(self):
        results = {
            'config.py': [
                {'type': 'AWS Access Key'},
                {'type': 'GitHub Token'},
            ],
        }
        # threshold=2 should catch this
        hits = find_concentrated_files(results, threshold=2)
        assert len(hits) == 1

    def test_supply_chain_pattern(self):
        """Simulate a supply chain attack with credentials from all 4 categories."""
        results = {
            'malicious_setup.py': [
                {'type': 'Anthropic API Key'},       # AI
                {'type': 'AWS Access Key'},           # Cloud
                {'type': 'GitHub Token'},             # CI/CD
                {'type': 'Slack Token'},              # Comms
                {'type': 'OpenAI Token'},             # AI (2nd)
            ],
        }
        hits = find_concentrated_files(results)
        assert len(hits) == 1
        hit = hits[0]
        assert hit['distinct_types'] == 5
        assert 'ai_provider' in hit['categories']
        assert 'cloud_provider' in hit['categories']
        assert 'ci_cd' in hit['categories']
        assert 'comms' in hit['categories']
        assert hit['score'] > 0.9  # Very high confidence


class TestConcentrationScore:
    """Test the concentration scoring formula."""

    def test_empty_types(self):
        assert calculate_concentration_score(set()) == 0.0

    def test_single_type(self):
        score = calculate_concentration_score({'AWS Access Key'})
        assert 0.0 < score < 1.0

    def test_more_types_higher_score(self):
        score_3 = calculate_concentration_score({
            'AWS Access Key', 'GitHub Token', 'Slack Token',
        })
        score_5 = calculate_concentration_score({
            'AWS Access Key', 'GitHub Token', 'Slack Token',
            'Anthropic API Key', 'OpenAI Token',
        })
        # Both likely cap at 1.0; at minimum, 5 types should be >= 3 types
        assert score_5 >= score_3

    def test_cross_category_bonus(self):
        """Types from multiple categories should score higher than same-category."""
        same_cat = calculate_concentration_score({
            'Anthropic API Key', 'OpenAI Token', 'HuggingFace Token',
        })
        cross_cat = calculate_concentration_score({
            'Anthropic API Key', 'AWS Access Key', 'Slack Token',
        })
        assert cross_cat > same_cat

    def test_score_bounded_zero_one(self):
        # Even with many types, score should not exceed 1.0
        all_types = AI_PROVIDER_TYPES | CLOUD_PROVIDER_TYPES | CI_CD_TYPES | COMMS_TYPES
        score = calculate_concentration_score(all_types)
        assert 0.0 <= score <= 1.0


class TestCategorize:
    """Test provider category classification."""

    def test_ai_providers(self):
        cats = _categorize({'Anthropic API Key', 'OpenAI Token'})
        assert cats == {'ai_provider'}

    def test_cloud_providers(self):
        cats = _categorize({'AWS Access Key', 'Cloudflare API Token'})
        assert cats == {'cloud_provider'}

    def test_ci_cd(self):
        cats = _categorize({'GitHub Token', 'NPM tokens'})
        assert cats == {'ci_cd'}

    def test_comms(self):
        cats = _categorize({'Slack Token', 'Discord Bot Token'})
        assert cats == {'comms'}

    def test_mixed_categories(self):
        cats = _categorize({
            'Anthropic API Key', 'AWS Access Key',
            'GitHub Token', 'Slack Token',
        })
        assert cats == {'ai_provider', 'cloud_provider', 'ci_cd', 'comms'}

    def test_uncategorized_type(self):
        cats = _categorize({'SomeUnknownType'})
        assert cats == set()


class TestFormatReport:
    """Test report formatting."""

    def test_empty_report(self):
        assert 'No multi-provider' in format_report([])

    def test_report_with_findings(self):
        findings = [{
            'file': 'leaked.env',
            'distinct_types': 4,
            'types': {'AWS Access Key', 'GitHub Token', 'Slack Token', 'OpenAI Token'},
            'categories': {'cloud_provider', 'ci_cd', 'comms', 'ai_provider'},
            'score': 0.97,
            'count': 5,
        }]
        report = format_report(findings)
        assert 'leaked.env' in report
        assert '4' in report  # distinct types
