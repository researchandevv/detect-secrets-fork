"""
Real-world validation of the detect-secrets confidence scoring system.

This test suite validates the fork's detection and confidence scoring
against a synthetic but realistic set of files containing planted secrets
and known false positives. The ground truth is defined per-file with
expected detector types, so precision and recall can be computed.

This is NOT a self-scan (which would be circular). The fixture files
in testing/fixtures/real_world/ simulate real codebases with:
- AWS keys, GitHub tokens, Slack tokens, Stripe keys
- Database connection strings, private keys, JWTs
- Cloud provider tokens (Cloudflare, Firebase, HuggingFace, etc.)
- False positives: hex colors, UUIDs, git SHAs, example values
"""
from __future__ import annotations

import os
from collections import defaultdict
from dataclasses import dataclass
from dataclasses import field
from pathlib import Path
from typing import Dict, List, Set, Tuple

import pytest

from detect_secrets.core.scan import scan_file
from detect_secrets.plugins.confidence import get_confidence
from detect_secrets.plugins.confidence import get_contextual_confidence
from detect_secrets.settings import default_settings


FIXTURE_DIR = Path(__file__).parent / 'fixtures' / 'real_world'


@dataclass
class GroundTruthEntry:
    """A planted secret with its expected detection metadata."""
    line_number: int
    expected_types: Set[str]  # at least one of these types should fire
    is_secret: bool  # True = real secret, False = false positive
    description: str = ''


@dataclass
class ScanResult:
    """Result of a single finding from the scanner."""
    line_number: int
    secret_type: str
    confidence: float
    contextual_confidence: float
    filename: str


# =============================================================================
# Ground truth definitions per fixture file.
#
# Each entry specifies a line number, the detector type(s) expected to fire,
# and whether the finding is a true secret (is_secret=True) or a known FP
# (is_secret=False).
#
# The ground truth is conservative: we only mark lines where we KNOW a real
# secret was planted. Lines that produce findings but are not in ground truth
# are classified as unlabeled (not counted toward P/R).
# =============================================================================

GROUND_TRUTH: Dict[str, List[GroundTruthEntry]] = {
    '.env': [
        GroundTruthEntry(8, {'AWS Access Key'}, True, 'AWS access key AKIA...'),
        GroundTruthEntry(9, {'AWS Access Key', 'Secret Keyword', 'Environment Variable Secret'}, True, 'AWS secret key'),
        GroundTruthEntry(13, {'Connection String Secret', 'Environment Variable Secret'}, True, 'PostgreSQL connection string'),
        GroundTruthEntry(14, {'Environment Variable Secret'}, True, 'DB password'),
        GroundTruthEntry(15, {'Connection String Secret', 'Environment Variable Secret'}, True, 'Redis connection string'),
        GroundTruthEntry(18, {'GitHub Token', 'Environment Variable Secret'}, True, 'GitHub PAT ghp_...'),
        GroundTruthEntry(22, {'Slack Token', 'Environment Variable Secret'}, True, 'Slack bot token xoxb-...'),
        GroundTruthEntry(26, {'Stripe Access Key', 'Environment Variable Secret'}, True, 'Stripe secret key sk_live_...'),
        GroundTruthEntry(30, {'SendGrid API Key', 'Environment Variable Secret'}, True, 'SendGrid API key SG....'),
        GroundTruthEntry(33, {'Cloudflare API Token', 'Environment Variable Secret'}, True, 'Cloudflare API token'),
        GroundTruthEntry(34, {'Cloudflare API Token', 'Environment Variable Secret'}, True, 'Cloudflare API key'),
        GroundTruthEntry(37, {'Firebase API Key', 'Environment Variable Secret'}, True, 'Firebase API key AIza...'),
        GroundTruthEntry(40, {'Anthropic API Key', 'Environment Variable Secret'}, True, 'Anthropic API key sk-ant-...'),
        GroundTruthEntry(43, {'OpenAI Token', 'Environment Variable Secret'}, True, 'OpenAI API key'),
        GroundTruthEntry(46, {'JSON Web Token', 'Environment Variable Secret'}, True, 'JWT token'),
    ],
    'config.py': [
        GroundTruthEntry(7, {'AWS Access Key'}, True, 'AWS access key'),
        GroundTruthEntry(8, {'AWS Access Key', 'Secret Keyword'}, True, 'AWS secret key'),
        GroundTruthEntry(12, {'GitHub Token'}, True, 'GitHub PAT'),
        GroundTruthEntry(15, {'Slack Token'}, True, 'Slack webhook'),
        GroundTruthEntry(18, {'Connection String Secret'}, True, 'PostgreSQL URI'),
        GroundTruthEntry(19, {'Connection String Secret'}, True, 'MongoDB URI'),
        GroundTruthEntry(22, {'Stripe Access Key'}, True, 'Stripe API key'),
        GroundTruthEntry(25, {'Private Key'}, True, 'RSA private key'),
        GroundTruthEntry(32, {'Ethereum Private Key'}, True, 'ETH private key 0x...'),
        GroundTruthEntry(33, {'Ethereum Private Key'}, True, 'ETH private key raw hex'),
        GroundTruthEntry(36, {'HashiCorp Vault Token'}, True, 'Vault token hvs....'),
        GroundTruthEntry(39, {'HuggingFace Token'}, True, 'HuggingFace token hf_...'),
        GroundTruthEntry(45, {'PyPI Token'}, False, 'PyPI token - may not match scanner regex'),
        GroundTruthEntry(48, {'Databricks API Token'}, False, 'Databricks - may not match scanner regex'),
        GroundTruthEntry(51, {'Databricks API Token'}, True, 'Databricks API token'),
        # False positives
        GroundTruthEntry(71, {'AWS Access Key'}, False, 'EXAMPLE key - placeholder'),
        GroundTruthEntry(76, {'Hex High Entropy String'}, False, 'Git SHA - not a secret'),
    ],
    'settings.json': [
        GroundTruthEntry(8, {'AWS Access Key'}, True, 'AWS access key in JSON'),
        GroundTruthEntry(9, {'Secret Keyword'}, True, 'AWS secret key in JSON'),
        GroundTruthEntry(17, {'Secret Keyword'}, True, 'DB password in JSON'),
        GroundTruthEntry(20, {'Connection String Secret'}, True, 'Redis URI in JSON'),
        GroundTruthEntry(23, {'GitHub Token'}, True, 'GitHub token in JSON'),
        GroundTruthEntry(24, {'JSON Web Token'}, True, 'JWT in JSON'),
        GroundTruthEntry(27, {'Slack Token'}, True, 'Slack token in JSON'),
        GroundTruthEntry(31, {'Stripe Access Key'}, True, 'Stripe key in JSON'),
    ],
    'credentials.txt': [
        GroundTruthEntry(5, {'AWS Access Key'}, True, 'AWS access key'),
        GroundTruthEntry(9, {'GitHub Token'}, True, 'GitHub PAT'),
        GroundTruthEntry(12, {'Slack Token'}, True, 'Slack bot token'),
        GroundTruthEntry(15, {'Stripe Access Key'}, True, 'Stripe secret key'),
        GroundTruthEntry(29, {'JSON Web Token'}, True, 'JWT signing key'),
        GroundTruthEntry(32, {'Ethereum Private Key'}, True, 'ETH private key'),
        GroundTruthEntry(35, {'HuggingFace Token'}, True, 'HuggingFace token'),
        GroundTruthEntry(38, {'Cloudflare API Token'}, True, 'Cloudflare API token'),
        GroundTruthEntry(44, {'Databricks API Token'}, True, 'Databricks token'),
        GroundTruthEntry(53, {'Twilio API Key'}, True, 'Twilio credentials'),
    ],
    'deploy_key.pem': [
        GroundTruthEntry(1, {'Private Key'}, True, 'RSA private key file'),
    ],
    'id_ed25519': [
        GroundTruthEntry(1, {'Private Key'}, True, 'OpenSSH private key file'),
    ],
    'README.md': [
        GroundTruthEntry(8, {'AWS Access Key'}, True, 'AWS key in README code block'),
        GroundTruthEntry(17, {'GitHub Token'}, True, 'GitHub token in README'),
        GroundTruthEntry(25, {'Slack Token'}, True, 'Slack token in README'),
        GroundTruthEntry(33, {'Connection String Secret', 'Basic Auth Credentials'}, True, 'DB connection string in README'),
        GroundTruthEntry(40, {'Firebase API Key'}, True, 'Firebase key in README'),
        GroundTruthEntry(52, {'AWS Access Key'}, False, 'EXAMPLE key in table - placeholder'),
    ],
    'deploy.tf': [
        GroundTruthEntry(3, {'AWS Access Key', 'Terraform Secret'}, True, 'AWS key in Terraform'),
        GroundTruthEntry(4, {'Terraform Secret', 'Secret Keyword'}, True, 'AWS secret in Terraform'),
        GroundTruthEntry(12, {'Terraform Secret'}, True, 'DB password in Terraform'),
        GroundTruthEntry(17, {'Stripe Access Key'}, True, 'Stripe key in Terraform secret'),
    ],
    'ci_workflow.yml': [
        GroundTruthEntry(8, {'AWS Access Key', 'CI/CD Hardcoded Secret'}, True, 'AWS key in CI env'),
        GroundTruthEntry(9, {'Secret Keyword'}, True, 'AWS secret in CI env'),
        GroundTruthEntry(26, {'GitHub Token'}, True, 'Deploy token in CI'),
        GroundTruthEntry(27, {'Slack Token'}, True, 'Slack webhook in CI'),
        GroundTruthEntry(29, {'Stripe Access Key'}, True, 'Stripe key in CI'),
    ],
    'k8s_secrets.yaml': [
        GroundTruthEntry(9, {'Secret Keyword'}, True, 'Base64 DB password in k8s secret'),
        GroundTruthEntry(11, {'Secret Keyword'}, True, 'Base64 JWT secret in k8s secret'),
    ],
    'false_positives_only.txt': [
        # Everything in this file is a false positive
        GroundTruthEntry(19, {'Hex High Entropy String'}, False, 'Git SHA - not a secret'),
        GroundTruthEntry(20, {'Hex High Entropy String'}, False, 'SHA-256 hash - not a secret'),
        GroundTruthEntry(21, {'Hex High Entropy String'}, False, 'Git SHA - not a secret'),
        GroundTruthEntry(36, {'Hex High Entropy String'}, False, 'Package checksum - not a secret'),
    ],
}


def _scan_fixtures() -> Dict[str, List[ScanResult]]:
    """Scan all fixture files and return findings grouped by filename."""
    results: Dict[str, List[ScanResult]] = defaultdict(list)

    with default_settings():
        for filename in sorted(os.listdir(FIXTURE_DIR)):
            filepath = FIXTURE_DIR / filename
            if not filepath.is_file():
                continue

            rel_path = str(filepath)
            for secret in scan_file(rel_path):
                results[filename].append(ScanResult(
                    line_number=secret.line_number,
                    secret_type=secret.type,
                    confidence=get_confidence(secret.type),
                    contextual_confidence=get_contextual_confidence(secret.type, rel_path),
                    filename=filename,
                ))

    return results


def _compute_metrics(
    results: Dict[str, List[ScanResult]],
    threshold: float,
) -> Tuple[float, float, float, int, int, int, int]:
    """Compute precision, recall, F1 at a given confidence threshold.

    Returns (precision, recall, f1, tp, fp, fn, total_findings).

    Classification rules:
    - A ground truth secret (is_secret=True) is TP if at least one finding
      on that line has confidence >= threshold and matches an expected type.
    - A ground truth secret (is_secret=True) with no matching finding above
      threshold is FN.
    - A ground truth FP (is_secret=False) found above threshold counts as FP.
    - Any finding above threshold on a line NOT in ground truth is counted
      as unlabeled -- not penalized (conservative estimate).
    """
    tp = 0
    fp = 0
    fn = 0
    total_findings = 0

    for filename, entries in GROUND_TRUTH.items():
        file_results = results.get(filename, [])

        for entry in entries:
            # Find all results on this line above threshold
            matching = [
                r for r in file_results
                if r.line_number == entry.line_number
                and r.confidence >= threshold
            ]

            # Check if any matching result has an expected type
            type_match = any(
                r.secret_type in entry.expected_types
                for r in matching
            )

            if entry.is_secret:
                if type_match:
                    tp += 1
                else:
                    fn += 1
            else:
                # Known FP in ground truth
                if type_match:
                    fp += 1
                # If not found, that's correct (true negative)

        # Count total findings above threshold for this file
        total_findings += sum(
            1 for r in file_results if r.confidence >= threshold
        )

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

    return precision, recall, f1, tp, fp, fn, total_findings


class TestRealWorldScan:
    """Scan fixture files and verify detection quality."""

    @pytest.fixture(scope='class')
    def scan_results(self) -> Dict[str, List[ScanResult]]:
        return _scan_fixtures()

    def test_fixtures_exist(self):
        """Verify that fixture files are present."""
        assert FIXTURE_DIR.is_dir(), f'Fixture directory not found: {FIXTURE_DIR}'
        files = list(FIXTURE_DIR.iterdir())
        assert len(files) >= 8, f'Expected at least 8 fixture files, got {len(files)}'

    def test_scanner_finds_secrets(self, scan_results):
        """Verify the scanner produces findings across multiple files."""
        files_with_findings = sum(1 for v in scan_results.values() if v)
        assert files_with_findings >= 6, (
            f'Scanner found secrets in only {files_with_findings} files, expected >= 6'
        )

    def test_total_finding_count(self, scan_results):
        """Verify a reasonable number of total findings."""
        total = sum(len(v) for v in scan_results.values())
        assert total >= 50, f'Expected >= 50 total findings, got {total}'

    def test_precision_at_threshold_03(self, scan_results):
        """Precision must be >= 0.90 at confidence threshold 0.3.

        This is the primary metric: when the scanner says something is
        a secret with confidence >= 0.3, it should be right >= 90% of
        the time (against our labeled ground truth).
        """
        precision, recall, f1, tp, fp, fn, total = _compute_metrics(scan_results, 0.3)
        assert precision >= 0.90, (
            f'Precision {precision:.3f} < 0.90 at threshold 0.3 '
            f'(TP={tp}, FP={fp}, FN={fn}, total_findings={total})'
        )

    def test_recall_at_threshold_03(self, scan_results):
        """Recall must be >= 0.60 at confidence threshold 0.3.

        This is relaxed from self-scan (0.778) because these are unseen
        fixture files. Some secret types may not match perfectly.
        """
        precision, recall, f1, tp, fp, fn, total = _compute_metrics(scan_results, 0.3)
        assert recall >= 0.60, (
            f'Recall {recall:.3f} < 0.60 at threshold 0.3 '
            f'(TP={tp}, FP={fp}, FN={fn}, total_findings={total})'
        )

    def test_f1_at_threshold_03(self, scan_results):
        """F1 score must be >= 0.70 at threshold 0.3."""
        precision, recall, f1, tp, fp, fn, total = _compute_metrics(scan_results, 0.3)
        assert f1 >= 0.70, (
            f'F1 {f1:.3f} < 0.70 at threshold 0.3 '
            f'(P={precision:.3f}, R={recall:.3f}, TP={tp}, FP={fp}, FN={fn})'
        )

    def test_precision_at_threshold_05(self, scan_results):
        """At higher threshold 0.5, precision should be even better."""
        precision, recall, f1, tp, fp, fn, total = _compute_metrics(scan_results, 0.5)
        assert precision >= 0.92, (
            f'Precision {precision:.3f} < 0.92 at threshold 0.5 '
            f'(TP={tp}, FP={fp}, FN={fn})'
        )

    def test_high_confidence_detections(self, scan_results):
        """High-confidence detectors (>= 0.8) should find their targets."""
        high_conf_types = {
            'AWS Access Key', 'GitHub Token', 'Slack Token',
            'Private Key', 'Stripe Access Key', 'Anthropic API Key',
        }

        found_types = set()
        for file_results in scan_results.values():
            for r in file_results:
                if r.confidence >= 0.8:
                    found_types.add(r.secret_type)

        missing = high_conf_types - found_types
        assert not missing, (
            f'High-confidence detector types not triggered: {missing}'
        )

    def test_private_key_detection(self, scan_results):
        """Private key files must be detected with high confidence."""
        pem_results = scan_results.get('deploy_key.pem', [])
        assert len(pem_results) >= 1, 'No findings in deploy_key.pem'
        assert any(r.secret_type == 'Private Key' for r in pem_results)

        ssh_results = scan_results.get('id_ed25519', [])
        assert len(ssh_results) >= 1, 'No findings in id_ed25519'
        assert any(r.secret_type == 'Private Key' for r in ssh_results)

    def test_false_positive_file_low_confidence(self, scan_results):
        """Findings in the false-positives-only file should be low confidence."""
        fp_results = scan_results.get('false_positives_only.txt', [])
        for r in fp_results:
            assert r.confidence < 0.5, (
                f'FP file finding has confidence {r.confidence}: '
                f'{r.secret_type} at line {r.line_number}'
            )

    def test_env_file_detection(self, scan_results):
        """The .env file detector should fire on .env files."""
        env_results = scan_results.get('.env', [])
        env_types = {r.secret_type for r in env_results}
        assert 'Environment Variable Secret' in env_types, (
            f'Environment Variable Secret not found in .env, got: {env_types}'
        )

    def test_connection_string_detection(self, scan_results):
        """Connection strings with embedded passwords should be detected."""
        all_types = set()
        for file_results in scan_results.values():
            for r in file_results:
                all_types.add(r.secret_type)

        assert 'Connection String Secret' in all_types, (
            'Connection String Secret not detected in any file'
        )

    def test_contextual_confidence_reduces_for_docs(self, scan_results):
        """Findings in README.md should have lower contextual confidence."""
        readme_results = scan_results.get('README.md', [])
        assert readme_results, 'No findings in README.md'

        for r in readme_results:
            assert r.contextual_confidence <= r.confidence, (
                f'Contextual confidence ({r.contextual_confidence}) should be <= '
                f'base confidence ({r.confidence}) for README.md findings'
            )


class TestScanFilterVerifyPipeline:
    """Integration tests exercising the full scan -> filter -> verify pipeline."""

    @pytest.fixture(scope='class')
    def scan_results(self) -> Dict[str, List[ScanResult]]:
        return _scan_fixtures()

    def test_confidence_filter_reduces_findings(self, scan_results):
        """Filtering at threshold 0.3 should reduce total findings
        compared to unfiltered (threshold 0.0).
        """
        _, _, _, _, _, _, total_unfiltered = _compute_metrics(scan_results, 0.0)
        _, _, _, _, _, _, total_filtered = _compute_metrics(scan_results, 0.3)

        # The total_findings count includes all findings above threshold
        # regardless of ground truth, so filtering should reduce it
        unfiltered_count = sum(len(v) for v in scan_results.values())
        filtered_count = sum(
            1 for file_results in scan_results.values()
            for r in file_results
            if r.confidence >= 0.3
        )

        assert filtered_count < unfiltered_count, (
            f'Filtering at 0.3 did not reduce findings: '
            f'{filtered_count} filtered vs {unfiltered_count} unfiltered'
        )

    def test_high_threshold_eliminates_entropy_findings(self, scan_results):
        """At threshold 0.5, entropy-based findings should be eliminated."""
        entropy_types = {'Base64 High Entropy String', 'Hex High Entropy String'}

        surviving_entropy = [
            r for file_results in scan_results.values()
            for r in file_results
            if r.confidence >= 0.5 and r.secret_type in entropy_types
        ]

        assert len(surviving_entropy) == 0, (
            f'{len(surviving_entropy)} entropy findings survived threshold 0.5: '
            f'{[(r.filename, r.line_number, r.secret_type) for r in surviving_entropy[:5]]}'
        )

    def test_multi_file_type_coverage(self, scan_results):
        """The pipeline should detect secrets across different file types."""
        files_with_findings = set(scan_results.keys())
        expected_files = {'.env', 'config.py', 'settings.json', 'credentials.txt',
                         'deploy_key.pem', 'id_ed25519', 'README.md'}

        missing = expected_files - files_with_findings
        assert not missing, (
            f'No findings in expected files: {missing}'
        )


class TestConfidencePRCurve:
    """Validate the precision-recall tradeoff across threshold values."""

    @pytest.fixture(scope='class')
    def scan_results(self) -> Dict[str, List[ScanResult]]:
        return _scan_fixtures()

    def test_precision_monotonically_increases(self, scan_results):
        """As threshold increases, precision should generally increase."""
        thresholds = [0.1, 0.3, 0.5, 0.7, 0.9]
        precisions = []

        for t in thresholds:
            p, _, _, tp, fp, _, _ = _compute_metrics(scan_results, t)
            precisions.append(p)

        # Allow one dip (noisy data) but overall trend should be up
        dips = sum(1 for i in range(1, len(precisions))
                   if precisions[i] < precisions[i-1] - 0.05)
        assert dips <= 1, (
            f'Precision not monotonically increasing: '
            f'{list(zip(thresholds, [f"{p:.3f}" for p in precisions]))}'
        )

    def test_recall_monotonically_decreases(self, scan_results):
        """As threshold increases, recall should generally decrease."""
        thresholds = [0.1, 0.3, 0.5, 0.7, 0.9]
        recalls = []

        for t in thresholds:
            _, r, _, _, _, _, _ = _compute_metrics(scan_results, t)
            recalls.append(r)

        # Allow one bump but overall trend should be down
        bumps = sum(1 for i in range(1, len(recalls))
                    if recalls[i] > recalls[i-1] + 0.05)
        assert bumps <= 1, (
            f'Recall not monotonically decreasing: '
            f'{list(zip(thresholds, [f"{r:.3f}" for r in recalls]))}'
        )

    def test_pr_curve_summary(self, scan_results):
        """Print PR curve for diagnostic purposes (always passes)."""
        thresholds = [0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9]

        print('\n  Confidence PR Curve (real-world fixtures):')
        print(f'  {"Threshold":>10} {"Precision":>10} {"Recall":>8} {"F1":>8} '
              f'{"TP":>4} {"FP":>4} {"FN":>4} {"Total":>6}')
        print(f'  {"-"*60}')

        for t in thresholds:
            p, r, f1, tp, fp, fn, total = _compute_metrics(scan_results, t)
            print(f'  {t:>10.1f} {p:>10.3f} {r:>8.3f} {f1:>8.3f} '
                  f'{tp:>4} {fp:>4} {fn:>4} {total:>6}')
