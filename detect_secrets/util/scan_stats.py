"""
Scan Statistics Utility

Aggregates statistics from a .secrets.baseline file:
- Total secrets by detector type
- Total secrets by file
- Breakdown by confidence tier (requires confidence module)
- Top N files by secret count
- Allowlist vs unreviewed vs confirmed breakdown

Useful for reporting, compliance dashboards, and prioritizing remediation.

Statistics reflect a consistent snapshot of the baseline at read time, not
a partial read of a changing file.
"""
import json
from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional, Tuple


def load_baseline(path: str) -> Dict[str, Any]:
    """Load a .secrets.baseline file."""
    with open(path) as f:
        return json.load(f)


def compute_stats(
    baseline_path: Optional[str] = None,
    baseline_dict: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Compute aggregate statistics from a baseline.

    Provide either baseline_path or baseline_dict (already loaded).

    Returns a dict with:
        total_secrets: int
        total_files: int
        by_type: dict of {secret_type: count}
        by_file: dict of {filename: count}
        top_files: list of (filename, count) tuples, descending
        by_review_status: dict of {status: count}
        by_confidence_tier: dict of {tier: count} (if confidence module available)
    """
    if baseline_dict is None:
        if baseline_path is None:
            raise ValueError('Provide either baseline_path or baseline_dict')
        baseline_dict = load_baseline(baseline_path)

    results = baseline_dict.get('results', {})

    total_secrets = 0
    by_type: Counter = Counter()
    by_file: Counter = Counter()
    by_review_status: Counter = Counter()
    all_secrets: List[Dict[str, Any]] = []

    for filename, secrets in results.items():
        count = len(secrets)
        total_secrets += count
        by_file[filename] = count

        for secret in secrets:
            secret_type = secret.get('type', 'unknown')
            by_type[secret_type] += 1

            # Review status
            is_secret = secret.get('is_secret')
            if is_secret is True:
                by_review_status['confirmed'] += 1
            elif is_secret is False:
                by_review_status['allowlisted'] += 1
            else:
                by_review_status['unreviewed'] += 1

            all_secrets.append({
                'filename': filename,
                'type': secret_type,
                'line_number': secret.get('line_number', 0),
                'is_verified': secret.get('is_verified', False),
            })

    # Top files by secret count
    top_files = by_file.most_common(10)

    # Confidence tier breakdown (best-effort)
    by_confidence_tier = _compute_confidence_tiers(all_secrets)

    # Verified vs unverified
    verified_count = sum(1 for s in all_secrets if s.get('is_verified'))

    # Contextual confidence tiers (file-path aware)
    by_contextual_tier = _compute_contextual_confidence_tiers(all_secrets)

    # Context impact: how many findings change tier when file context is applied
    ctx_impact = _compute_context_impact(all_secrets)

    # Weighted priority scores
    weighted = _compute_weighted_scores(all_secrets)

    return {
        'total_secrets': total_secrets,
        'total_files': len(results),
        'by_type': dict(by_type.most_common()),
        'by_file': dict(by_file),
        'top_files': top_files,
        'by_review_status': dict(by_review_status),
        'by_confidence_tier': by_confidence_tier,
        'by_contextual_tier': by_contextual_tier,
        'context_impact': ctx_impact,
        'weighted_scores': weighted,
        'verified_count': verified_count,
        'unverified_count': total_secrets - verified_count,
        'baseline_version': baseline_dict.get('version', 'unknown'),
        'plugins_used': len(baseline_dict.get('plugins_used', [])),
    }


def _compute_confidence_tiers(
    secrets: List[Dict[str, Any]],
) -> Dict[str, int]:
    """Group secrets into confidence tiers using the confidence module.

    Tiers:
        high (>= 0.8): Almost certainly real secrets
        medium (0.4 - 0.8): Likely real, needs review
        low (< 0.4): Probably false positive
    """
    try:
        from detect_secrets.plugins.confidence import get_confidence
    except ImportError:
        return {'error': 'confidence module not available'}

    tiers: Counter = Counter()
    for secret in secrets:
        score = get_confidence(secret['type'])
        if score >= 0.8:
            tiers['high'] += 1
        elif score >= 0.4:
            tiers['medium'] += 1
        else:
            tiers['low'] += 1

    return dict(tiers)


def _compute_weighted_scores(
    secrets: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Compute confidence-weighted priority scores.

    Instead of raw counts per tier, produces a single weighted total
    and per-type weighted scores for remediation prioritization.

    weighted_total = sum(confidence_score for each finding)
    A repo with 100 low-confidence findings (score 0.2 each = 20.0) is
    lower priority than one with 10 high-confidence findings (0.9 each = 9.0)
    when normalized by count.
    """
    try:
        from detect_secrets.plugins.confidence import get_contextual_confidence
    except ImportError:
        return {'error': 'confidence module not available'}

    weighted_total = 0.0
    by_type_weighted: Dict[str, float] = {}

    for secret in secrets:
        secret_type = secret['type']
        filename = secret.get('filename', '')
        score = get_contextual_confidence(secret_type, filename)
        weighted_total += score
        by_type_weighted[secret_type] = by_type_weighted.get(secret_type, 0.0) + score

    total = len(secrets)
    return {
        'weighted_total': round(weighted_total, 2),
        'weighted_mean': round(weighted_total / total, 3) if total > 0 else 0.0,
        'by_type_weighted': {k: round(v, 2) for k, v in
                            sorted(by_type_weighted.items(), key=lambda x: -x[1])},
    }


def _compute_contextual_confidence_tiers(
    secrets: List[Dict[str, Any]],
) -> Dict[str, int]:
    """Group secrets into confidence tiers using contextual (file-aware) scoring.

    Same tier thresholds as _compute_confidence_tiers, but uses
    get_contextual_confidence which adjusts scores based on file path patterns
    (test files, lock files, vendor dirs, etc.).

    This answers the question from claim_confidence_requires_context_not_just_type:
    does file context actually change the confidence distribution?
    """
    try:
        from detect_secrets.plugins.confidence import get_contextual_confidence
    except ImportError:
        return {'error': 'confidence module not available'}

    tiers: Counter = Counter()
    for secret in secrets:
        score = get_contextual_confidence(secret['type'], secret.get('filename', ''))
        if score >= 0.8:
            tiers['high'] += 1
        elif score >= 0.4:
            tiers['medium'] += 1
        else:
            tiers['low'] += 1

    return dict(tiers)


def _tier_for_score(score: float) -> str:
    """Map a confidence score to its tier name."""
    if score >= 0.8:
        return 'high'
    elif score >= 0.4:
        return 'medium'
    return 'low'


def _compute_context_impact(
    secrets: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Compute how many findings change confidence tier when file context is applied.

    Returns:
        reclassified: number of findings that moved to a different tier
        demotions: findings that dropped to a lower tier (e.g., high -> medium)
        promotions: findings that moved to a higher tier (unlikely but possible)
        reclassified_pct: percentage of total findings reclassified
        examples: up to 5 example reclassifications with details
    """
    try:
        from detect_secrets.plugins.confidence import get_confidence, get_contextual_confidence
    except ImportError:
        return {'error': 'confidence module not available'}

    reclassified = 0
    demotions = 0
    promotions = 0
    examples: List[Dict[str, Any]] = []
    tier_order = {'low': 0, 'medium': 1, 'high': 2}

    for secret in secrets:
        secret_type = secret['type']
        filename = secret.get('filename', '')
        base_score = get_confidence(secret_type)
        ctx_score = get_contextual_confidence(secret_type, filename)
        base_tier = _tier_for_score(base_score)
        ctx_tier = _tier_for_score(ctx_score)

        if base_tier != ctx_tier:
            reclassified += 1
            if tier_order[ctx_tier] < tier_order[base_tier]:
                demotions += 1
            else:
                promotions += 1
            if len(examples) < 5:
                examples.append({
                    'type': secret_type,
                    'filename': filename,
                    'base_score': base_score,
                    'contextual_score': ctx_score,
                    'base_tier': base_tier,
                    'contextual_tier': ctx_tier,
                })

    total = len(secrets)
    return {
        'reclassified': reclassified,
        'demotions': demotions,
        'promotions': promotions,
        'reclassified_pct': round(reclassified / total * 100, 1) if total > 0 else 0.0,
        'total_evaluated': total,
        'examples': examples,
    }


def format_report(stats: Dict[str, Any]) -> str:
    """Format statistics as a human-readable report."""
    lines = [
        'Scan Statistics Report',
        '=' * 50,
        f'Baseline version: {stats["baseline_version"]}',
        f'Plugins used: {stats["plugins_used"]}',
        '',
        f'Total secrets: {stats["total_secrets"]}',
        f'Total files with secrets: {stats["total_files"]}',
        f'Verified: {stats["verified_count"]}  |  Unverified: {stats["unverified_count"]}',
    ]

    # Review status
    lines.append('\n--- Review Status ---')
    for status, count in sorted(stats['by_review_status'].items()):
        lines.append(f'  {status}: {count}')

    # Confidence tiers
    if stats['by_confidence_tier'] and 'error' not in stats['by_confidence_tier']:
        lines.append('\n--- Confidence Tiers ---')
        for tier in ('high', 'medium', 'low'):
            count = stats['by_confidence_tier'].get(tier, 0)
            lines.append(f'  {tier}: {count}')

    # Contextual confidence tiers
    ctx_tier = stats.get('by_contextual_tier', {})
    if ctx_tier and 'error' not in ctx_tier:
        lines.append('\n--- Contextual Confidence Tiers (file-path aware) ---')
        for tier in ('high', 'medium', 'low'):
            count = ctx_tier.get(tier, 0)
            lines.append(f'  {tier}: {count}')

    # Context impact
    impact = stats.get('context_impact', {})
    if impact and 'error' not in impact:
        lines.append('\n--- Context Impact ---')
        lines.append(f'  Reclassified: {impact["reclassified"]} / {impact["total_evaluated"]} ({impact["reclassified_pct"]}%)')
        lines.append(f'  Demotions (high->med, med->low): {impact["demotions"]}')
        lines.append(f'  Promotions: {impact["promotions"]}')
        if impact.get('examples'):
            lines.append('  Examples:')
            for ex in impact['examples']:
                lines.append(f'    {ex["type"]} in {ex["filename"]}: {ex["base_tier"]} -> {ex["contextual_tier"]} ({ex["base_score"]} -> {ex["contextual_score"]})')

    # Weighted priority scores
    weighted = stats.get('weighted_scores', {})
    if weighted and 'error' not in weighted:
        lines.append('\n--- Confidence-Weighted Priority ---')
        lines.append(f'  Weighted total: {weighted["weighted_total"]} (sum of confidence scores)')
        lines.append(f'  Weighted mean:  {weighted["weighted_mean"]} (avg confidence per finding)')
        if weighted.get('by_type_weighted'):
            lines.append('  By type (weighted):')
            for stype, wscore in list(weighted['by_type_weighted'].items())[:5]:
                lines.append(f'    {stype}: {wscore}')

    # By type
    lines.append('\n--- Secrets by Type ---')
    for secret_type, count in sorted(
        stats['by_type'].items(), key=lambda x: -x[1]
    ):
        lines.append(f'  {secret_type}: {count}')

    # Top files
    lines.append('\n--- Top 10 Files by Secret Count ---')
    for filename, count in stats['top_files']:
        lines.append(f'  {count:4d}  {filename}')

    return '\n'.join(lines)


def compare_stats(
    old_stats: Dict[str, Any],
    new_stats: Dict[str, Any],
) -> Dict[str, Any]:
    """Compare statistics between two baselines (e.g., before/after scan).

    Returns changes in total counts, new types, resolved types.
    """
    delta_total = new_stats['total_secrets'] - old_stats['total_secrets']
    delta_files = new_stats['total_files'] - old_stats['total_files']

    old_types = set(old_stats['by_type'].keys())
    new_types = set(new_stats['by_type'].keys())

    type_deltas = {}
    for t in old_types | new_types:
        old_count = old_stats['by_type'].get(t, 0)
        new_count = new_stats['by_type'].get(t, 0)
        if old_count != new_count:
            type_deltas[t] = {
                'old': old_count,
                'new': new_count,
                'delta': new_count - old_count,
            }

    return {
        'delta_total': delta_total,
        'delta_files': delta_files,
        'new_types': sorted(new_types - old_types),
        'removed_types': sorted(old_types - new_types),
        'type_deltas': type_deltas,
        'direction': 'improved' if delta_total < 0 else ('worse' if delta_total > 0 else 'unchanged'),
    }
