"""Multi-provider credential concentration detector.

Not a plugin — an analysis overlay. Identifies files containing secrets
from 3+ different detector types, which indicates a higher probability
of real credential exposure (supply chain attack pattern).

NOTE: This is a utility module, not a plugin detector.
It has no BasePlugin subclass and is not loaded by the plugin discovery system.

Rationale: supply chain attacks embed credentials for MULTIPLE services in
a single file (e.g., a poisoned requirements installer that exfiltrates keys
for Anthropic, OpenAI, AWS, HuggingFace simultaneously). Legitimate code
rarely hardcodes keys for 3+ providers in the same file. When a scan finds
multi-provider concentration, the probability that ALL matches are false
positives is multiplicative — P(all FP) = P(FP_1) * P(FP_2) * ... * P(FP_n),
which drops fast.

Usage:
    from detect_secrets.plugins.multi_provider import find_concentrated_files

    # scan_results: dict mapping filename -> list of secret dicts with 'type' key
    hits = find_concentrated_files(scan_results)
    for hit in hits:
        print(f"{hit['file']}: {hit['distinct_types']} types, score={hit['score']:.2f}")

See also: confidence.py for per-secret scoring, calibrate.py for TP rate calibration.
"""
from __future__ import annotations

from .confidence import get_confidence


# Provider groups — secrets in these categories indicate the credential belongs
# to a specific ecosystem. A file touching multiple ecosystems is suspicious.
AI_PROVIDER_TYPES: set[str] = {
    'Anthropic API Key',
    'OpenAI Token',
    'HuggingFace Token',
    'AWS Bedrock Key',
    'Databricks API Token',
}

CLOUD_PROVIDER_TYPES: set[str] = {
    'AWS Access Key',
    'Cloudflare API Token',
    'Vercel API Token',
    'Firebase API Key',
    'Supabase API Key',
    'Azure Storage Account access key',
}

CI_CD_TYPES: set[str] = {
    'GitHub Token',
    'GitLab Personal Access Token',
    'NPM tokens',
    'PyPI Token',
    'Docker Registry Token',
}

COMMS_TYPES: set[str] = {
    'Slack Token',
    'Telegram Bot Token',
    'SendGrid API Key',
    'Twilio API Key',
    'Mailchimp Access Key',
    'Discord Bot Token',
}

# All categorized types for quick lookup
ALL_CATEGORIZED: set[str] = AI_PROVIDER_TYPES | CLOUD_PROVIDER_TYPES | CI_CD_TYPES | COMMS_TYPES

# Minimum distinct detector types in one file to flag as concentrated
CONCENTRATION_THRESHOLD: int = 3


def find_concentrated_files(scan_results: dict, threshold: int = CONCENTRATION_THRESHOLD) -> list[dict]:
    """Given scan results (filename -> [secrets]), find files with 3+ distinct types.

    Args:
        scan_results: dict mapping filename to list of secret dicts.
            Each secret dict must have a 'type' key (the detector type string).
        threshold: minimum distinct detector types to flag (default 3).

    Returns:
        List of dicts sorted by score descending:
        [
            {
                'file': str,
                'distinct_types': int,
                'types': set of type strings,
                'categories': set of category names hit,
                'score': float,
                'count': int (total secrets in file),
            },
            ...
        ]
    """
    concentrated = []

    for filename, secrets in scan_results.items():
        types_in_file = set()
        for secret in secrets:
            secret_type = secret.get('type') if isinstance(secret, dict) else getattr(secret, 'type', None)
            if secret_type:
                types_in_file.add(secret_type)

        if len(types_in_file) >= threshold:
            score = calculate_concentration_score(types_in_file)
            categories = _categorize(types_in_file)
            concentrated.append({
                'file': filename,
                'distinct_types': len(types_in_file),
                'types': types_in_file,
                'categories': categories,
                'score': score,
                'count': len(secrets),
            })

    concentrated.sort(key=lambda x: x['score'], reverse=True)
    return concentrated


def calculate_concentration_score(types_in_file: set[str]) -> float:
    """Higher score = more likely real credentials (not FPs).

    Score components:
    1. Multiplicative FP improbability: product of (1 - P(FP)) for each type.
       More types with high individual confidence = higher combined confidence.
    2. Category diversity bonus: hitting multiple provider categories (AI, cloud,
       CI/CD, comms) increases suspicion — supply chain attacks cast wide nets.
    3. Count bonus: more types = exponentially less likely to be all false positives.

    Returns a score in [0.0, 1.0] where 1.0 = near-certain real credentials.
    """
    if not types_in_file:
        return 0.0

    # Component 1: multiplicative FP improbability
    # P(all FP) = product of (1 - confidence) for each type
    # Score contribution = 1 - P(all FP)
    fp_product = 1.0
    for secret_type in types_in_file:
        confidence = get_confidence(secret_type)
        fp_product *= (1.0 - confidence)
    improbability = 1.0 - fp_product

    # Component 2: category diversity
    categories = _categorize(types_in_file)
    category_count = len(categories)
    # 1 category = no bonus, 2 = +0.05, 3 = +0.10, 4 = +0.15
    diversity_bonus = max(0, (category_count - 1)) * 0.05

    # Combine: improbability is the base, diversity is additive
    score = min(1.0, improbability + diversity_bonus)
    return round(score, 4)


def _categorize(types: set[str]) -> set[str]:
    """Return which provider categories are represented."""
    categories = set()
    if types & AI_PROVIDER_TYPES:
        categories.add('ai_provider')
    if types & CLOUD_PROVIDER_TYPES:
        categories.add('cloud_provider')
    if types & CI_CD_TYPES:
        categories.add('ci_cd')
    if types & COMMS_TYPES:
        categories.add('comms')
    # Types not in any category don't contribute to diversity
    return categories


def format_report(concentrated_files: list[dict]) -> str:
    """Format concentrated file findings as a readable report."""
    if not concentrated_files:
        return "No multi-provider credential concentration detected."

    lines = [
        f"Multi-provider credential concentration: {len(concentrated_files)} file(s)",
        "=" * 60,
    ]
    for hit in concentrated_files:
        lines.append(f"\n  {hit['file']}")
        lines.append(f"    Score: {hit['score']:.2f} | {hit['distinct_types']} types | {hit['count']} secrets")
        if hit['categories']:
            lines.append(f"    Categories: {', '.join(sorted(hit['categories']))}")
        lines.append(f"    Types: {', '.join(sorted(hit['types']))}")

    return '\n'.join(lines)
