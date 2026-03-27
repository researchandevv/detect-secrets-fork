"""
Secret Rotation Detection

Compares two baseline files and identifies secrets that were:
- Rotated (same location, different hash -- credential was changed)
- Added (new secret location)
- Removed (secret location no longer present)
- Unchanged (same location, same hash)

This supports rotation compliance auditing: teams can verify that secrets
flagged in a previous scan have been rotated, and that no new secrets appeared.

Comparing two baseline snapshots is analogous to divergence detection: the
location is the key, the secret hash is the value, and a change means the
credential was updated.
"""
import json
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple


def load_baseline(path: str) -> Dict[str, Any]:
    """Load a .secrets.baseline file."""
    with open(path) as f:
        return json.load(f)


def _build_location_index(baseline: Dict[str, Any]) -> Dict[Tuple[str, int, str], str]:
    """Build an index of (filename, line_number, type) -> secret_hash.

    Each unique combination of file + line + detector type identifies a
    secret "slot". The hashed_secret tells us which credential occupies
    that slot.
    """
    index = {}
    results = baseline.get('results', {})
    for filename, secrets in results.items():
        for secret in secrets:
            key = (
                filename,
                secret.get('line_number', 0),
                secret.get('type', 'unknown'),
            )
            index[key] = secret.get('hashed_secret', '')
    return index


def compare_baselines(
    old_path: str,
    new_path: str,
) -> Dict[str, List[Dict[str, Any]]]:
    """Compare two baselines and categorize secret changes.

    Returns a dict with keys:
        rotated: secrets at the same location but with a different hash
        added: secrets in new baseline that aren't in old
        removed: secrets in old baseline that aren't in new
        unchanged: secrets identical in both baselines

    Each entry contains: filename, line_number, type, and for rotated,
    both old_hash and new_hash.
    """
    old_baseline = load_baseline(old_path)
    new_baseline = load_baseline(new_path)

    return compare_baseline_dicts(old_baseline, new_baseline)


def compare_baseline_dicts(
    old_baseline: Dict[str, Any],
    new_baseline: Dict[str, Any],
) -> Dict[str, List[Dict[str, Any]]]:
    """Compare two baseline dicts (already loaded)."""
    old_index = _build_location_index(old_baseline)
    new_index = _build_location_index(new_baseline)

    old_keys = set(old_index.keys())
    new_keys = set(new_index.keys())

    result = {
        'rotated': [],
        'added': [],
        'removed': [],
        'unchanged': [],
    }

    # Keys in both: check if hash changed (rotated) or same (unchanged)
    for key in sorted(old_keys & new_keys):
        filename, line_number, secret_type = key
        entry = {
            'filename': filename,
            'line_number': line_number,
            'type': secret_type,
        }
        if old_index[key] != new_index[key]:
            entry['old_hash'] = old_index[key]
            entry['new_hash'] = new_index[key]
            result['rotated'].append(entry)
        else:
            entry['hash'] = old_index[key]
            result['unchanged'].append(entry)

    # Keys only in new: added
    for key in sorted(new_keys - old_keys):
        filename, line_number, secret_type = key
        result['added'].append({
            'filename': filename,
            'line_number': line_number,
            'type': secret_type,
            'hash': new_index[key],
        })

    # Keys only in old: removed
    for key in sorted(old_keys - new_keys):
        filename, line_number, secret_type = key
        result['removed'].append({
            'filename': filename,
            'line_number': line_number,
            'type': secret_type,
            'hash': old_index[key],
        })

    return result


def rotation_summary(comparison: Dict[str, List[Dict[str, Any]]]) -> str:
    """Human-readable summary of rotation comparison."""
    lines = ['Secret Rotation Report', '=' * 40]

    lines.append(f"\nRotated:   {len(comparison['rotated'])}")
    lines.append(f"Added:     {len(comparison['added'])}")
    lines.append(f"Removed:   {len(comparison['removed'])}")
    lines.append(f"Unchanged: {len(comparison['unchanged'])}")

    total_old = len(comparison['rotated']) + len(comparison['removed']) + len(comparison['unchanged'])
    if total_old > 0:
        rotation_rate = len(comparison['rotated']) / total_old * 100
        lines.append(f"\nRotation rate: {rotation_rate:.1f}% of previous secrets were rotated")

    if comparison['rotated']:
        lines.append('\n--- Rotated Secrets ---')
        for entry in comparison['rotated']:
            lines.append(
                f"  {entry['filename']}:{entry['line_number']} "
                f"({entry['type']})"
            )

    if comparison['added']:
        lines.append('\n--- New Secrets ---')
        for entry in comparison['added']:
            lines.append(
                f"  {entry['filename']}:{entry['line_number']} "
                f"({entry['type']})"
            )

    if comparison['removed']:
        lines.append('\n--- Removed Secrets ---')
        for entry in comparison['removed']:
            lines.append(
                f"  {entry['filename']}:{entry['line_number']} "
                f"({entry['type']})"
            )

    return '\n'.join(lines)


def check_rotation_compliance(
    comparison: Dict[str, List[Dict[str, Any]]],
    expected_rotations: Optional[List[Tuple[str, int]]] = None,
) -> Dict[str, Any]:
    """Check if expected secrets were actually rotated.

    Args:
        comparison: Output from compare_baselines
        expected_rotations: List of (filename, line_number) tuples that
            should have been rotated. If None, checks all unchanged as
            potential compliance gaps.

    Returns:
        Dict with 'compliant' (bool), 'rotated_as_expected', 'not_rotated',
        and 'unexpected_changes'.
    """
    rotated_locations = {
        (e['filename'], e['line_number'])
        for e in comparison['rotated']
    }

    if expected_rotations is None:
        # If no specific expectations, report all unchanged as potential gaps
        return {
            'compliant': len(comparison['unchanged']) == 0,
            'rotated_count': len(comparison['rotated']),
            'unchanged_count': len(comparison['unchanged']),
            'not_rotated': [
                {'filename': e['filename'], 'line_number': e['line_number'], 'type': e['type']}
                for e in comparison['unchanged']
            ],
        }

    rotated_ok = []
    not_rotated = []

    for filename, line_number in expected_rotations:
        if (filename, line_number) in rotated_locations:
            rotated_ok.append((filename, line_number))
        else:
            not_rotated.append((filename, line_number))

    return {
        'compliant': len(not_rotated) == 0,
        'rotated_as_expected': rotated_ok,
        'not_rotated': not_rotated,
        'unexpected_changes': [
            e for e in comparison['rotated']
            if (e['filename'], e['line_number']) not in set(expected_rotations)
        ],
    }
