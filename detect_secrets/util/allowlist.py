"""
Allowlist Management Utility

Manages .secrets.baseline allowlists programmatically:
- Add/remove secrets from the allowlist by hash
- List all currently allowlisted entries
- Verify that allowlisted entries still exist in the codebase
- Prune stale allowlist entries

Allowlisting is explicit human judgment persisted as machine-readable state.
The verify_allowlist_entries_still_exist function handles re-validation when
code changes -- previously dismissed findings need re-checking because
allowlist entries may reference code that has been refactored, making the
allowlist stale and potentially hiding new secrets at the same location.
"""
import json
import os
from typing import Any, Dict, List, Optional, Set


def load_baseline(path: str) -> Dict[str, Any]:
    """Load a .secrets.baseline file."""
    with open(path) as f:
        return json.load(f)


def save_baseline(path: str, baseline: Dict[str, Any]) -> None:
    """Save a .secrets.baseline file with consistent formatting."""
    with open(path, 'w') as f:
        json.dump(baseline, f, indent=4)
        f.write('\n')


def _get_allowlisted_hashes(baseline: Dict[str, Any]) -> Set[str]:
    """Extract all hashes that are marked as allowlisted (is_secret=false)."""
    hashes = set()
    for filename, secrets in baseline.get('results', {}).items():
        for secret in secrets:
            if secret.get('is_secret') is False:
                hashes.add(secret.get('hashed_secret', ''))
    return hashes


def add_to_allowlist(
    baseline_path: str,
    secret_hash: str,
    filename: Optional[str] = None,
    line_number: Optional[int] = None,
) -> Dict[str, Any]:
    """Mark a secret as allowlisted (is_secret=false) in the baseline.

    Args:
        baseline_path: Path to .secrets.baseline
        secret_hash: The hashed_secret value to allowlist
        filename: If provided, only allowlist in this specific file
        line_number: If provided with filename, only allowlist at this line

    Returns:
        Dict with 'modified_count' and 'entries' showing what was changed
    """
    baseline = load_baseline(baseline_path)
    modified = []

    for fname, secrets in baseline.get('results', {}).items():
        if filename and fname != filename:
            continue
        for secret in secrets:
            if secret.get('hashed_secret') != secret_hash:
                continue
            if line_number is not None and secret.get('line_number') != line_number:
                continue
            if secret.get('is_secret') is not False:
                secret['is_secret'] = False
                modified.append({
                    'filename': fname,
                    'line_number': secret.get('line_number'),
                    'type': secret.get('type'),
                })

    if modified:
        save_baseline(baseline_path, baseline)

    return {
        'modified_count': len(modified),
        'entries': modified,
    }


def remove_from_allowlist(
    baseline_path: str,
    secret_hash: str,
    filename: Optional[str] = None,
) -> Dict[str, Any]:
    """Remove allowlist status (set is_secret back to null/unreviewed).

    Args:
        baseline_path: Path to .secrets.baseline
        secret_hash: The hashed_secret value to un-allowlist
        filename: If provided, only modify in this specific file

    Returns:
        Dict with 'modified_count' and 'entries'
    """
    baseline = load_baseline(baseline_path)
    modified = []

    for fname, secrets in baseline.get('results', {}).items():
        if filename and fname != filename:
            continue
        for secret in secrets:
            if secret.get('hashed_secret') != secret_hash:
                continue
            if secret.get('is_secret') is False:
                # Remove the is_secret key entirely to return to unreviewed state
                del secret['is_secret']
                modified.append({
                    'filename': fname,
                    'line_number': secret.get('line_number'),
                    'type': secret.get('type'),
                })

    if modified:
        save_baseline(baseline_path, baseline)

    return {
        'modified_count': len(modified),
        'entries': modified,
    }


def list_allowlisted(baseline_path: str) -> List[Dict[str, Any]]:
    """List all allowlisted entries in the baseline.

    Returns a list of dicts with: filename, line_number, type, hashed_secret
    """
    baseline = load_baseline(baseline_path)
    entries = []

    for filename, secrets in sorted(baseline.get('results', {}).items()):
        for secret in secrets:
            if secret.get('is_secret') is False:
                entries.append({
                    'filename': filename,
                    'line_number': secret.get('line_number'),
                    'type': secret.get('type'),
                    'hashed_secret': secret.get('hashed_secret'),
                })

    return entries


def verify_allowlist_entries_still_exist(
    baseline_path: str,
    repo_root: Optional[str] = None,
) -> Dict[str, List[Dict[str, Any]]]:
    """Check if allowlisted entries still exist in the codebase.

    For each allowlisted secret, verify the file still exists and the
    line number is within range. This catches stale allowlist entries
    left behind after refactoring.

    Args:
        baseline_path: Path to .secrets.baseline
        repo_root: Root directory for resolving relative file paths.
            Defaults to the directory containing the baseline file.

    Returns:
        Dict with 'valid' (entries that still exist) and 'stale'
        (entries where the file or line no longer exists)
    """
    if repo_root is None:
        repo_root = os.path.dirname(os.path.abspath(baseline_path))

    allowlisted = list_allowlisted(baseline_path)
    valid = []
    stale = []

    for entry in allowlisted:
        filepath = os.path.join(repo_root, entry['filename'])

        if not os.path.isfile(filepath):
            entry['reason'] = 'file_not_found'
            stale.append(entry)
            continue

        try:
            with open(filepath) as f:
                line_count = sum(1 for _ in f)
        except (OSError, UnicodeDecodeError):
            entry['reason'] = 'file_unreadable'
            stale.append(entry)
            continue

        if entry['line_number'] and entry['line_number'] > line_count:
            entry['reason'] = 'line_out_of_range'
            stale.append(entry)
            continue

        valid.append(entry)

    return {
        'valid': valid,
        'stale': stale,
        'total_allowlisted': len(allowlisted),
        'stale_count': len(stale),
    }


def prune_stale_entries(
    baseline_path: str,
    repo_root: Optional[str] = None,
) -> Dict[str, Any]:
    """Remove stale allowlist entries from the baseline.

    Combines verify + remove: finds entries where the code no longer
    exists and removes them from the baseline entirely.

    Returns:
        Dict with 'pruned_count' and 'pruned_entries'
    """
    verification = verify_allowlist_entries_still_exist(baseline_path, repo_root)

    if not verification['stale']:
        return {'pruned_count': 0, 'pruned_entries': []}

    baseline = load_baseline(baseline_path)
    pruned = []

    for stale_entry in verification['stale']:
        fname = stale_entry['filename']
        if fname not in baseline.get('results', {}):
            continue

        secrets = baseline['results'][fname]
        original_len = len(secrets)
        baseline['results'][fname] = [
            s for s in secrets
            if not (
                s.get('hashed_secret') == stale_entry['hashed_secret']
                and s.get('is_secret') is False
            )
        ]

        if len(baseline['results'][fname]) < original_len:
            pruned.append(stale_entry)

        # Remove empty file entries
        if not baseline['results'][fname]:
            del baseline['results'][fname]

    if pruned:
        save_baseline(baseline_path, baseline)

    return {
        'pruned_count': len(pruned),
        'pruned_entries': pruned,
    }
