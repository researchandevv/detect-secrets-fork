"""Baseline migration — DDIA Ch4 schema evolution for secret baselines.

When detect-secrets is upgraded (new plugins added, plugins removed, or
secret types renamed), existing .secrets.baseline files become stale.
baseline_stamp.py can *diagnose* incompatibility; this module *resolves* it.

Design principle (DDIA Ch4 "data outlives code"):
  Human audit labor (is_secret markings) is the most expensive data in a
  baseline. A migration must preserve every audit label that still applies.
  Like Avro's writer-reader schema resolution:
  - New fields (new plugins) get defaults (null / unreviewed)
  - Removed fields (removed plugins) are dropped from results
  - Renamed fields (type renames) carry labels forward via a mapping

The type_renames dict serves as the "schema registry" — it maps old
secret_type strings to their current equivalents so audit labels survive
plugin refactors.
"""

import copy
import json
import os
import time
from typing import Any
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple

from .baseline_stamp import check_baseline_compat
from .baseline_stamp import get_current_stamp


# Known type renames across versions.  When a plugin's `secret_type` property
# changes (e.g., refactoring "Vault Token" → "HashiCorp Vault Token"), add
# the mapping here so migrate_baseline() can carry forward audit labels.
#
# Format: {'old_type_string': 'new_type_string'}
DEFAULT_TYPE_RENAMES: Dict[str, str] = {
    # Example: 'Vault Token': 'HashiCorp Vault Token',
}


def migrate_baseline(
    baseline_path: str,
    type_renames: Optional[Dict[str, str]] = None,
    dry_run: bool = False,
) -> Dict[str, Any]:
    """Migrate a baseline file to be compatible with the current detector.

    Applies three evolution rules (DDIA Ch4 writer-reader resolution):
      1. RENAME: Remap secret types per type_renames mapping.  Audit labels
         (is_secret) are preserved on renamed entries.
      2. REMOVE: Drop result entries whose secret type belongs to a plugin
         that no longer exists (and is not in the rename map).
      3. ADD: Update plugins_used to reflect the current plugin set.
         New plugins don't inject phantom results — they'll be found on
         the next scan.

    Args:
        baseline_path: Path to .secrets.baseline file.
        type_renames: Optional override for DEFAULT_TYPE_RENAMES.
        dry_run: If True, compute migration plan without writing.

    Returns:
        Migration report dict with:
          - migrated: bool (True if changes were applied or would be)
          - renamed_count: number of secret entries with remapped types
          - removed_count: number of secret entries removed (dead plugins)
          - preserved_labels: number of is_secret labels that survived
          - lost_labels: number of is_secret labels on removed entries
          - plugins_added: list of new plugin names
          - plugins_removed: list of removed plugin names
          - type_renames_applied: dict of {old_type: new_type} actually used
          - dry_run: whether this was a dry run
    """
    if type_renames is None:
        type_renames = DEFAULT_TYPE_RENAMES

    with open(baseline_path) as f:
        baseline = json.load(f)

    # Get compatibility info
    compat = check_baseline_compat(baseline_path)

    if compat['compatible']:
        return {
            'migrated': False,
            'renamed_count': 0,
            'removed_count': 0,
            'preserved_labels': 0,
            'lost_labels': 0,
            'plugins_added': [],
            'plugins_removed': [],
            'type_renames_applied': {},
            'dry_run': dry_run,
            'note': 'Baseline is already compatible. No migration needed.',
        }

    # Build the set of currently valid secret types
    current_stamp = get_current_stamp()
    current_types = {p['secret_type'] for p in current_stamp['plugins']}

    # Build reverse map: plugin_name -> secret_type for current plugins
    current_name_to_type = {
        p['name']: p['secret_type'] for p in current_stamp['plugins']
    }

    # Tracking counters
    renamed_count = 0
    removed_count = 0
    preserved_labels = 0
    lost_labels = 0
    renames_applied: Dict[str, str] = {}

    # Deep copy results for mutation
    migrated_baseline = copy.deepcopy(baseline)
    results = migrated_baseline.get('results', {})
    new_results: Dict[str, List[Dict[str, Any]]] = {}

    for filename, secrets in results.items():
        migrated_secrets = []
        for secret in secrets:
            old_type = secret.get('type', '')
            has_label = secret.get('is_secret') is not None

            # Rule 1: RENAME — check if this type was renamed
            if old_type in type_renames:
                new_type = type_renames[old_type]
                if new_type in current_types:
                    secret['type'] = new_type
                    renamed_count += 1
                    renames_applied[old_type] = new_type
                    if has_label:
                        preserved_labels += 1
                    migrated_secrets.append(secret)
                    continue

            # Rule 2: Check if type still exists in current plugins
            if old_type in current_types:
                # Type is still valid — keep as-is
                if has_label:
                    preserved_labels += 1
                migrated_secrets.append(secret)
                continue

            # Type not in current plugins and not in rename map — REMOVE
            removed_count += 1
            if has_label:
                lost_labels += 1

        if migrated_secrets:
            new_results[filename] = migrated_secrets

    migrated_baseline['results'] = new_results

    # Rule 3: ADD — update plugins_used to reflect current configuration
    migrated_baseline['plugins_used'] = [
        {'name': p['name']} for p in current_stamp['plugins']
    ]

    # Record migration metadata
    migration_record = {
        'migrated_at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'from_version': baseline.get('generated_by', {}).get('version', 'unknown'),
        'to_version': current_stamp['version'],
        'renamed_types': renames_applied,
        'removed_types_count': removed_count,
        'preserved_labels': preserved_labels,
        'lost_labels': lost_labels,
    }
    migrated_baseline.setdefault('migration_history', []).append(migration_record)

    report = {
        'migrated': True,
        'renamed_count': renamed_count,
        'removed_count': removed_count,
        'preserved_labels': preserved_labels,
        'lost_labels': lost_labels,
        'plugins_added': compat.get('added_plugins', []),
        'plugins_removed': compat.get('removed_plugins', []),
        'type_renames_applied': renames_applied,
        'dry_run': dry_run,
    }

    if not dry_run:
        # Atomic write (same pattern as baseline_stamp.py)
        tmp_path = baseline_path + '.tmp'
        with open(tmp_path, 'w') as f:
            f.write(json.dumps(migrated_baseline, indent=2) + '\n')
        os.rename(tmp_path, baseline_path)

    return report


def migrate_baseline_dict(
    baseline: Dict[str, Any],
    type_renames: Optional[Dict[str, str]] = None,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Migrate an in-memory baseline dict (no file I/O).

    Useful for testing and for pipelines that already have the baseline loaded.

    Returns:
        (migrated_baseline, report)
    """
    if type_renames is None:
        type_renames = DEFAULT_TYPE_RENAMES

    current_stamp = get_current_stamp()
    current_types = {p['secret_type'] for p in current_stamp['plugins']}

    renamed_count = 0
    removed_count = 0
    preserved_labels = 0
    lost_labels = 0
    renames_applied: Dict[str, str] = {}

    migrated = copy.deepcopy(baseline)
    results = migrated.get('results', {})
    new_results: Dict[str, List[Dict[str, Any]]] = {}

    for filename, secrets in results.items():
        migrated_secrets = []
        for secret in secrets:
            old_type = secret.get('type', '')
            has_label = secret.get('is_secret') is not None

            if old_type in type_renames:
                new_type = type_renames[old_type]
                if new_type in current_types:
                    secret['type'] = new_type
                    renamed_count += 1
                    renames_applied[old_type] = new_type
                    if has_label:
                        preserved_labels += 1
                    migrated_secrets.append(secret)
                    continue

            if old_type in current_types:
                if has_label:
                    preserved_labels += 1
                migrated_secrets.append(secret)
                continue

            removed_count += 1
            if has_label:
                lost_labels += 1

        if migrated_secrets:
            new_results[filename] = migrated_secrets

    migrated['results'] = new_results
    migrated['plugins_used'] = [
        {'name': p['name']} for p in current_stamp['plugins']
    ]

    report = {
        'migrated': renamed_count > 0 or removed_count > 0,
        'renamed_count': renamed_count,
        'removed_count': removed_count,
        'preserved_labels': preserved_labels,
        'lost_labels': lost_labels,
        'type_renames_applied': renames_applied,
    }

    return migrated, report
