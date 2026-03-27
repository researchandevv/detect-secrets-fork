"""Tests for baseline migration (DDIA Ch4 schema evolution).

Tests the inversion statement: if migration preserves zero audit labels,
then it's no better than regenerating a fresh baseline.
"""

import json
import os
import tempfile
from unittest.mock import patch

import pytest

from detect_secrets.util.baseline_migrate import migrate_baseline
from detect_secrets.util.baseline_migrate import migrate_baseline_dict


# Fake plugin manifest for testing — simulates a detector with 3 plugins
FAKE_CURRENT_PLUGINS = [
    {'name': 'HighEntropyString', 'secret_type': 'High Entropy String'},
    {'name': 'PrivateKeyDetector', 'secret_type': 'Private Key'},
    {'name': 'AnthropicKeyDetector', 'secret_type': 'Anthropic API Key'},
]

FAKE_CURRENT_STAMP = {
    'version': '2.0.0',
    'plugins': FAKE_CURRENT_PLUGINS,
    'plugin_count': 3,
    'stamp_time': '2026-01-01T00:00:00Z',
}


def _make_baseline(
    secrets_by_file,
    version='1.0.0',
    plugins_used=None,
    generated_by=None,
):
    """Build a baseline dict for testing."""
    baseline = {
        'version': version,
        'plugins_used': plugins_used or [],
        'filters_used': [],
        'results': secrets_by_file,
    }
    if generated_by is not None:
        baseline['generated_by'] = generated_by
    return baseline


def _make_secret(secret_type, is_secret=None, line_number=1):
    """Build a secret entry."""
    entry = {
        'type': secret_type,
        'filename': 'test.py',
        'hashed_secret': 'abc123',
        'is_verified': False,
        'line_number': line_number,
    }
    if is_secret is not None:
        entry['is_secret'] = is_secret
    return entry


class TestMigrateBaselineDict:
    """Test in-memory migration (no file I/O)."""

    @patch('detect_secrets.util.baseline_migrate.get_current_stamp')
    def test_preserves_labels_on_unchanged_types(self, mock_stamp):
        """Audit labels on types that still exist must survive migration."""
        mock_stamp.return_value = FAKE_CURRENT_STAMP

        baseline = _make_baseline({
            'test.py': [
                _make_secret('High Entropy String', is_secret=True),
                _make_secret('Private Key', is_secret=False),
            ],
        })

        migrated, report = migrate_baseline_dict(baseline)

        # Both secrets should survive with labels intact
        assert len(migrated['results']['test.py']) == 2
        assert migrated['results']['test.py'][0]['is_secret'] is True
        assert migrated['results']['test.py'][1]['is_secret'] is False
        assert report['preserved_labels'] == 2
        assert report['lost_labels'] == 0

    @patch('detect_secrets.util.baseline_migrate.get_current_stamp')
    def test_renames_carry_labels_forward(self, mock_stamp):
        """Renamed types must preserve audit labels via type_renames mapping."""
        mock_stamp.return_value = FAKE_CURRENT_STAMP

        baseline = _make_baseline({
            'config.yml': [
                _make_secret('Old Anthropic Key', is_secret=True),
            ],
        })

        type_renames = {'Old Anthropic Key': 'Anthropic API Key'}
        migrated, report = migrate_baseline_dict(baseline, type_renames=type_renames)

        # Secret should exist with new type and preserved label
        secrets = migrated['results']['config.yml']
        assert len(secrets) == 1
        assert secrets[0]['type'] == 'Anthropic API Key'
        assert secrets[0]['is_secret'] is True
        assert report['renamed_count'] == 1
        assert report['preserved_labels'] == 1
        assert report['type_renames_applied'] == {'Old Anthropic Key': 'Anthropic API Key'}

    @patch('detect_secrets.util.baseline_migrate.get_current_stamp')
    def test_removes_entries_for_dead_plugins(self, mock_stamp):
        """Entries for plugins that no longer exist should be removed."""
        mock_stamp.return_value = FAKE_CURRENT_STAMP

        baseline = _make_baseline({
            'app.py': [
                _make_secret('High Entropy String', is_secret=True),
                _make_secret('Defunct Scanner Type', is_secret=False),
            ],
        })

        migrated, report = migrate_baseline_dict(baseline)

        secrets = migrated['results']['app.py']
        assert len(secrets) == 1
        assert secrets[0]['type'] == 'High Entropy String'
        assert report['removed_count'] == 1
        assert report['lost_labels'] == 1
        assert report['preserved_labels'] == 1

    @patch('detect_secrets.util.baseline_migrate.get_current_stamp')
    def test_removes_file_entry_when_all_secrets_removed(self, mock_stamp):
        """If all secrets in a file are from dead plugins, remove the file entry."""
        mock_stamp.return_value = FAKE_CURRENT_STAMP

        baseline = _make_baseline({
            'dead.py': [
                _make_secret('Gone Type A'),
                _make_secret('Gone Type B'),
            ],
            'alive.py': [
                _make_secret('Private Key', is_secret=True),
            ],
        })

        migrated, report = migrate_baseline_dict(baseline)

        assert 'dead.py' not in migrated['results']
        assert 'alive.py' in migrated['results']
        assert report['removed_count'] == 2

    @patch('detect_secrets.util.baseline_migrate.get_current_stamp')
    def test_updates_plugins_used(self, mock_stamp):
        """plugins_used should reflect the current detector's plugin set."""
        mock_stamp.return_value = FAKE_CURRENT_STAMP

        baseline = _make_baseline(
            {'test.py': [_make_secret('Private Key')]},
            plugins_used=[{'name': 'OldPlugin'}],
        )

        migrated, report = migrate_baseline_dict(baseline)

        plugin_names = [p['name'] for p in migrated['plugins_used']]
        assert 'HighEntropyString' in plugin_names
        assert 'PrivateKeyDetector' in plugin_names
        assert 'AnthropicKeyDetector' in plugin_names
        assert 'OldPlugin' not in plugin_names

    @patch('detect_secrets.util.baseline_migrate.get_current_stamp')
    def test_no_migration_when_types_match(self, mock_stamp):
        """If all types are current, report migrated=False."""
        mock_stamp.return_value = FAKE_CURRENT_STAMP

        baseline = _make_baseline({
            'test.py': [
                _make_secret('High Entropy String'),
                _make_secret('Private Key'),
            ],
        })

        migrated, report = migrate_baseline_dict(baseline)

        assert report['migrated'] is False
        assert report['renamed_count'] == 0
        assert report['removed_count'] == 0

    @patch('detect_secrets.util.baseline_migrate.get_current_stamp')
    def test_mixed_scenario(self, mock_stamp):
        """Combined rename + remove + keep in a single migration."""
        mock_stamp.return_value = FAKE_CURRENT_STAMP

        baseline = _make_baseline({
            'mixed.py': [
                _make_secret('High Entropy String', is_secret=True),   # keep
                _make_secret('Old Anthropic Key', is_secret=True),     # rename
                _make_secret('Deleted Scanner', is_secret=False),      # remove
                _make_secret('Private Key'),                           # keep (no label)
            ],
        })

        type_renames = {'Old Anthropic Key': 'Anthropic API Key'}
        migrated, report = migrate_baseline_dict(baseline, type_renames=type_renames)

        secrets = migrated['results']['mixed.py']
        types = [s['type'] for s in secrets]
        assert 'High Entropy String' in types
        assert 'Anthropic API Key' in types
        assert 'Private Key' in types
        assert 'Deleted Scanner' not in types

        assert report['renamed_count'] == 1
        assert report['removed_count'] == 1
        assert report['preserved_labels'] == 2  # HES(true) + renamed(true)
        assert report['lost_labels'] == 1       # Deleted(false)


class TestMigrateBaselineFile:
    """Test file-based migration with atomic write."""

    @patch('detect_secrets.util.baseline_migrate.get_current_stamp')
    @patch('detect_secrets.util.baseline_migrate.check_baseline_compat')
    def test_dry_run_does_not_write(self, mock_compat, mock_stamp, tmp_path):
        """dry_run=True should not modify the file."""
        mock_stamp.return_value = FAKE_CURRENT_STAMP
        mock_compat.return_value = {
            'compatible': False,
            'added_plugins': ['AnthropicKeyDetector'],
            'removed_plugins': [],
        }

        baseline = _make_baseline({
            'test.py': [_make_secret('Defunct Type', is_secret=True)],
        })
        path = str(tmp_path / '.secrets.baseline')
        with open(path, 'w') as f:
            json.dump(baseline, f)

        report = migrate_baseline(path, dry_run=True)

        assert report['dry_run'] is True
        assert report['migrated'] is True

        # File should be unchanged
        with open(path) as f:
            on_disk = json.load(f)
        assert 'migration_history' not in on_disk

    @patch('detect_secrets.util.baseline_migrate.get_current_stamp')
    @patch('detect_secrets.util.baseline_migrate.check_baseline_compat')
    def test_writes_migration_history(self, mock_compat, mock_stamp, tmp_path):
        """Migration should append to migration_history."""
        mock_stamp.return_value = FAKE_CURRENT_STAMP
        mock_compat.return_value = {
            'compatible': False,
            'added_plugins': ['AnthropicKeyDetector'],
            'removed_plugins': ['OldDetector'],
        }

        baseline = _make_baseline(
            {'test.py': [_make_secret('High Entropy String')]},
            generated_by={'version': '1.0.0', 'plugins': []},
        )
        path = str(tmp_path / '.secrets.baseline')
        with open(path, 'w') as f:
            json.dump(baseline, f)

        report = migrate_baseline(path)

        with open(path) as f:
            migrated = json.load(f)

        assert 'migration_history' in migrated
        assert len(migrated['migration_history']) == 1
        history = migrated['migration_history'][0]
        assert history['from_version'] == '1.0.0'
        assert history['to_version'] == '2.0.0'

    @patch('detect_secrets.util.baseline_migrate.get_current_stamp')
    @patch('detect_secrets.util.baseline_migrate.check_baseline_compat')
    def test_already_compatible_skips(self, mock_compat, mock_stamp, tmp_path):
        """Compatible baseline should return migrated=False."""
        mock_stamp.return_value = FAKE_CURRENT_STAMP
        mock_compat.return_value = {
            'compatible': True,
        }

        baseline = _make_baseline({'test.py': [_make_secret('Private Key')]})
        path = str(tmp_path / '.secrets.baseline')
        with open(path, 'w') as f:
            json.dump(baseline, f)

        report = migrate_baseline(path)

        assert report['migrated'] is False
        assert report['note'] == 'Baseline is already compatible. No migration needed.'
