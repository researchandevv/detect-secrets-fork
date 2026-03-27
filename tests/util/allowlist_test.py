import json
import os
import tempfile

import pytest

from detect_secrets.util.allowlist import (
    add_to_allowlist,
    remove_from_allowlist,
    list_allowlisted,
    verify_allowlist_entries_still_exist,
    prune_stale_entries,
    save_baseline,
    load_baseline,
    _get_allowlisted_hashes,
)


def _write_baseline(tmpdir, results, filename='.secrets.baseline'):
    baseline = {
        'version': '1.5.0',
        'plugins_used': [],
        'results': results,
    }
    path = os.path.join(tmpdir, filename)
    with open(path, 'w') as f:
        json.dump(baseline, f)
    return path


class TestAddToAllowlist:

    def test_add_marks_is_secret_false(self, tmp_path):
        path = _write_baseline(str(tmp_path), {
            'test.py': [{
                'type': 'Secret Keyword',
                'hashed_secret': 'abc123',
                'line_number': 5,
            }],
        })
        result = add_to_allowlist(path, 'abc123')
        assert result['modified_count'] == 1

        # Verify the file was updated
        with open(path) as f:
            updated = json.load(f)
        assert updated['results']['test.py'][0]['is_secret'] is False

    def test_add_scoped_to_file(self, tmp_path):
        path = _write_baseline(str(tmp_path), {
            'a.py': [{'type': 'SK', 'hashed_secret': 'abc123', 'line_number': 1}],
            'b.py': [{'type': 'SK', 'hashed_secret': 'abc123', 'line_number': 1}],
        })
        result = add_to_allowlist(path, 'abc123', filename='a.py')
        assert result['modified_count'] == 1
        assert result['entries'][0]['filename'] == 'a.py'

    def test_already_allowlisted_not_modified(self, tmp_path):
        path = _write_baseline(str(tmp_path), {
            'test.py': [{
                'type': 'SK',
                'hashed_secret': 'abc123',
                'line_number': 5,
                'is_secret': False,
            }],
        })
        result = add_to_allowlist(path, 'abc123')
        assert result['modified_count'] == 0


class TestRemoveFromAllowlist:

    def test_remove_deletes_is_secret_key(self, tmp_path):
        path = _write_baseline(str(tmp_path), {
            'test.py': [{
                'type': 'SK',
                'hashed_secret': 'abc123',
                'line_number': 5,
                'is_secret': False,
            }],
        })
        result = remove_from_allowlist(path, 'abc123')
        assert result['modified_count'] == 1

        with open(path) as f:
            updated = json.load(f)
        assert 'is_secret' not in updated['results']['test.py'][0]


class TestListAllowlisted:

    def test_lists_only_allowlisted(self, tmp_path):
        path = _write_baseline(str(tmp_path), {
            'a.py': [
                {'type': 'SK', 'hashed_secret': 'h1', 'line_number': 1, 'is_secret': False},
                {'type': 'SK', 'hashed_secret': 'h2', 'line_number': 2},
            ],
            'b.py': [
                {'type': 'SK', 'hashed_secret': 'h3', 'line_number': 1, 'is_secret': False},
            ],
        })
        entries = list_allowlisted(path)
        assert len(entries) == 2
        hashes = {e['hashed_secret'] for e in entries}
        assert hashes == {'h1', 'h3'}


class TestVerifyAllowlistEntries:

    def test_valid_entries(self, tmp_path):
        # Create a real file that matches
        test_file = tmp_path / 'test.py'
        test_file.write_text('line1\nline2\nline3\n')

        path = _write_baseline(str(tmp_path), {
            'test.py': [{
                'type': 'SK',
                'hashed_secret': 'abc',
                'line_number': 2,
                'is_secret': False,
            }],
        })
        result = verify_allowlist_entries_still_exist(path, repo_root=str(tmp_path))
        assert len(result['valid']) == 1
        assert len(result['stale']) == 0

    def test_stale_file_not_found(self, tmp_path):
        path = _write_baseline(str(tmp_path), {
            'deleted.py': [{
                'type': 'SK',
                'hashed_secret': 'abc',
                'line_number': 1,
                'is_secret': False,
            }],
        })
        result = verify_allowlist_entries_still_exist(path, repo_root=str(tmp_path))
        assert len(result['stale']) == 1
        assert result['stale'][0]['reason'] == 'file_not_found'

    def test_stale_line_out_of_range(self, tmp_path):
        test_file = tmp_path / 'short.py'
        test_file.write_text('only one line\n')

        path = _write_baseline(str(tmp_path), {
            'short.py': [{
                'type': 'SK',
                'hashed_secret': 'abc',
                'line_number': 999,
                'is_secret': False,
            }],
        })
        result = verify_allowlist_entries_still_exist(path, repo_root=str(tmp_path))
        assert len(result['stale']) == 1
        assert result['stale'][0]['reason'] == 'line_out_of_range'


class TestPruneStaleEntries:
    """Tests for prune_stale_entries — previously untested."""

    def test_prune_removes_stale_entries_from_baseline(self, tmp_path):
        """Stale entries (file deleted) should be removed from baseline."""
        path = _write_baseline(str(tmp_path), {
            'deleted.py': [{
                'type': 'SK',
                'hashed_secret': 'abc',
                'line_number': 1,
                'is_secret': False,
            }],
        })
        result = prune_stale_entries(path, repo_root=str(tmp_path))
        assert result['pruned_count'] == 1
        # Verify the baseline was actually modified
        updated = load_baseline(path)
        assert 'deleted.py' not in updated['results']

    def test_prune_no_stale_returns_zero(self, tmp_path):
        """When all entries are valid, pruned_count should be 0."""
        test_file = tmp_path / 'real.py'
        test_file.write_text('line1\nline2\n')
        path = _write_baseline(str(tmp_path), {
            'real.py': [{
                'type': 'SK',
                'hashed_secret': 'abc',
                'line_number': 1,
                'is_secret': False,
            }],
        })
        result = prune_stale_entries(path, repo_root=str(tmp_path))
        assert result['pruned_count'] == 0

    def test_prune_keeps_non_allowlisted_entries(self, tmp_path):
        """Pruning should only remove allowlisted (is_secret=False) stale entries."""
        path = _write_baseline(str(tmp_path), {
            'deleted.py': [
                {'type': 'SK', 'hashed_secret': 'allow', 'line_number': 1, 'is_secret': False},
                {'type': 'SK', 'hashed_secret': 'unreviewed', 'line_number': 2},
            ],
        })
        result = prune_stale_entries(path, repo_root=str(tmp_path))
        assert result['pruned_count'] == 1
        updated = load_baseline(path)
        # The unreviewed entry should still exist
        assert len(updated['results']['deleted.py']) == 1
        assert updated['results']['deleted.py'][0]['hashed_secret'] == 'unreviewed'

    def test_prune_line_out_of_range(self, tmp_path):
        """Entries with line_number beyond file length should be pruned."""
        test_file = tmp_path / 'short.py'
        test_file.write_text('one line\n')
        path = _write_baseline(str(tmp_path), {
            'short.py': [{
                'type': 'SK',
                'hashed_secret': 'abc',
                'line_number': 999,
                'is_secret': False,
            }],
        })
        result = prune_stale_entries(path, repo_root=str(tmp_path))
        assert result['pruned_count'] == 1


class TestGetAllowlistedHashes:
    """Tests for _get_allowlisted_hashes helper — previously untested."""

    def test_returns_only_allowlisted(self):
        baseline = {
            'results': {
                'a.py': [
                    {'hashed_secret': 'h1', 'is_secret': False},
                    {'hashed_secret': 'h2', 'is_secret': True},
                    {'hashed_secret': 'h3'},
                ],
            },
        }
        hashes = _get_allowlisted_hashes(baseline)
        assert hashes == {'h1'}

    def test_empty_results(self):
        hashes = _get_allowlisted_hashes({'results': {}})
        assert hashes == set()

    def test_no_results_key(self):
        hashes = _get_allowlisted_hashes({})
        assert hashes == set()


class TestRemoveFromAllowlistExtended:
    """Extended tests for remove_from_allowlist."""

    def test_remove_scoped_to_file(self, tmp_path):
        """Removing with filename scope should only affect that file."""
        path = _write_baseline(str(tmp_path), {
            'a.py': [{'type': 'SK', 'hashed_secret': 'abc', 'line_number': 1, 'is_secret': False}],
            'b.py': [{'type': 'SK', 'hashed_secret': 'abc', 'line_number': 1, 'is_secret': False}],
        })
        result = remove_from_allowlist(path, 'abc', filename='a.py')
        assert result['modified_count'] == 1
        updated = load_baseline(path)
        assert 'is_secret' not in updated['results']['a.py'][0]
        assert updated['results']['b.py'][0]['is_secret'] is False

    def test_remove_nonexistent_hash(self, tmp_path):
        """Removing a hash that doesn't exist should modify nothing."""
        path = _write_baseline(str(tmp_path), {
            'a.py': [{'type': 'SK', 'hashed_secret': 'abc', 'line_number': 1, 'is_secret': False}],
        })
        result = remove_from_allowlist(path, 'nonexistent')
        assert result['modified_count'] == 0


class TestAddToAllowlistLineScoping:
    """Test add_to_allowlist with line_number scoping (previously untested)."""

    def test_add_scoped_to_line_number(self, tmp_path):
        """Allowlisting scoped to file+line should only affect that entry."""
        path = _write_baseline(str(tmp_path), {
            'test.py': [
                {'type': 'SK', 'hashed_secret': 'abc123', 'line_number': 5},
                {'type': 'SK', 'hashed_secret': 'abc123', 'line_number': 10},
            ],
        })
        result = add_to_allowlist(path, 'abc123', filename='test.py', line_number=5)
        assert result['modified_count'] == 1
        updated = load_baseline(path)
        assert updated['results']['test.py'][0]['is_secret'] is False
        assert 'is_secret' not in updated['results']['test.py'][1]

    def test_add_nonexistent_hash_modifies_nothing(self, tmp_path):
        """Adding a hash that doesn't exist should not modify the file."""
        path = _write_baseline(str(tmp_path), {
            'test.py': [{'type': 'SK', 'hashed_secret': 'abc', 'line_number': 1}],
        })
        result = add_to_allowlist(path, 'nonexistent')
        assert result['modified_count'] == 0
        assert result['entries'] == []

    def test_add_across_multiple_files(self, tmp_path):
        """Same hash in multiple files without file scope should allowlist all."""
        path = _write_baseline(str(tmp_path), {
            'a.py': [{'type': 'SK', 'hashed_secret': 'shared', 'line_number': 1}],
            'b.py': [{'type': 'SK', 'hashed_secret': 'shared', 'line_number': 2}],
            'c.py': [{'type': 'SK', 'hashed_secret': 'other', 'line_number': 3}],
        })
        result = add_to_allowlist(path, 'shared')
        assert result['modified_count'] == 2


class TestVerifyAllowlistEdgeCases:
    """Edge cases for verify_allowlist_entries_still_exist."""

    def test_default_repo_root_from_baseline_dir(self, tmp_path):
        """When repo_root is None, it should default to the baseline's directory."""
        test_file = tmp_path / 'code.py'
        test_file.write_text('line1\nline2\n')
        path = _write_baseline(str(tmp_path), {
            'code.py': [{
                'type': 'SK',
                'hashed_secret': 'abc',
                'line_number': 1,
                'is_secret': False,
            }],
        })
        result = verify_allowlist_entries_still_exist(path)  # no repo_root
        assert len(result['valid']) == 1
        assert len(result['stale']) == 0

    def test_line_number_zero_or_none_is_valid(self, tmp_path):
        """Entry with line_number=0 or missing should not be flagged stale."""
        test_file = tmp_path / 'code.py'
        test_file.write_text('one line\n')
        path = _write_baseline(str(tmp_path), {
            'code.py': [{
                'type': 'SK',
                'hashed_secret': 'abc',
                'line_number': 0,
                'is_secret': False,
            }],
        })
        result = verify_allowlist_entries_still_exist(path, repo_root=str(tmp_path))
        # line_number 0 is falsy, so the "line > line_count" check should not trigger
        assert len(result['valid']) == 1


class TestSaveBaseline:
    """Tests for save_baseline formatting."""

    def test_save_creates_valid_json(self, tmp_path):
        path = str(tmp_path / 'test.baseline')
        baseline = {'version': '1.5.0', 'results': {}}
        save_baseline(path, baseline)
        loaded = load_baseline(path)
        assert loaded['version'] == '1.5.0'

    def test_save_ends_with_newline(self, tmp_path):
        path = str(tmp_path / 'test.baseline')
        save_baseline(path, {'version': '1.0', 'results': {}})
        with open(path) as f:
            content = f.read()
        assert content.endswith('\n')
