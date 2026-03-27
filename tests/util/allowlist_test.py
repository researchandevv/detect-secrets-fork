import json
import os
import tempfile

import pytest

from detect_secrets.util.allowlist import (
    add_to_allowlist,
    remove_from_allowlist,
    list_allowlisted,
    verify_allowlist_entries_still_exist,
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
