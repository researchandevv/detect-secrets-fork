"""Lightweight git history secret scanner.

Scans git log --diff-filter=D (deleted files) and git log -p (patches)
for secrets that were committed then removed. Uses existing detect-secrets
plugins -- no separate regex engine.

This is a utility module, not a core scanner component.
"""
import re
import subprocess
from typing import Dict
from typing import List


def _git(repo_path: str, *args: str) -> str:
    """Run a git command in the given repo and return stdout."""
    result = subprocess.run(
        ['git', '-C', repo_path] + list(args),
        capture_output=True,
        text=True,
        timeout=60,
    )
    result.check_returncode()
    return result.stdout


def _scan_content(lines: List[str], filename: str) -> List[Dict]:
    """Scan lines through all active detect-secrets plugins.

    Uses the public scan_line API for each line, which initializes
    plugins and filters automatically.

    Returns list of dicts with secret_type, line_number, line_content.
    """
    from ..core.scan import scan_line

    findings = []
    for line_number, line in enumerate(lines, start=1):
        for secret in scan_line(line):
            findings.append({
                'secret_type': secret.type,
                'line_number': line_number,
                'line_content': line.rstrip(),
            })
    return findings


def scan_deleted_files(repo_path: str, max_commits: int = 100) -> List[Dict]:
    """Find secrets in files that were deleted from the repo.

    Walks the git log for commits that deleted files, retrieves the file
    content at the parent commit, and scans it through active plugins.

    Returns:
        [{'commit': str, 'filename': str, 'secret_type': str,
          'line_number': int, 'line_content': str}]
    """
    raw = _git(
        repo_path,
        'log', '--diff-filter=D', '--name-only',
        '--pretty=format:%H', '-n', str(max_commits),
    )

    findings = []
    current_commit = None

    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        if re.match(r'^[0-9a-f]{40}$', line):
            current_commit = line
            continue
        if current_commit is None:
            continue

        filename = line
        try:
            content = _git(repo_path, 'show', '{}~1:{}'.format(current_commit, filename))
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            # File might not exist in parent (added and deleted in same commit)
            continue

        for hit in _scan_content(content.splitlines(), filename):
            findings.append({
                'commit': current_commit,
                'filename': filename,
                'secret_type': hit['secret_type'],
                'line_number': hit['line_number'],
                'line_content': hit['line_content'],
            })

    return findings


def scan_recent_patches(repo_path: str, max_commits: int = 50) -> List[Dict]:
    """Scan recent git patches for secrets in added lines.

    Uses git log -p to get unified diffs, then feeds them through
    detect-secrets' scan_diff which already handles unified diff parsing
    and plugin invocation.

    Falls back to manual parsing if unidiff is not installed.

    Returns:
        [{'commit': str, 'filename': str, 'secret_type': str,
          'line_content': str}]
    """
    findings = []

    # Get list of commits first
    commit_log = _git(
        repo_path,
        'log', '--pretty=format:%H', '-n', str(max_commits),
    )
    commits = [c.strip() for c in commit_log.splitlines() if c.strip()]

    for commit in commits:
        try:
            diff = _git(repo_path, 'diff-tree', '-p', commit)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            continue

        if not diff.strip():
            continue

        # Try using the built-in scan_diff (requires unidiff)
        try:
            from ..core.scan import scan_diff
            for secret in scan_diff(diff):
                findings.append({
                    'commit': commit,
                    'filename': secret.filename,
                    'secret_type': secret.type,
                    'line_content': '',
                })
        except ImportError:
            # unidiff not installed -- fall back to manual added-line parsing
            current_file = None
            added_lines = []

            for line in diff.splitlines():
                m = re.match(r'^diff --git a/.+ b/(.+)$', line)
                if m:
                    # Flush previous file
                    if current_file and added_lines:
                        for hit in _scan_content(added_lines, current_file):
                            findings.append({
                                'commit': commit,
                                'filename': current_file,
                                'secret_type': hit['secret_type'],
                                'line_content': hit['line_content'],
                            })
                    current_file = m.group(1)
                    added_lines = []
                    continue

                if line.startswith('+') and not line.startswith('+++'):
                    added_lines.append(line[1:])

            # Flush last file
            if current_file and added_lines:
                for hit in _scan_content(added_lines, current_file):
                    findings.append({
                        'commit': commit,
                        'filename': current_file,
                        'secret_type': hit['secret_type'],
                        'line_content': hit['line_content'],
                    })

    return findings


def format_history_report(findings: List[Dict]) -> str:
    """Format git history findings as a human-readable report.

    Groups findings by commit for readability.
    """
    if not findings:
        return 'No secrets found in git history.'

    lines = ['Found {} potential secret(s) in git history:\n'.format(len(findings))]

    by_commit = {}  # type: Dict[str, List[Dict]]
    for f in findings:
        short = f['commit'][:8]
        by_commit.setdefault(short, []).append(f)

    for commit, hits in by_commit.items():
        lines.append('Commit {}:'.format(commit))
        for hit in hits:
            filename = hit.get('filename', 'unknown')
            secret_type = hit.get('secret_type', 'unknown')
            line_content = hit.get('line_content', '')
            if len(line_content) > 80:
                line_content = line_content[:77] + '...'
            line_num = hit.get('line_number', '')
            loc = ':{}'.format(line_num) if line_num else ''
            lines.append('  {}{} [{}] {}'.format(filename, loc, secret_type, line_content))
        lines.append('')

    return '\n'.join(lines)
