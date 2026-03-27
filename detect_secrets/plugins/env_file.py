"""
Detector for secrets in .env files.

.env files use KEY=VALUE structure where keys often describe the secret's
purpose (e.g., DATABASE_PASSWORD=hunter2). The keyword detector partially
covers this via its denylist regex, but misses structured patterns unique
to .env files: unquoted values, no assignment operators beyond '=', and
the strong contextual signal that .env files are *intended* to hold secrets.

This detector only activates on files named .env, .env.*, or *.env.
"""
import os
import re
from typing import Any
from typing import Generator
from typing import Set

from ..core.potential_secret import PotentialSecret
from .base import BasePlugin
from detect_secrets.util.code_snippet import CodeSnippet


# Sensitive key patterns (case-insensitive)
SENSITIVE_KEY_PATTERNS = re.compile(
    r'(?:^|_)('
    r'PASSWORD|PASSWD|PWD|'
    r'SECRET|SECRET_KEY|'
    r'TOKEN|AUTH_TOKEN|ACCESS_TOKEN|REFRESH_TOKEN|'
    r'API_KEY|APIKEY|API_SECRET|'
    r'PRIVATE_KEY|PRIV_KEY|'
    r'DATABASE_URL|DB_URL|DB_PASSWORD|DB_PASS|'
    r'CONNECTION_STRING|CONN_STR|'
    r'AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|'
    r'ENCRYPTION_KEY|SIGNING_KEY|'
    r'CLIENT_SECRET|APP_SECRET|'
    r'SMTP_PASSWORD|MAIL_PASSWORD|'
    r'REDIS_PASSWORD|REDIS_URL|'
    r'MONGO_URI|MONGODB_URI|'
    r'STRIPE_KEY|STRIPE_SECRET|'
    r'SENDGRID_API_KEY|TWILIO_AUTH_TOKEN|'
    r'SLACK_TOKEN|SLACK_WEBHOOK|'
    r'GITHUB_TOKEN|GITLAB_TOKEN|'
    r'JWT_SECRET|SESSION_SECRET|'
    r'CREDENTIALS|CREDENTIAL'
    r')(?:_|$)',
    re.IGNORECASE,
)

# Placeholder patterns that indicate template/example values, not real secrets
PLACEHOLDER_PATTERNS = re.compile(
    r'^('
    r'\$\{.*\}|'          # ${VAR} shell expansion
    r'\$\w+|'             # $VAR shell variable
    r'<.*>|'              # <placeholder>
    r'\{\{.*\}\}|'        # {{template}}
    r'TODO|FIXME|'        # TODO markers
    r'CHANGEME|CHANGE_ME|'
    r'REPLACE_ME|REPLACEME|'
    r'YOUR_.*_HERE|'      # YOUR_KEY_HERE patterns
    r'xxx+|XXX+|'         # xxx placeholders
    r'dummy|example|'     # obvious fakes
    r'test|fake|mock|'    # test values
    r'placeholder|'
    r'insert.?here|'
    r'fill.?in|'
    r'none|null|'         # null values
    r'true|false'         # boolean values
    r')$',
    re.IGNORECASE,
)

# .env filename patterns
ENV_FILE_PATTERN = re.compile(
    r'(?:^|/)\.env(?:\..+)?$|'   # .env, .env.local, .env.production
    r'(?:^|/)[^/]+\.env$',        # something.env
)

# KEY=VALUE line pattern
KEY_VALUE_PATTERN = re.compile(
    r'^([A-Z][A-Z0-9_]*)\s*=\s*(.*)$',
    re.IGNORECASE,
)


def _is_env_file(filename: str) -> bool:
    """Check if filename matches .env file patterns."""
    basename = os.path.basename(filename)
    # Exact match for .env
    if basename == '.env':
        return True
    # .env.something (e.g., .env.local, .env.production)
    if basename.startswith('.env.'):
        return True
    # something.env (e.g., production.env)
    if basename.endswith('.env') and not basename.startswith('.'):
        return True
    return False


def _strip_quotes(value: str) -> str:
    """Remove surrounding quotes from a value."""
    if len(value) >= 2:
        if (value[0] == '"' and value[-1] == '"') or \
           (value[0] == "'" and value[-1] == "'"):
            return value[1:-1]
    return value


def _is_placeholder(value: str) -> bool:
    """Check if a value looks like a template placeholder, not a real secret."""
    return bool(PLACEHOLDER_PATTERNS.match(value))


class EnvFileSecretDetector(BasePlugin):
    """
    Scans .env files for secrets in KEY=VALUE format.

    Only activates on files named .env, .env.*, or *.env.
    Matches lines where the key contains sensitive words and the value
    is not empty, not a comment, and not a template placeholder.
    """
    secret_type = 'Environment Variable Secret'
    confidence = 0.70

    def analyze_string(self, string: str) -> Generator[str, None, None]:
        """Analyze a single KEY=VALUE line for secrets.

        This is called by analyze_line after the filename check passes.
        """
        line = string.strip()

        # Skip empty lines and comments
        if not line or line.startswith('#'):
            return

        # Match KEY=VALUE
        match = KEY_VALUE_PATTERN.match(line)
        if not match:
            return

        key = match.group(1)
        raw_value = match.group(2).strip()

        # Strip inline comments (but not inside quotes)
        value = _strip_quotes(raw_value)

        # Skip empty values
        if not value or not value.strip():
            return

        # Skip placeholder/template values
        if _is_placeholder(value):
            return

        # Check if the key matches sensitive patterns
        if SENSITIVE_KEY_PATTERNS.search(key):
            yield value

    def analyze_line(
        self,
        filename: str,
        line: str,
        line_number: int = 0,
        context: CodeSnippet = None,
        **kwargs: Any,
    ) -> Set[PotentialSecret]:
        """Only analyze lines from .env files."""
        if not _is_env_file(filename):
            return set()

        return super().analyze_line(
            filename=filename,
            line=line,
            line_number=line_number,
            context=context,
            **kwargs,
        )
