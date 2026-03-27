from __future__ import annotations

import re
from typing import Generator

from .base import RegexBasedDetector


# Placeholder patterns that indicate template variables, not real credentials
_PLACEHOLDER_RE = re.compile(
    r'^(?:'
    r'<[^>]+>'          # <password>, <your-password>
    r'|\$\{[^}]+\}'    # ${PASSWORD}, ${DB_PASS}
    r'|\$\w+'          # $PASSWORD
    r'|\{\{[^}]+\}\}'  # {{password}}
    r'|%[sd]'          # %s, %d (Python/Go format strings)
    r'|\{[0-9]*\}'     # {0}, {} (Python .format())
    r'|x{3,}'          # xxxx placeholder
    r'|\*{3,}'         # **** placeholder
    r'|password'       # literal word "password"
    r'|changeme'       # common placeholder
    r'|fixme'          # fix-later placeholder
    r'|todo'           # incomplete placeholder
    r'|insert_\w*'     # INSERT_YOUR_PASSWORD etc.
    r'|replace_\w*'    # REPLACE_WITH_REAL etc.
    r'|your_\w*'       # your_password, your_api_key etc.
    r'|example\w*'     # example, examplepassword etc.
    r'|secret'         # common placeholder
    r')$',
    re.IGNORECASE,
)


class ConnectionStringDetector(RegexBasedDetector):
    """Detects database and service connection strings with embedded credentials.

    Catches URI-style connection strings like:
        postgresql://admin:SecretPass123@db.example.com:5432/prod
        mongodb+srv://user:p4$$w0rd@cluster.mongodb.net/db
        redis://default:mypass@redis.cloud:6380

    Filters out template placeholders (${VAR}, <password>, %s, etc.).
    """

    secret_type: str = 'Connection String Secret'
    confidence: float = 0.75

    denylist: list[re.Pattern[str]] = [
        # Database/service URIs with embedded credentials
        # Capture group 1 = the password portion for secret extraction
        re.compile(
            r'(?:mongodb(?:\+srv)?|mysql|postgresql|postgres|redis|amqp|amqps|mssql)'
            r'://[^:\s/]+:([^\s@]+)@[^\s]+',
        ),
    ]

    def analyze_string(self, string: str, **kwargs: object) -> Generator[str, None, None]:
        for match in super().analyze_string(string, **kwargs):
            # Filter out placeholder/template passwords
            if _PLACEHOLDER_RE.match(match):
                continue
            # Filter out empty passwords
            if not match or match.strip() == '':
                continue
            yield match
