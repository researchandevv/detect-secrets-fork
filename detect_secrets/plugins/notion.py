import re
from .base import RegexBasedDetector

class NotionTokenDetector(RegexBasedDetector):
    """Scans for Notion integration tokens."""
    secret_type = 'Notion Integration Token'
    confidence = 0.85  # secret_ and ntn_ prefixes are strong but not fully unique
    denylist = [
        # secret_ tokens are fixed-length: exactly 43 alphanumeric chars after prefix
        # (50 total). This is Notion's current/legacy integration token format.
        re.compile(r'secret_[A-Za-z0-9]{43}(?![A-Za-z0-9])'),
        # ntn_ is Notion's newer token format. Length is not yet confirmed to be
        # fixed, so we use {40,} as a minimum floor rather than an exact count.
        re.compile(r'ntn_[A-Za-z0-9]{40,}'),
    ]
