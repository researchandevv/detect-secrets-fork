import re
from .base import RegexBasedDetector

class NotionTokenDetector(RegexBasedDetector):
    """Scans for Notion integration tokens."""
    secret_type = 'Notion Integration Token'
    confidence = 0.85  # secret_ and ntn_ prefixes are strong but not fully unique
    denylist = [
        re.compile(r'secret_[A-Za-z0-9]{40,}'),
        re.compile(r'ntn_[A-Za-z0-9]{40,}'),
    ]
