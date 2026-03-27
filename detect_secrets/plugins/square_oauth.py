import re

from .base import RegexBasedDetector


class SquareOAuthDetector(RegexBasedDetector):
    """Scans for Square OAuth Secrets"""
    secret_type = 'Square OAuth Secret'
    confidence = 0.85  # sq0atp-/sq0csp- prefixes are unique to Square

    denylist = [
        re.compile(r'sq0csp-[0-9A-Za-z\\\-_]{43}'),
    ]
