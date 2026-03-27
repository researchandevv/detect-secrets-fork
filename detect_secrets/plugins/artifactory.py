import re

from .base import RegexBasedDetector


class ArtifactoryDetector(RegexBasedDetector):
    """Scans for Artifactory credentials."""
    secret_type = 'Artifactory Credentials'
    confidence = 0.70  # AKC/AP[A-Z] prefixes are fairly specific but not unique

    denylist = [
        # Artifactory tokens begin with AKC
        re.compile(r'(?:\s|=|:|"|^)AKC[a-zA-Z0-9]{10,}(?:\s|"|$)'),  # API token
        # Artifactory encrypted passwords begin with AP[A-Z]
        re.compile(r'(?:\s|=|:|"|^)AP[\dABCDEF][a-zA-Z0-9]{8,}(?:\s|"|$)'),  # Password
    ]
