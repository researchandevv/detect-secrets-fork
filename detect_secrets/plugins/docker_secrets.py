import re
from .base import RegexBasedDetector

class DockerRegistryTokenDetector(RegexBasedDetector):
    """Scans for Docker registry authentication tokens and passwords."""
    secret_type = 'Docker Registry Token'
    confidence = 0.90  # dckr_pat_ prefix is unique; config auth pattern is structural
    denylist = [
        # Docker Hub tokens
        re.compile(r'dckr_pat_[A-Za-z0-9_\-]{20,}'),
        # Docker config auth (base64 encoded user:pass)
        re.compile(r'"auth"\s*:\s*"[A-Za-z0-9+/=]{20,}"'),
        # Docker login password in scripts
        re.compile(r'docker\s+login\s+.*?(?:-p|--password)\s+["\']?([^\s"\']+)'),
    ]
