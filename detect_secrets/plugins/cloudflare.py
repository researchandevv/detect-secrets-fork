import re
from .base import RegexBasedDetector

class CloudflareApiTokenDetector(RegexBasedDetector):
    """Scans for Cloudflare API tokens and Global API keys."""
    secret_type = 'Cloudflare API Token'
    confidence = 0.60  # hex tokens lack a unique prefix; context-dependent matching
    denylist = [
        # Cloudflare API Tokens (v4 format)
        re.compile(r'(?:cloudflare|cf|CF)[_\-]?(?:api[_\-]?)?(?:token|key)["\s:=]+[A-Za-z0-9_\-]{40}'),
        # Bearer token pattern near cloudflare context
        re.compile(r'[a-f0-9]{37}(?:[a-f0-9]{3})'),
    ]
