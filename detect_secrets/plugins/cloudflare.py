import re
from .base import RegexBasedDetector

class CloudflareApiTokenDetector(RegexBasedDetector):
    """Scans for Cloudflare API tokens and Global API keys."""
    secret_type = 'Cloudflare API Token'
    confidence = 0.60  # hex tokens lack a unique prefix; context-dependent matching
    denylist = [
        # Cloudflare API Tokens (v4 format) — require cloudflare-related keyword context
        re.compile(
            r'(?:CF_API_TOKEN|CLOUDFLARE_API_TOKEN|cloudflare[_\s]*(?:api[_\s]*)?token)'
            r'\s*[=:]\s*["\']?([a-f0-9]{40})["\']?',
            re.IGNORECASE,
        ),
        # Cloudflare Global API Key — also requires context
        re.compile(
            r'(?:CF_API_KEY|CLOUDFLARE_API_KEY|cloudflare[_\s]*(?:api[_\s]*)?key)'
            r'\s*[=:]\s*["\']?([a-f0-9]{37,40})["\']?',
            re.IGNORECASE,
        ),
    ]
