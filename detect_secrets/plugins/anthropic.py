import re
from .base import RegexBasedDetector

class AnthropicApiKeyDetector(RegexBasedDetector):
    """Scans for Anthropic API keys (sk-ant-*)."""
    secret_type = 'Anthropic API Key'
    confidence = 0.95  # sk-ant-* prefix is unique to Anthropic
    denylist = [
        re.compile(r'sk-ant-[A-Za-z0-9_\-]{20,}'),
    ]

    def verify(self, secret: str):
        try:
            from detect_secrets.constants import VerifiedResult
            import requests
            resp = requests.get(
                'https://api.anthropic.com/v1/models',
                headers={'x-api-key': secret, 'anthropic-version': '2023-06-01'},
                timeout=5
            )
            if resp.status_code == 200:
                return VerifiedResult.VERIFIED_TRUE
            elif resp.status_code == 401:
                return VerifiedResult.VERIFIED_FALSE
            return VerifiedResult.UNVERIFIED
        except Exception:
            return VerifiedResult.UNVERIFIED
