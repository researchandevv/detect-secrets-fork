import re
from .base import RegexBasedDetector

class HuggingFaceTokenDetector(RegexBasedDetector):
    """Scans for HuggingFace user and API tokens."""
    secret_type = 'HuggingFace Token'
    confidence = 0.90  # hf_ prefix is highly specific to HuggingFace
    denylist = [
        re.compile(r'hf_[A-Za-z0-9]{32,}'),
        re.compile(r'api_org_[A-Za-z0-9]{40,}'),
    ]

    def verify(self, secret: str):
        try:
            from detect_secrets.core.constants import VerifiedResult
            import requests
            resp = requests.get(
                'https://huggingface.co/api/whoami-v2',
                headers={'Authorization': f'Bearer {secret}'},
                timeout=5
            )
            if resp.status_code == 200:
                return VerifiedResult.VERIFIED_TRUE
            elif resp.status_code == 401:
                return VerifiedResult.VERIFIED_FALSE
            return VerifiedResult.UNVERIFIED
        except Exception:
            return VerifiedResult.UNVERIFIED
