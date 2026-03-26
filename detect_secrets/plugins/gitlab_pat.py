import re
from .base import RegexBasedDetector

class GitLabPatDetector(RegexBasedDetector):
    """Scans for GitLab Personal Access Tokens (glpat-*)."""
    secret_type = 'GitLab Personal Access Token'
    confidence = 0.95  # glpat-/gldt-/glrt- prefixes are unique to GitLab
    denylist = [
        re.compile(r'glpat-[A-Za-z0-9_\-]{20,}'),
        re.compile(r'gldt-[A-Za-z0-9_\-]{20,}'),
        re.compile(r'glrt-[A-Za-z0-9_\-]{20,}'),
    ]

    def verify(self, secret: str):
        try:
            from detect_secrets.core.constants import VerifiedResult
            import requests
            resp = requests.get(
                'https://gitlab.com/api/v4/user',
                headers={'PRIVATE-TOKEN': secret},
                timeout=5
            )
            if resp.status_code == 200:
                return VerifiedResult.VERIFIED_TRUE
            elif resp.status_code == 401:
                return VerifiedResult.VERIFIED_FALSE
            return VerifiedResult.UNVERIFIED
        except Exception:
            return VerifiedResult.UNVERIFIED
