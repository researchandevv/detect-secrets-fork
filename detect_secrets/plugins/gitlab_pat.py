import re
from .base import RegexBasedDetector

class GitLabPatDetector(RegexBasedDetector):
    """Verifiable GitLab token detector.

    Detection patterns for glpat-/gldt-/glrt- are already covered by
    GitLabTokenDetector in gitlab_token.py. This plugin exists solely to
    add verify() capability. Using the same secret_type avoids duplicate
    findings when both plugins are active.
    """
    secret_type = 'GitLab Token'  # Must match gitlab_token.py to avoid duplicates
    confidence = 0.95
    denylist = [
        # Only patterns NOT already in gitlab_token.py go here.
        # Currently gitlab_token.py covers glpat, gldt, glft, glsoat, glrt,
        # glcbt, glimt, glptt, glagent, gloas, and GR1348941 runner tokens.
        # Nothing to add — kept empty so this plugin won't produce its own
        # findings. The verify() method below can be called on GitLab Token
        # findings when wired up by a verification harness.
    ]

    def verify(self, secret: str):
        try:
            from detect_secrets.constants import VerifiedResult
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
