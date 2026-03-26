import re
from .base import RegexBasedDetector

class VercelTokenDetector(RegexBasedDetector):
    """Scans for Vercel API tokens."""
    secret_type = 'Vercel API Token'
    confidence = 0.55  # no distinctive prefix; relies on env var naming context
    denylist = [
        re.compile(r'(?:vercel|VERCEL)[_\s]*(?:token|TOKEN|api|API)[_\s]*[=:]\s*["\']?([A-Za-z0-9]{24,})'),
    ]
