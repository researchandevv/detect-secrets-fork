import re
from .base import RegexBasedDetector

class FirebaseApiKeyDetector(RegexBasedDetector):
    """Scans for Firebase/Google API keys."""
    secret_type = 'Firebase API Key'
    confidence = 0.75  # AIza prefix is distinctive but keys are often client-side/public
    denylist = [
        re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
    ]
