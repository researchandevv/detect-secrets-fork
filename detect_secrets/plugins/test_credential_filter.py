"""NOTE: This is a utility module, not a plugin detector.
It has no BasePlugin subclass and is not loaded by the plugin discovery system."""
import re

KNOWN_FAKE_SECRETS = {
    'AKIAIOSFODNN7EXAMPLE',
    'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
    'sk-ant-api03-example',
    'ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
    'glpat-xxxxxxxxxxxxxxxxxxxx',
}

KNOWN_FAKE_PATTERNS = [
    re.compile(r'(?:example|test|fake|dummy|sample|placeholder)', re.I),
    re.compile(r'your[_\-\s]', re.I),
    re.compile(r'x{8,}'),
    re.compile(r'0{16,}'),
    re.compile(r'(?:1234567890|abcdefgh)', re.I),
    re.compile(r'(?:insert|replace|put)[_\-\s].*(?:here|key|token)', re.I),
]

def is_likely_fake(secret_value: str) -> bool:
    if secret_value in KNOWN_FAKE_SECRETS:
        return True
    for pattern in KNOWN_FAKE_PATTERNS:
        if pattern.search(secret_value):
            return True
    return False
