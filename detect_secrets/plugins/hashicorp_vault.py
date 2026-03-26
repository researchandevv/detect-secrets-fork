import re
from .base import RegexBasedDetector

class HashiCorpVaultTokenDetector(RegexBasedDetector):
    """Scans for HashiCorp Vault tokens (hvs.*, hvb.*, hvr.*)."""
    secret_type = 'HashiCorp Vault Token'
    confidence = 0.90  # hvs./hvb./hvr. prefixes are unique to Vault
    denylist = [
        re.compile(r'hvs\.[A-Za-z0-9_\-]{24,}'),   # Service tokens (modern)
        re.compile(r'hvb\.[A-Za-z0-9_\-]{24,}'),   # Batch tokens (modern)
        re.compile(r'hvr\.[A-Za-z0-9_\-]{24,}'),   # Recovery tokens (modern)
        # Legacy format: s. followed by exactly alphanumeric (NOT camelCase method names)
        re.compile(r'(?<![a-z])s\.[A-Z][A-Za-z0-9]{23}'),  # Must start with uppercase after s.
    ]
