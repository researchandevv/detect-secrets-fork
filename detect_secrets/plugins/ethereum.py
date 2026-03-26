import re
from .base import RegexBasedDetector

class EthereumPrivateKeyDetector(RegexBasedDetector):
    """Scans for Ethereum/EVM private keys (hex format)."""
    secret_type = 'Ethereum Private Key'
    confidence = 0.60  # 64-char hex is common in non-secret contexts; needs keyword context
    denylist = [
        re.compile(r'(?:private[_\s]*key|secret)[_\s]*[=:]\s*["\']?(?:0x)?[a-fA-F0-9]{64}["\']?', re.IGNORECASE),
    ]
