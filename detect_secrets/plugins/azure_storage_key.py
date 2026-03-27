"""
This plugin searches for Azure Storage Account access keys.
"""
import re

from detect_secrets.plugins.base import RegexBasedDetector


class AzureStorageKeyDetector(RegexBasedDetector):
    """Scans for Azure Storage Account access keys."""
    secret_type = 'Azure Storage Account access key'
    confidence = 0.75  # base64 key after account name pattern; context-dependent

    denylist = [
        # Account Key (AccountKey=xxxxxxxxx)
        re.compile(r'AccountKey=[a-zA-Z0-9+\/=]{88}'),
    ]
