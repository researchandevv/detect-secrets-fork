import re
from .base import RegexBasedDetector

class DatabricksTokenDetector(RegexBasedDetector):
    """Scans for Databricks API tokens (dapi*)."""
    secret_type = 'Databricks API Token'
    confidence = 0.90  # dapi prefix is unique to Databricks
    denylist = [
        re.compile(r'dapi[a-f0-9]{30,}'),
    ]
