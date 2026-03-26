import re
from .base import RegexBasedDetector

class AWSBedrockDetector(RegexBasedDetector):
    """Scans for AWS Bedrock inference profile ARNs and model access keys."""
    secret_type = 'AWS Bedrock Key'
    confidence = 0.80  # ARN patterns are structural but config key matches need context
    denylist = [
        # Bedrock model invocation ARNs with embedded credentials
        re.compile(r'arn:aws:bedrock:[a-z0-9\-]+:\d{12}:(?:inference-profile|provisioned-model)/[A-Za-z0-9\-]+'),
        # Bedrock API keys in config files
        re.compile(r'(?:bedrock|BEDROCK)[_\-]?(?:api[_\-]?)?(?:key|KEY)\s*[=:]\s*["\']?[A-Za-z0-9/+=]{20,}'),
    ]
