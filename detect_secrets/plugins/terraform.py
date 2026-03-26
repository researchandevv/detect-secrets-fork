import re
from .base import RegexBasedDetector

class TerraformSecretDetector(RegexBasedDetector):
    """Scans for secrets in Terraform/OpenTofu configurations."""
    secret_type = 'Terraform Secret'
    confidence = 0.65  # TFE_TOKEN env var is specific; HCL credential patterns have FP risk
    denylist = [
        # Terraform Cloud API tokens
        re.compile(r'(?:TFE_TOKEN|TF_TOKEN_[a-z]+)\s*=\s*["\']?([A-Za-z0-9\.\-_]{40,})'),
        # Hardcoded credentials in provider blocks
        re.compile(r'(?:access_key|secret_key|password|api_key)\s*=\s*"(?!var\.|local\.|data\.)[^"]{8,}"'),
    ]
