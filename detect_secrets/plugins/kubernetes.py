import re
from .base import RegexBasedDetector

class KubernetesSecretDetector(RegexBasedDetector):
    """Scans for Kubernetes service account tokens and secrets in manifests."""
    secret_type = 'Kubernetes Secret'
    confidence = 0.70  # JWT tokens in kubeconfig are strong; base64 manifest matches are noisy
    denylist = [
        # K8s service account tokens (JWT format in kubeconfig)
        re.compile(r'token:\s+eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+'),
        # Base64 encoded secrets in K8s manifests
        re.compile(r'(?:password|token|key|secret):\s+(?!true|false|null)[A-Za-z0-9+/]{40,}={0,2}'),
    ]
