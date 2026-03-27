import re
from .base import RegexBasedDetector

class SupabaseKeyDetector(RegexBasedDetector):
    """Scans for Supabase API keys and service role keys.

    Note on false positives: Supabase anon keys (eyJ... JWT format) are
    intentionally public and embedded in client-side code by design. They
    are scoped to row-level security and are expected false positives.
    This detector exists primarily for service_role keys and sbp_ tokens,
    which ARE secrets and must never be exposed in client code.
    """
    secret_type = 'Supabase API Key'
    confidence = 0.50  # JWT anon keys are often public; sbp_ prefix helps but FP-prone
    denylist = [
        re.compile(r'sbp_[a-f0-9]{40}'),
        re.compile(r'(?:supabase|SUPABASE)[_\s]*(?:key|KEY|anon|service)[_\s]*[=:]\s*["\']?eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+'),
    ]
