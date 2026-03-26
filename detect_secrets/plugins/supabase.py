import re
from .base import RegexBasedDetector

class SupabaseKeyDetector(RegexBasedDetector):
    """Scans for Supabase API keys and service role keys."""
    secret_type = 'Supabase API Key'
    confidence = 0.50  # JWT anon keys are often public; sbp_ prefix helps but FP-prone
    denylist = [
        re.compile(r'sbp_[a-f0-9]{40}'),
        re.compile(r'(?:supabase|SUPABASE)[_\s]*(?:key|KEY|anon|service)[_\s]*[=:]\s*["\']?eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+'),
    ]
