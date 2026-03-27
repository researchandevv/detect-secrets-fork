"""
Note: This module is an overlay — it is not called by the core scan engine.
Use demo.py or import get_confidence/get_contextual_confidence directly
for confidence-aware output.

NOTE: This is a utility module, not a plugin detector.
It has no BasePlugin subclass and is not loaded by the plugin discovery system.

Confidence scoring for secret detectors.

Confidence scoring system:
- High confidence: pattern is specific, almost always a real secret
- Medium confidence: pattern matches but needs context (like 40-char hex)
- Low confidence: entropy-based, frequently false positive

Scores calibrated from: pattern specificity, known false positive rates, and real-world scan data.

Resolution order (inspired by Avro writer/reader schema resolution):
1. Central DETECTOR_CONFIDENCE dict — explicit calibration overrides
2. Plugin class `confidence` attribute — self-describing plugins
3. Default 0.5 — unknown detector types

This means new plugins can declare `confidence = 0.85` as a class attribute
and it works without editing this file. The central dict remains for
calibration overrides and backward compatibility with the original
detect-secrets plugin interface.

Usage:
    from detect_secrets.plugins.confidence import get_confidence
    score = get_confidence(secret.type)
"""

# Confidence scores per detector type (0.0 = always FP, 1.0 = always real)
# Calibrated from: known pattern specificity + industry FP rates
DETECTOR_CONFIDENCE = {
    # High confidence (>0.8): specific prefixes, almost always real
    'Anthropic API Key': 0.95,           # sk-ant-* prefix is unique
    'GitHub Token': 0.95,                # ghp_/gho_/ghu_ prefixes
    'GitLab Personal Access Token': 0.95, # glpat-* prefix
    'HuggingFace Token': 0.90,           # hf_* prefix
    'Slack Token': 0.90,                 # xoxb-/xoxp-/xoxa- prefixes
    'Stripe Access Key': 0.90,           # sk_live_/rk_live_ prefixes
    'PyPI Token': 0.90,                  # pypi-AgE* prefix
    'Docker Registry Token': 0.90,       # dckr_pat_* prefix
    'HashiCorp Vault Token': 0.90,       # hvs.*/hvb.*/hvr.* prefixes
    'Databricks API Token': 0.90,        # dapi* prefix
    'SendGrid API Key': 0.85,            # SG.* prefix
    'Twilio API Key': 0.85,              # AC/SK patterns
    'Notion Integration Token': 0.85,    # secret_*/ntn_* prefixes
    'Telegram Bot Token': 0.85,          # numeric:alphanumeric format
    'OpenAI Token': 0.85,                # sk-*T3BlbkFJ pattern
    'AWS Access Key': 0.80,              # AKIA* prefix
    'AWS Access Key (Validatable)': 0.85, # Same + can verify
    'AWS Bedrock Key': 0.80,             # ARN format
    'Firebase API Key': 0.75,            # AIza* — also used by other Google services
    'Private Key': 0.95,                 # PEM headers are definitive

    # Medium confidence (0.4-0.8): pattern-based but context-dependent
    'Kubernetes Secret': 0.70,           # JWT in K8s context
    'Terraform Secret': 0.65,            # Hardcoded credentials in HCL
    'Ethereum Private Key': 0.60,        # Hex in key context
    'Cloudflare API Token': 0.60,        # Context-dependent hex
    'Vercel API Token': 0.55,            # Context-dependent
    'Supabase API Key': 0.50,            # JWT or sbp_ prefix
    'Basic Auth Credentials': 0.50,      # URI format
    'Connection String Secret': 0.75,    # DB/service URI with embedded creds
    'JSON Web Token': 0.45,              # eyJ* — many are non-secret
    'NPM tokens': 0.70,                  # npm_* prefix
    'Secret Keyword': 0.40,              # Very context-dependent

    # Low confidence (<0.4): entropy-based, frequent false positives
    'Base64 High Entropy String': 0.20,  # Catches many non-secrets
    'Hex High Entropy String': 0.15,     # Catches UUIDs, hashes, etc.
    'Public IP (ipv4)': 0.10,            # IPs are rarely secrets
}


def get_confidence(secret_type: str) -> float:
    """Get confidence score for a detector type.

    Resolution order:
    1. Central DETECTOR_CONFIDENCE dict (calibration overrides)
    2. Plugin class `confidence` attribute (self-describing plugins)
    3. Default 0.5 (unknown types)
    """
    # 1. Central dict takes precedence (allows calibration overrides)
    if secret_type in DETECTOR_CONFIDENCE:
        return DETECTOR_CONFIDENCE[secret_type]

    # 2. Discover from plugin class attribute
    try:
        from detect_secrets.core.plugins.util import get_mapping_from_secret_type_to_class
        mapping = get_mapping_from_secret_type_to_class()
        plugin_cls = mapping.get(secret_type)
        if plugin_cls and hasattr(plugin_cls, 'confidence'):
            return plugin_cls.confidence
    except (ImportError, Exception):
        pass

    # 3. Default
    return 0.5


def filter_by_confidence(secrets, min_confidence=0.5):
    """Filter secrets to only include those above minimum confidence threshold."""
    return [s for s in secrets if get_confidence(s.type) >= min_confidence]


def sort_by_confidence(secrets):
    """Sort secrets by confidence (highest first)."""
    return sorted(secrets, key=lambda s: get_confidence(s.type), reverse=True)


# Context modifiers: adjust confidence based on file/repo context
CONTEXT_MODIFIERS = {
    # Files that legitimately contain secret-like patterns
    'secret_management': {
        'file_patterns': ['vault', 'secret', 'credential', 'auth', 'token', 'key-management'],
        'modifier': -0.3,  # Reduce confidence by 30% in secret management code
    },
    'test_files': {
        'file_patterns': ['test_', '_test.', 'spec.', 'mock', 'fixture', 'fake', 'stub'],
        'modifier': -0.4,  # Test files often contain intentional secrets
    },
    'config_examples': {
        'file_patterns': ['example', 'sample', 'template', '.example', '.sample', '.template'],
        'modifier': -0.5,  # Example configs almost always have fake secrets
    },
    'documentation': {
        'file_patterns': ['.md', 'README', 'CHANGELOG', 'docs/', 'doc/'],
        'modifier': -0.2,  # Docs may reference secrets but rarely contain real ones
    },
}


def get_contextual_confidence(secret_type: str, filename: str) -> float:
    """Get confidence adjusted by file context. More accurate than type-only scoring."""
    base = get_confidence(secret_type)
    
    filename_lower = filename.lower()
    modifier = 0.0
    
    for context_name, context in CONTEXT_MODIFIERS.items():
        for pattern in context['file_patterns']:
            if pattern in filename_lower:
                modifier = min(modifier, context['modifier'])  # Take strongest modifier
                break
    
    adjusted = max(0.05, base + modifier)  # Never go below 5%
    return round(adjusted, 2)
