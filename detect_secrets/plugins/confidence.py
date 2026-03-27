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

See also: multi_provider.py for file-level concentration analysis — when a single
file contains secrets from 3+ different providers, the combined false positive
probability drops multiplicatively, making the finding high-priority.
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
    'AWS Bedrock Key': 0.80,             # ARN format
    'Firebase API Key': 0.75,            # AIza* — also used by other Google services
    'Private Key': 0.95,                 # PEM headers are definitive
    'CI/CD Hardcoded Secret': 0.85,      # Hardcoded tokens in workflow files
    'Package Registry Token': 0.80,      # Cargo/NuGet/RubyGems/Go registry tokens

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
    'Environment Variable Secret': 0.70,  # .env context is strong signal

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
    'generated_code': {
        'file_patterns': ['.generated.', '.auto.', '_generated', 'generated_', 'autogen'],
        'modifier': -0.7,  # Generated code contains machine-produced patterns, not real secrets
    },
    'minified': {
        'file_patterns': ['.min.js', '.min.css', '.bundle.js', '.chunk.js'],
        'modifier': -0.8,  # Minified assets: high-entropy tokens are variable names, not secrets
    },
    'lock_files': {
        'file_patterns': ['package-lock.json', 'yarn.lock', 'Gemfile.lock', 'poetry.lock',
                          'Pipfile.lock', 'composer.lock', 'Cargo.lock', 'pnpm-lock.yaml'],
        'modifier': -0.9,  # Lock files contain integrity hashes, never real secrets
    },
    'vendor': {
        'file_patterns': ['vendor/', 'node_modules/', 'third_party/', '.yarn/'],
        'modifier': -0.6,  # Third-party code: secrets belong to the dependency, not the project
    },
}


# Rapid-dismiss patterns: near-zero true positive probability.
# Files matching these patterns should be skipped entirely — investigating them
# has negative expected value (time cost > 0, information gain ~ 0).
RAPID_DISMISS_PATTERNS = [
    'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml',
    '.min.js', '.min.css', '.bundle.js',
    'node_modules/', '.yarn/', 'vendor/bundle/',
]


def should_rapid_dismiss(filename: str) -> bool:
    """True if file context has near-zero probability of real secrets.

    These are files where secret-like patterns are structural artifacts
    (integrity hashes, minified variable names, vendored code) rather
    than leaked credentials.
    """
    fl = filename.lower()
    return any(p in fl for p in RAPID_DISMISS_PATTERNS)


def verify_plugin_uniqueness() -> list:
    """Check for duplicate secret_types across all registered plugins.

    From Ch9 total order broadcast: plugin discovery must be deterministic.
    If two plugins declare the same secret_type, the one that wins depends on
    filesystem import order, which varies across OS and Python version.

    Returns a list of conflict dicts, each with 'secret_type' and 'classes'
    (the class names that share it).  Empty list means no conflicts.
    """
    try:
        from detect_secrets.core.plugins.util import get_mapping_from_secret_type_to_class
    except ImportError:
        return [{'error': 'Could not import plugin discovery'}]

    # get_mapping_from_secret_type_to_class returns one class per type (last
    # wins).  To detect collisions we need to scan all plugin classes directly.
    from detect_secrets.core.plugins import initialize as _init
    from detect_secrets.core.plugins.util import import_plugins
    import_plugins()

    from detect_secrets.plugins.base import BasePlugin
    seen: dict = {}  # secret_type -> [class_name, ...]
    for cls in BasePlugin.__subclasses__():
        st = getattr(cls, 'secret_type', None)
        if st is None:
            continue
        seen.setdefault(st, []).append(cls.__name__)

    conflicts = []
    for secret_type, classes in sorted(seen.items()):
        if len(classes) > 1:
            conflicts.append({
                'secret_type': secret_type,
                'classes': sorted(classes),
            })
    return conflicts


def get_contextual_confidence(secret_type: str, filename: str) -> float:
    """Get confidence adjusted by file context. More accurate than type-only scoring."""
    base = get_confidence(secret_type)
    
    filename_lower = filename.lower()
    modifier = 0.0
    
    for context_name, context in CONTEXT_MODIFIERS.items():
        for pattern in context['file_patterns']:
            if pattern.startswith('.') and not pattern.startswith('./'):
                # Extension check: must end with this extension
                if filename_lower.endswith(pattern):
                    modifier = min(modifier, context['modifier'])
                    break
            else:
                if pattern in filename_lower:
                    modifier = min(modifier, context['modifier'])  # Take strongest modifier
                    break
    
    adjusted = max(0.05, base + modifier)  # Never go below 5%
    return round(adjusted, 2)
