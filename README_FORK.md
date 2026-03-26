# detect-secrets-enhanced

A maintained fork of [Yelp/detect-secrets](https://github.com/Yelp/detect-secrets) with **16 new detectors**, **active secret verification**, and **false positive reduction**.

The original project has had no commits in 15+ months. This fork fixes bugs, merges stale PRs, and adds detectors for modern API keys that didn't exist when the original was last updated.

## What's New

### 16 New Detectors

| Detector | Pattern | Verification |
|----------|---------|-------------|
| **Anthropic API Key** | `sk-ant-*` | ✅ Live API check |
| **HuggingFace Token** | `hf_*` | ✅ Live API check |
| **GitLab PAT** | `glpat-*`, `gldt-*`, `glrt-*` | ✅ Live API check |
| **Cloudflare API Token** | Context-aware 40-char hex | — |
| **Vercel Token** | `VERCEL_TOKEN=*` | — |
| **Databricks Token** | `dapi*` | — |
| **Notion Token** | `secret_*`, `ntn_*` | — |
| **Supabase Key** | `sbp_*`, JWT service keys | — |
| **Ethereum Private Key** | `0x` + 64 hex in key context | — |
| **Firebase API Key** | `AIza*` | — |
| **Docker Registry Token** | `dckr_pat_*`, config auth | — |
| **Kubernetes Secret** | Service account JWTs, base64 manifests | — |
| **Terraform Secret** | TFE tokens, provider credentials | — |
| **AWS Bedrock** | Inference profile ARNs | — |
| **HashiCorp Vault** | `hvs.*`, `hvb.*`, `hvr.*` | — |
| **AWS Active Validator** | Enhanced AWS with verification | ✅ Format check |

### Active Secret Verification

Unlike the original, this fork can **verify if detected secrets are still active** by testing them against live APIs:

```bash
detect-secrets scan --verify /path/to/code
```

Currently supported: Anthropic, HuggingFace, GitLab. More coming.

### False Positive Reduction

Built-in filter catches common test/example credentials:
- `AKIAIOSFODNN7EXAMPLE` (AWS docs)
- `your_api_key_here` (placeholder patterns)
- `xxxxxxxxxxxxxxxxxxxx` (masked values)
- `sk-ant-api03-example` (example keys)

### Infrastructure-as-Code Support

- **Docker**: Registry tokens, config auth, login passwords
- **Kubernetes**: Service account JWTs, base64 secrets in manifests  
- **Terraform**: TFE tokens, hardcoded provider credentials

## Comparison

| Feature | detect-secrets (original) | This fork | gitleaks | trufflehog |
|---------|--------------------------|-----------|----------|------------|
| Detectors | 27 | **43** | ~150 (regex) | ~800 (regex) |
| Verification | 3 (AWS, Slack, Stripe) | **6** (+Anthropic, HF, GitLab) | — | ✅ (all) |
| Plugin system | ✅ | ✅ | — | — |
| IaC scanning | — | ✅ (Docker, K8s, TF) | ✅ | ✅ |
| FP filter | — | ✅ | — | — |
| Baseline mode | ✅ | ✅ | — | — |
| Python-native | ✅ | ✅ | Go | Go |
| ARM64 | ✅ | ✅ | ✅ | ✅ |
| Maintained | ❌ (15mo stale) | ✅ | ✅ | ✅ |

## Installation

```bash
pip install detect-secrets-enhanced
```

Or from source:
```bash
git clone https://github.com/YOUR_USERNAME/detect-secrets-enhanced
cd detect-secrets-enhanced
pip install -e .
```

## Quick Start

```bash
# Scan a directory
detect-secrets scan /path/to/code

# Scan with verification (tests keys against live APIs)
detect-secrets scan --verify /path/to/code

# List all available plugins
detect-secrets scan --list-all-plugins

# Create a baseline
detect-secrets scan > .secrets.baseline
```

## Writing Custom Plugins

```python
import re
from detect_secrets.plugins.base import RegexBasedDetector

class MyCustomDetector(RegexBasedDetector):
    secret_type = 'My Custom Secret'
    denylist = [
        re.compile(r'my_secret_pattern_[A-Za-z0-9]{20,}'),
    ]
```

Drop the file in `detect_secrets/plugins/` and it's automatically discovered.

## License

Apache-2.0 (same as original)
