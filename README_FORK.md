# detect-secrets-enhanced

**Secret detection that tells you how confident it is.**

Most secret scanners dump hundreds of findings and leave you to figure out which ones matter. detect-secrets-enhanced adds confidence scoring to every finding, so you triage the 5 high-confidence results instead of wading through 200.

Built on [Yelp/detect-secrets](https://github.com/Yelp/detect-secrets) (unmaintained since late 2024), this fork adds 18 new detectors for modern API keys, active secret verification, and the infrastructure to measure how well each detector actually performs on your codebase.

## 30-Second Demo

```bash
pip install -e .
python demo.py /path/to/your/code
```

Output shows color-coded confidence for every finding. High confidence (red) = almost certainly a real secret. Low confidence (grey) = likely a false positive from high-entropy strings.

## Why This Exists

**The problem:** detect-secrets is the only Python-native secret scanner with a plugin system, baseline mode, and `pip install`. But the original hasn't been updated in 15+ months. New API key formats (Anthropic, HuggingFace, Supabase, Vercel) go undetected. There's no way to know which findings are worth investigating.

**The alternative tools:** gitleaks (~150 regex rules) and trufflehog (~800 detectors + full verification) are excellent but written in Go. If your pipeline is Python, or you need custom detectors without learning a new language, or you want a plugin system — they don't fit.

**This fork fills the gap:** Python-native, extensible, and now with confidence scoring that improves as you use it.

## What's Different

| Capability | Original detect-secrets | This fork | gitleaks | trufflehog |
|------------|------------------------|-----------|----------|------------|
| Detectors | 27 | **45** (+18 new) | ~150 (regex) | ~800 (regex+verify) |
| Confidence scores | No | **Per-finding scores** | No | No |
| Calibration from your data | No | **Yes** (audit labels) | No | No |
| Active verification | 3 (AWS, Slack, Stripe) | **6** (+Anthropic, HF, GitLab) | No | Yes (all) |
| Git history scanning | No | **Yes** (deleted files + patches) | Yes | Yes |
| SARIF output (CI) | No | **Yes** (2.1.0) | Yes | Yes |
| Baseline version stamps | No | **Yes** (upgrade drift detection) | N/A | N/A |
| Plugin system | Yes | Yes | No | No |
| False positive filter | No | **Yes** (known test creds) | No | No |
| IaC support | No | **Yes** (Docker, K8s, Terraform) | Yes | Yes |
| Language | Python | Python | Go | Go |
| Maintained | No (15mo+) | **Yes** | Yes | Yes |

**On detector counts:** gitleaks and trufflehog have more regex rules. This fork has fewer but smarter detectors — each one carries a confidence score and can be calibrated against your labeled baselines. 45 detectors with confidence data beats 800 without it, because you spend time on findings that matter.

## New Detectors

| Detector | Pattern | Verifies? |
|----------|---------|-----------|
| Anthropic API Key | `sk-ant-*` | Yes |
| HuggingFace Token | `hf_*` | Yes |
| GitLab PAT | `glpat-*` | Yes |
| Cloudflare API Token | Context-aware 40-char hex | — |
| Vercel Token | `VERCEL_TOKEN=*` | — |
| Databricks Token | `dapi*` | — |
| Notion Token | `secret_*`, `ntn_*` | — |
| Supabase Key | `sbp_*`, JWT service keys | — |
| Ethereum Private Key | `0x` + 64 hex in key context | — |
| Firebase API Key | `AIza*` | — |
| Docker Registry Token | `dckr_pat_*`, config auth | — |
| Kubernetes Secret | Service account JWTs, base64 manifests | — |
| Terraform Secret | TFE tokens, provider credentials | — |
| AWS Bedrock | Inference profile ARNs | — |
| HashiCorp Vault | `hvs.*`, `hvb.*`, `hvr.*` | — |
| Connection String | Database URIs with embedded passwords | — |
| CI/CD Secret | Hardcoded secrets in CI config files | — |
| Package Registry Token | npm, PyPI, NuGet, Cargo tokens | — |

## Installation

```bash
pip install detect-secrets-enhanced
```

From source:
```bash
git clone https://github.com/YOUR_USERNAME/detect-secrets-enhanced
cd detect-secrets-enhanced
pip install -e .
```

## Quick Start

```bash
# Scan a directory
detect-secrets scan /path/to/code

# Scan with active verification (checks if secrets are live)
detect-secrets scan --verify /path/to/code

# Create a baseline (track new secrets, ignore known ones)
detect-secrets scan > .secrets.baseline

# Audit findings interactively
detect-secrets audit .secrets.baseline

# List all available detectors
detect-secrets scan --list-all-plugins
```

## Confidence Scoring

Every detector has a confidence score (0.0-1.0) reflecting how likely its findings are real secrets vs. false positives.

Scores come from pattern specificity: `sk-ant-api03-*` (Anthropic key format, confidence 0.95) is almost always real. A 40-character hex string (confidence 0.4) could be anything.

### Calibration: Make Scores Accurate for Your Codebase

After you audit a baseline (`detect-secrets audit`), calibration compares each detector's confidence score against its actual true positive rate from your labeled data:

```python
from detect_secrets.plugins.calibrate import calibrate_from_baseline, format_calibration_report

results = calibrate_from_baseline('.secrets.baseline')
print(format_calibration_report(results))
```

```
Detector                   TP Rate   Confidence   Delta    Samples
─────────────────────────────────────────────────────────────────────
ArtifactoryDetector        1.000     0.80         +0.200   7
AnthropicDetector          1.000     0.95          0.000   3
HighEntropyString          0.125     0.40         -0.275   8 **
KeywordDetector             0.071     0.60         -0.529   14 **
```

Detectors marked `**` have significant drift — their static scores don't match reality. Adjust or disable them.

### Writing Custom Detectors

```python
import re
from detect_secrets.plugins.base import RegexBasedDetector

class MyInternalToken(RegexBasedDetector):
    secret_type = 'Internal Service Token'
    confidence = 0.90  # Self-describing: no need to edit confidence.py
    denylist = [
        re.compile(r'myco_tok_[A-Za-z0-9]{32}'),
    ]
```

Drop the file in `detect_secrets/plugins/` — it's auto-discovered. The `confidence` class attribute is optional; if omitted, defaults to 0.5.

## CI Integration (SARIF)

Convert scan results to SARIF 2.1.0 for GitHub Code Scanning, GitLab SAST, or Azure DevOps:

```python
from detect_secrets.util.sarif_output import baseline_to_sarif_file
baseline_to_sarif_file('.secrets.baseline', 'results.sarif')
```

GitHub Actions workflow:
```yaml
- name: Scan for secrets
  run: |
    pip install detect-secrets-enhanced
    detect-secrets scan > .secrets.baseline
    python -c "from detect_secrets.util.sarif_output import baseline_to_sarif_file; baseline_to_sarif_file('.secrets.baseline', 'results.sarif')"

- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

## Git History Scanning

Secrets committed then deleted are still in git history. This fork scans for them without leaving Python:

```python
from detect_secrets.util.git_history import (
    scan_deleted_files,
    scan_recent_patches,
    format_history_report,
)

# Find secrets in files that were deleted from the repo
deleted = scan_deleted_files('/path/to/repo', max_commits=100)

# Find secrets in recently added lines
patches = scan_recent_patches('/path/to/repo', max_commits=50)

print(format_history_report(deleted + patches))
```

This reuses existing plugin detectors — no new dependencies. It covers the common case (secret committed then removed) without requiring Go tooling.

## Baseline Version Stamps

Upgrading detect-secrets can cause phantom diffs in baselines (new plugins find things old ones didn't). Version stamps catch this before it causes confusion:

```python
from detect_secrets.util.baseline_stamp import stamp_baseline, check_baseline_compat

stamp_baseline('.secrets.baseline')  # Record current version + plugin set

# After upgrading:
result = check_baseline_compat('.secrets.baseline')
if not result['compatible']:
    print(f"Added plugins:   {result['added_plugins']}")
    print(f"Removed plugins: {result['removed_plugins']}")
    # Re-scan to create a clean baseline
```

## Active Verification

Verification tests detected secrets against live APIs to check if they're still active:

```bash
detect-secrets scan --verify /path/to/code
```

Currently supported: Anthropic, HuggingFace, GitLab (plus the original AWS, Slack, Stripe).

**Important:** Verification sends the secret to the API endpoint. Only use on secrets you're authorized to test. Use `--no-verify` when scanning repos you don't own.

## False Positive Filter

Built-in filter removes known test/example credentials before they reach your results:
- `AKIAIOSFODNN7EXAMPLE` (AWS documentation)
- `your_api_key_here`, `xxxxxxxxxxxxxxxxxxxx` (placeholder patterns)
- `sk-ant-api03-example` (example keys)

## Test Suite

1,241 tests. Run with:
```bash
pip install -r requirements-dev.txt
pytest tests/
```

## License

Apache-2.0 (same as original)
