# Contributing to detect-secrets (Confidence Fork)

This fork adds confidence scoring to detect-secrets. This guide explains how
to add new detectors, configure confidence scores, use the filter system,
and write tests. For general project background, see [docs/design.md](/docs/design.md).

## Development Setup

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements-dev.txt
python -m detect_secrets --version
```

Run the test suite:

```bash
python -m pytest tests          # fast: ~10 seconds
tox -e py311                    # full: linting + coverage + mypy
```

## Adding a New Detector

Every detector is a single file in `detect_secrets/plugins/`. Most detectors
extend `RegexBasedDetector`.

### 1. Create the plugin file

```python
# detect_secrets/plugins/acme.py
import re
from .base import RegexBasedDetector

class AcmeApiKeyDetector(RegexBasedDetector):
    """Scans for Acme Corp API keys (acme_sk_*)."""
    secret_type = 'Acme API Key'
    confidence = 0.85          # <-- REQUIRED in this fork
    denylist = [
        re.compile(r'acme_sk_[A-Za-z0-9]{32,}'),
    ]
```

That's it. The plugin discovery system auto-registers any `BasePlugin` subclass.

### 2. Choose `secret_type` carefully

- Must be unique across all plugins (no two plugins share the same value).
- Must be human-readable -- it appears in scan output and baselines.
- Once published, changing it requires a baseline migration.

### 3. Set the `confidence` class attribute

Every detector in this fork **must** declare a `confidence` float (0.0--1.0).
This is the fork's core differentiator -- it tells users how likely a finding
is to be a real secret vs. a false positive.

**Calibration guidelines:**

| Range       | Meaning                          | Example                                    |
|-------------|----------------------------------|--------------------------------------------|
| 0.90--1.00  | Unique prefix, almost always real | `sk-ant-*` (Anthropic), PEM headers         |
| 0.70--0.89  | Strong prefix, occasional FP     | `npm_*`, `dckr_pat_*`, connection strings   |
| 0.40--0.69  | Context-dependent                 | Hex tokens, Terraform HCL, Vercel env vars  |
| 0.10--0.39  | High entropy / keyword-based      | Base64 strings, keyword matches             |
| < 0.10      | Informational only                | Public IPs                                  |

Ask yourself:

- Does the pattern have a **unique prefix**? (high confidence)
- Could the pattern match **non-secret content** like UUIDs, hashes, or
  variable names? (lower confidence)
- Is the match **dependent on file context** (e.g., only meaningful in
  `.env` files)? (medium confidence, contextual modifiers will adjust it)

### 4. Optionally add a `verify()` method

If the service provides a way to check whether a key is live (e.g., a
lightweight API call), add a `verify()` method. Return `VerifiedResult.VERIFIED_TRUE`,
`VERIFIED_FALSE`, or `UNVERIFIED`.

```python
def verify(self, secret: str):
    from detect_secrets.constants import VerifiedResult
    import requests
    try:
        resp = requests.get(
            'https://api.acme.com/v1/whoami',
            headers={'Authorization': f'Bearer {secret}'},
            timeout=5,
        )
        return VerifiedResult.VERIFIED_TRUE if resp.status_code == 200 \
            else VerifiedResult.VERIFIED_FALSE
    except Exception:
        return VerifiedResult.UNVERIFIED
```

### 5. Write tests

Create `tests/plugins/acme_test.py`:

```python
import pytest
from detect_secrets.plugins.acme import AcmeApiKeyDetector

class TestAcmeApiKeyDetector:
    def setup_method(self):
        self.plugin = AcmeApiKeyDetector()

    def test_detect_real_key(self):
        assert self.plugin.analyze_line(
            filename='config.py',
            line='API_KEY = "acme_sk_abcdefghijklmnopqrstuvwxyz123456"',
            line_number=1,
        )

    def test_ignore_short_match(self):
        assert not self.plugin.analyze_line(
            filename='config.py',
            line='API_KEY = "acme_sk_short"',
            line_number=1,
        )

    def test_confidence_attribute(self):
        assert hasattr(AcmeApiKeyDetector, 'confidence')
        assert 0.0 <= AcmeApiKeyDetector.confidence <= 1.0
```

**Every new detector must have:**
- At least one positive detection test (real pattern matches).
- At least one negative test (similar but non-matching pattern).
- A confidence attribute test.

## Confidence Scoring System

The confidence system resolves scores in this order:

1. **`DETECTOR_CONFIDENCE` dict** in `confidence.py` -- calibration overrides.
   This is where empirically-tuned scores go after real-world data analysis.
2. **Plugin class `confidence` attribute** -- self-describing plugins. New
   plugins declare their score here and it works without editing confidence.py.
3. **Default 0.5** -- unknown detector types get a neutral score.

For new detectors, just set the class attribute (step 2). Only add to the
central dict if you have empirical scan data that overrides the initial estimate.

### Contextual Confidence

`get_contextual_confidence(secret_type, filename)` adjusts the base score
using file context. For example:

- A Stripe key in `test_fixtures.py` gets a -0.4 modifier (test files)
- A key in `package-lock.json` gets a -0.9 modifier (lock files)
- A key in `vendor/` gets a -0.6 modifier (third-party code)

Context modifiers are defined in `CONTEXT_MODIFIERS` in `confidence.py`.
You do not need to modify these when adding a new detector -- they apply
automatically to all detector types.

### Rapid Dismiss

Files matching `RAPID_DISMISS_PATTERNS` (lock files, minified JS, node_modules)
are skipped entirely. These have near-zero probability of containing real
secrets. If your detector targets a file type that is currently rapid-dismissed,
you may need to adjust the pattern list.

## Filter System

Filters in `detect_secrets/filters/` reduce false positives by examining
context around a finding. The built-in filters include:

- **allowlist** -- inline `# pragma: allowlist secret` comments
- **heuristic** -- common FP patterns (likely not a secret, looks like variable name)
- **gibberish** -- statistical detection of random-looking but non-secret strings
- **wordlist** -- known non-secret tokens

To add a custom filter:

1. Create a function in `detect_secrets/filters/` that returns `True` to
   filter out (suppress) a finding:

```python
def should_exclude_secret(filename: str, secret: str) -> bool:
    """Exclude findings that match known safe patterns."""
    return secret.startswith('EXAMPLE_')
```

2. Register the filter via the settings system or pass it to the scan call.

## Multi-Provider Analysis

`multi_provider.py` analyzes files that contain secrets from 3+ different
providers. When a single file has an AWS key, a Stripe key, and a Slack token,
the probability that ALL of them are false positives drops multiplicatively.
This is implemented as a post-scan analysis step, not a detector.

## Code Style

- Follow existing patterns in the codebase.
- Use `tox` to run linting before submitting.
- Keep detector files focused -- one detector class per file.
- Document the `confidence` score with a brief comment explaining the reasoning.

## Pull Request Checklist

- [ ] New detector has `secret_type` (unique) and `confidence` (calibrated)
- [ ] Tests cover positive match, negative match, and confidence attribute
- [ ] `tox` passes locally
- [ ] If you modified confidence.py, scores are justified with reasoning
- [ ] No secrets, credentials, or API keys in test fixtures (use obvious fakes)
