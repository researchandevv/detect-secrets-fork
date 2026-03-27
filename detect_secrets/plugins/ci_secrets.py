"""
CI/CD Secret Detector

Detects hardcoded secrets in CI/CD pipeline configuration files:
- GitHub Actions workflow YAML
- GitLab CI YAML
- Jenkinsfile / Jenkins pipeline scripts

Patterns with specific prefixes (like ghp_, glpat-) have high true positive
rates, while generic env-var references (${{ secrets.X }}) are expected usage,
not leaks.

The key insight: CI config files are a privileged context. A hardcoded token
in a workflow file is almost always a real leak because the *correct* pattern
is to use the platform's secret store. When a developer bypasses the safe API,
the true positive rate jumps from near-zero to near-one.
"""
import re

from detect_secrets.plugins.base import RegexBasedDetector


class CISecretsDetector(RegexBasedDetector):
    """Scans for hardcoded secrets in CI/CD configuration files."""
    secret_type = 'CI/CD Hardcoded Secret'
    confidence = 0.85

    denylist = [
        # GitHub Actions: hardcoded GitHub token on a YAML value line
        # Matches the value line: "  GITHUB_TOKEN: ghp_xxxx"
        # Does NOT match: ${{ secrets.GITHUB_TOKEN }}
        re.compile(
            r'^\s+\w+:\s*["\']?'
            r'(ghp_[A-Za-z0-9_]{36}|gho_[A-Za-z0-9_]{36}|'
            r'ghu_[A-Za-z0-9_]{36}|ghs_[A-Za-z0-9_]{36}|'
            r'ghr_[A-Za-z0-9_]{36})'
        ),

        # GitHub Actions: token directly in run block (inline secret)
        re.compile(
            r'(?:^|\s)(?:curl|wget|gh|git)\s+.*(?:-H\s+["\']Authorization:\s*(?:token|Bearer)\s+'
            r')([A-Za-z0-9_\-]{40,})'
        ),

        # GitLab CI: hardcoded PAT on a YAML value line
        re.compile(
            r'^\s+\w+:\s*["\']?'
            r'(glpat-[A-Za-z0-9\-_]{20,}|glcbt-[A-Za-z0-9\-_]{20,})'
        ),

        # GitLab CI: runner registration token
        re.compile(
            r'(?:REGISTRATION_TOKEN|RUNNER_TOKEN)\s*[=:]\s*["\']?'
            r'(GR1348941[A-Za-z0-9\-_]{20,})'
        ),

        # Jenkins: hardcoded credentials in Jenkinsfile/pipeline
        re.compile(
            r'(?:withCredentials|credentials)\s*\(\s*["\']'
            r'([A-Za-z0-9\-]{36,})["\']'
        ),

        # Jenkins: hardcoded token in sh/bat steps
        re.compile(
            r'(?:sh|bat)\s+["\'].*(?:TOKEN|SECRET|PASSWORD|API_KEY)\s*=\s*'
            r'([A-Za-z0-9\-_]{20,})'
        ),

        # Generic: hardcoded AWS keys in any CI config
        re.compile(
            r'(?:AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*["\']?'
            r'((?:AKIA|ASIA)[A-Z0-9]{16}|[A-Za-z0-9/+=]{40})'
        ),

        # Generic: hardcoded Docker Hub token in CI
        re.compile(
            r'(?:DOCKER_PASSWORD|DOCKER_TOKEN|DOCKERHUB_TOKEN)\s*[=:]\s*["\']?'
            r'(dckr_pat_[A-Za-z0-9\-_]{20,})'
        ),
    ]
