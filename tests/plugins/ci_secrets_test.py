import pytest

from detect_secrets.plugins.ci_secrets import CISecretsDetector


class TestCISecretsDetector:

    @pytest.mark.parametrize(
        'payload, should_flag',
        [
            # GitHub Actions: hardcoded token in env block
            (
                'env:\n  GITHUB_TOKEN: ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890',
                True,
            ),
            # GitLab CI: hardcoded PAT in variables
            (
                'variables:\n  DEPLOY_TOKEN: glpat-xxxxxxxxxxxxxxxxxxxx',
                True,
            ),
            # GitLab runner registration token
            (
                'REGISTRATION_TOKEN=GR1348941abcdefghijklmnopqrst',
                True,
            ),
            # AWS key in CI config
            (
                'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE',
                True,
            ),
            # Docker Hub token in CI
            (
                'DOCKER_TOKEN=dckr_pat_abcdefghijklmnopqrstuvwx',
                True,
            ),
            # Safe: GitHub Actions secret reference (NOT a leak)
            (
                'env:\n  GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}',
                False,
            ),
            # Safe: empty value
            (
                'env:\n  TOKEN: ""',
                False,
            ),
            # Plain text, no CI context
            (
                'Hello world',
                False,
            ),
        ],
    )
    def test_analyze(self, payload, should_flag):
        logic = CISecretsDetector()
        # Test each line individually since RegexBasedDetector works line by line
        found = False
        for i, line in enumerate(payload.split('\n')):
            output = logic.analyze_line(filename='mock_filename', line=line, line_number=i)
            if output:
                found = True
        assert found == should_flag
