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


class TestCISecretsDetectorExtended:
    """Extended tests for code paths not covered by the parametrized suite."""

    def _scan_lines(self, text):
        logic = CISecretsDetector()
        found = False
        for i, line in enumerate(text.split('\n')):
            if logic.analyze_line(filename='mock_filename', line=line, line_number=i):
                found = True
        return found

    def test_gho_prefix_token(self):
        """gho_ (OAuth) prefix should be detected in YAML env blocks."""
        payload = 'env:\n  TOKEN: gho_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890'
        assert self._scan_lines(payload) is True

    def test_ghu_prefix_token(self):
        """ghu_ (user-to-server) prefix should be detected."""
        payload = 'env:\n  TOKEN: ghu_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890'
        assert self._scan_lines(payload) is True

    def test_ghs_prefix_token(self):
        """ghs_ (server-to-server) prefix should be detected."""
        payload = 'env:\n  TOKEN: ghs_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890'
        assert self._scan_lines(payload) is True

    def test_ghr_prefix_token(self):
        """ghr_ (refresh) prefix should be detected."""
        payload = 'env:\n  TOKEN: ghr_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890'
        assert self._scan_lines(payload) is True

    def test_jenkins_hardcoded_credentials(self):
        """Jenkins withCredentials block with hardcoded UUID should be detected."""
        payload = 'withCredentials("a1b2c3d4-e5f6-7890-abcd-ef1234567890")'
        assert self._scan_lines(payload) is True

    def test_jenkins_sh_step_token(self):
        """Jenkins sh step with hardcoded TOKEN= should be detected."""
        payload = 'sh "export API_KEY=abcdefghijklmnopqrstuvwxyz1234"'
        assert self._scan_lines(payload) is True

    def test_curl_authorization_header(self):
        """curl with -H Authorization: token should be detected."""
        payload = 'curl -H "Authorization: token abcdefghijklmnopqrstuvwxyz1234567890abcd"'
        assert self._scan_lines(payload) is True

    def test_aws_secret_access_key(self):
        """AWS_SECRET_ACCESS_KEY with 40-char base64 value should be detected."""
        payload = 'AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
        assert self._scan_lines(payload) is True

    def test_gitlab_ci_build_token(self):
        """glcbt- (CI build token) prefix should be detected."""
        payload = 'variables:\n  CI_TOKEN: glcbt-xxxxxxxxxxxxxxxxxxxx'
        assert self._scan_lines(payload) is True

    def test_safe_env_variable_reference(self):
        """GitLab CI $VARIABLE references should NOT be flagged."""
        payload = 'variables:\n  TOKEN: $CI_JOB_TOKEN'
        assert self._scan_lines(payload) is False

    def test_safe_github_actions_expression(self):
        """${{ secrets.X }} expressions should NOT be flagged."""
        payload = 'env:\n  AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}'
        assert self._scan_lines(payload) is False

    def test_secret_type_attribute(self):
        """Verify the detector has correct secret_type."""
        assert CISecretsDetector.secret_type == 'CI/CD Hardcoded Secret'

    def test_confidence_attribute(self):
        """Verify confidence is set as a class attribute."""
        assert CISecretsDetector.confidence == 0.85

    def test_denylist_has_expected_count(self):
        """Verify all 8 regex patterns are in the denylist."""
        assert len(CISecretsDetector.denylist) == 8

    def test_gh_cli_authorization_bearer(self):
        """gh CLI with Bearer auth header should be detected."""
        payload = 'gh api -H "Authorization: Bearer abcdefghijklmnopqrstuvwxyz1234567890abcd"'
        assert self._scan_lines(payload) is True

    def test_jenkins_credentials_function(self):
        """Jenkins credentials() function with UUID should be detected."""
        payload = 'credentials("12345678-1234-1234-1234-123456789012")'
        assert self._scan_lines(payload) is True

    def test_jenkins_bat_step_secret(self):
        """Jenkins bat step with hardcoded SECRET= should be detected."""
        payload = 'bat "set SECRET=abcdefghijklmnopqrstuvwxyz1234"'
        assert self._scan_lines(payload) is True

    def test_runner_token_with_colon_separator(self):
        """RUNNER_TOKEN: value (YAML-style) should be detected."""
        payload = 'RUNNER_TOKEN: GR1348941abcdefghijklmnopqrst'
        assert self._scan_lines(payload) is True

    def test_docker_password_env(self):
        """DOCKER_PASSWORD with dckr_pat_ token should be detected."""
        payload = 'DOCKER_PASSWORD=dckr_pat_abcdefghijklmnopqrstuvwx'
        assert self._scan_lines(payload) is True

    def test_dockerhub_token_quoted(self):
        """DOCKERHUB_TOKEN with quoted value should be detected."""
        payload = "DOCKERHUB_TOKEN='dckr_pat_abcdefghijklmnopqrstuvwx'"
        assert self._scan_lines(payload) is True

    def test_aws_asia_prefix(self):
        """AWS key with ASIA prefix (temporary credentials) should be detected."""
        payload = 'AWS_ACCESS_KEY_ID=ASIAIOSFODNN7EXAMPLE'
        assert self._scan_lines(payload) is True

    def test_ghp_token_in_single_quotes(self):
        """GitHub token in single quotes should be detected."""
        payload = "  MY_TOKEN: 'ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890'"
        assert self._scan_lines(payload) is True

    def test_safe_short_github_prefix(self):
        """Token-like prefix but too short should NOT match."""
        payload = '  TOKEN: ghp_short'
        assert self._scan_lines(payload) is False

    def test_safe_jenkins_empty_credentials(self):
        """Empty credentials() call should NOT match."""
        payload = 'credentials("")'
        assert self._scan_lines(payload) is False

    def test_inherits_regex_based_detector(self):
        """CISecretsDetector must be a subclass of RegexBasedDetector."""
        from detect_secrets.plugins.base import RegexBasedDetector
        assert issubclass(CISecretsDetector, RegexBasedDetector)
