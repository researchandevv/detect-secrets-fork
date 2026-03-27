import pytest

from detect_secrets.plugins.package_registry import PackageRegistryDetector


class TestPackageRegistryDetector:

    @pytest.mark.parametrize(
        'payload, should_flag',
        [
            # Cargo token in env var
            (
                'CARGO_REGISTRY_TOKEN=cioAbCdEfGhIjKlMnOpQrStUvWxYz012345',
                True,
            ),
            # Cargo token in credentials.toml
            (
                'token = "cioAbCdEfGhIjKlMnOpQrStUvWxYz012345"',
                True,
            ),
            # Go private module proxy with embedded token
            (
                'GOPROXY=https://user:mySecretTokenValue1234@proxy.company.com',
                True,
            ),
            # NuGet API key
            (
                'NUGET_API_KEY=oy2abcdefghijklmnopqrstuvwxyz0123456789ABCDEF',
                True,
            ),
            # NuGet in config
            (
                '<add key="ClearTextPassword" value="myNuGetPasswordThatIsLong"/>',
                True,
            ),
            # RubyGems API key
            (
                'GEM_HOST_API_KEY=rubygems_abcdef0123456789abcdef0123456789abcdef0123456789',
                True,
            ),
            # Not a token: too short
            (
                'CARGO_REGISTRY_TOKEN=short',
                False,
            ),
            # Not a token: plain text
            (
                'Hello world',
                False,
            ),
            # Not a token: Go proxy without credentials
            (
                'GOPROXY=https://proxy.golang.org,direct',
                False,
            ),
        ],
    )
    def test_analyze(self, payload, should_flag):
        logic = PackageRegistryDetector()
        output = logic.analyze_line(filename='mock_filename', line=payload)
        assert len(output) == int(should_flag), f'Expected {"match" if should_flag else "no match"} for: {payload}'


class TestPackageRegistryDetectorExtended:
    """Extended tests for untested registry types and edge cases."""

    def _scan(self, line):
        logic = PackageRegistryDetector()
        return len(logic.analyze_line(filename='mock_filename', line=line)) > 0

    def test_hex_pm_token(self):
        """Hex.pm (Erlang/Elixir) API key should be detected."""
        payload = 'HEX_API_KEY=abcdef01-2345-6789-abcd-ef0123456789ab'
        assert self._scan(payload) is True

    def test_dart_pub_dev_token(self):
        """Dart pub.dev token should be detected (40+ chars)."""
        payload = 'PUB_TOKEN=abcdefghijklmnopqrstuvwxyz01234567890ABCDE'
        assert self._scan(payload) is True

    def test_composer_packagist_token(self):
        """Composer/Packagist auth token should be detected (32+ chars)."""
        payload = 'COMPOSER_AUTH=abcdef0123456789abcdef0123456789ab'
        assert self._scan(payload) is True

    def test_goauth_private_module(self):
        """Go GOAUTH for private modules should be detected."""
        payload = 'GOAUTH=netrc machine.example.com abcdefghijklmnopqrstuvwx'
        assert self._scan(payload) is True

    def test_nuget_in_config_short_value_no_match(self):
        """NuGet config with value under 20 chars should NOT match."""
        payload = '<add key="ClearTextPassword" value="short"/>'
        assert self._scan(payload) is False

    def test_rubygems_wrong_prefix_no_match(self):
        """RubyGems key without rubygems_ prefix should NOT match."""
        payload = 'GEM_HOST_API_KEY=notarubygems_abcdef0123456789abcdef012345678'
        assert self._scan(payload) is False

    def test_cargo_hyphenated_env_name(self):
        """cargo-token (with hyphen) should be detected."""
        payload = 'cargo-token=cioAbCdEfGhIjKlMnOpQrStUvWxYz012345'
        assert self._scan(payload) is True

    def test_secret_type_attribute(self):
        """Verify secret_type is set correctly."""
        assert PackageRegistryDetector.secret_type == 'Package Registry Token'

    def test_confidence_attribute(self):
        """Verify confidence level."""
        assert PackageRegistryDetector.confidence == 0.80

    def test_denylist_count(self):
        """Verify all 10 regex patterns are present."""
        assert len(PackageRegistryDetector.denylist) == 10

    def test_nuget_key_variant_spelling(self):
        """nuget-key (hyphenated) should be detected."""
        payload = 'nuget-key=oy2abcdefghijklmnopqrstuvwxyz0123456789ABCDEF'
        assert self._scan(payload) is True

    def test_hex_pm_with_hyphenated_name(self):
        """hex-api-key (hyphenated) should be detected."""
        payload = 'hex-api-key=abcdef01-2345-6789-abcd-ef0123456789ab'
        assert self._scan(payload) is True

    def test_pub_token_with_underscore_name(self):
        """pub_token (underscore) should be detected."""
        payload = 'pub_token=abcdefghijklmnopqrstuvwxyz01234567890ABCDE'
        assert self._scan(payload) is True

    def test_packagist_token_variant(self):
        """packagist-token (hyphenated) should be detected."""
        payload = 'packagist-token=abcdef0123456789abcdef0123456789ab'
        assert self._scan(payload) is True

    def test_cargo_credentials_toml_with_quotes(self):
        """Cargo credentials.toml with single quotes should be detected."""
        payload = "token = 'cioAbCdEfGhIjKlMnOpQrStUvWxYz012345'"
        assert self._scan(payload) is True

    def test_safe_cargo_no_cio_prefix(self):
        """Cargo token without cio prefix should NOT match."""
        payload = 'CARGO_REGISTRY_TOKEN=notcioAbCdEfGhIjKlMnOpQrStUvWxYz'
        assert self._scan(payload) is False

    def test_safe_nuget_no_oy2_prefix(self):
        """NuGet key without oy2 prefix should NOT match."""
        payload = 'NUGET_API_KEY=abcdefghijklmnopqrstuvwxyz0123456789ABCDEF'
        assert self._scan(payload) is False

    def test_safe_rubygems_short_value(self):
        """RubyGems key with too-short value should NOT match."""
        payload = 'GEM_HOST_API_KEY=rubygems_abc'
        assert self._scan(payload) is False

    def test_inherits_regex_based_detector(self):
        """PackageRegistryDetector must be a subclass of RegexBasedDetector."""
        from detect_secrets.plugins.base import RegexBasedDetector
        assert issubclass(PackageRegistryDetector, RegexBasedDetector)
