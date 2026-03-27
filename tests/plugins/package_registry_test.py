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
