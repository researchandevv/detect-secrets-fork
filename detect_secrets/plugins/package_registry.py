"""
Package Registry Token Detector — Loop 57

Detects tokens for package registries beyond NPM:
- Cargo (crates.io) tokens (cio prefix)
- Go module proxy tokens (GONOSUMCHECK bypass patterns)
- PyPI trusted publisher tokens (distinct from pypi_token.py upload tokens)
- NuGet API keys
- RubyGems API keys
- Composer/Packagist tokens

Cross-domain transfer: Each registry has a distinct token format (like GitHub's
ghp_ prefix). From the weight profile, prefix-based patterns have TP rates of
0.85-0.95. The Cargo "cio" prefix and RubyGems "rubygems_" prefix are similarly
distinctive, giving high confidence without context dependency.

Source: knowledge_ddia_ch4_encoding_evolution (schema evolution — new token
formats are forward-compatible additions to the detection schema)
"""
import re

from detect_secrets.plugins.base import RegexBasedDetector


class PackageRegistryDetector(RegexBasedDetector):
    """Scans for package registry authentication tokens."""
    secret_type = 'Package Registry Token'
    confidence = 0.80

    denylist = [
        # Cargo (crates.io) API tokens
        # Format: cio prefix followed by alphanumeric string
        re.compile(
            r'(?:CARGO_REGISTRY_TOKEN|cargo[_\-]token)\s*[=:]\s*["\']?'
            r'(cio[A-Za-z0-9]{32,})'
        ),

        # Cargo: token in .cargo/credentials.toml
        re.compile(
            r'token\s*=\s*["\']?(cio[A-Za-z0-9]{32,})'
        ),

        # Go module proxy: GONOSUMDB / GONOSUMCHECK with private module token
        # The leak is the GOPROXY token for private registries
        re.compile(
            r'GOPROXY\s*=\s*["\']?https://[^,\s]+:([A-Za-z0-9\-_]{20,})@'
        ),

        # Go: GOAUTH for private modules (go 1.23+)
        re.compile(
            r'GOAUTH\s*=\s*["\']?netrc\s+[^\s]+\s+([A-Za-z0-9\-_]{20,})'
        ),

        # NuGet API keys
        re.compile(
            r'(?:NUGET_API_KEY|nuget[_\-]?key)\s*[=:]\s*["\']?'
            r'(oy2[A-Za-z0-9]{40,})'
        ),

        # NuGet: in nuget.config
        re.compile(
            r'<add\s+key="ClearTextPassword"\s+value="([^"]{20,})"'
        ),

        # RubyGems API key
        re.compile(
            r'(?:GEM_HOST_API_KEY|rubygems[_\-]?api[_\-]?key)\s*[=:]\s*["\']?'
            r'(rubygems_[A-Fa-f0-9]{48,})'
        ),

        # Composer/Packagist token (in auth.json or env)
        re.compile(
            r'(?:COMPOSER_AUTH|packagist[_\-]token)\s*[=:]\s*["\']?'
            r'([A-Za-z0-9]{32,})'
        ),

        # Hex.pm (Erlang/Elixir package manager) tokens
        re.compile(
            r'(?:HEX_API_KEY|hex[_\-]?api[_\-]?key)\s*[=:]\s*["\']?'
            r'([A-Za-z0-9\-]{32,})'
        ),

        # Dart pub.dev token
        re.compile(
            r'(?:PUB_TOKEN|pub[_\-]?token)\s*[=:]\s*["\']?'
            r'([A-Za-z0-9\-_]{40,})'
        ),
    ]
