"""Tests for all new detectors added in the fork."""
import pytest
from detect_secrets.plugins.anthropic import AnthropicApiKeyDetector
from detect_secrets.plugins.huggingface import HuggingFaceTokenDetector
from detect_secrets.plugins.cloudflare import CloudflareApiTokenDetector
from detect_secrets.plugins.vercel import VercelTokenDetector
from detect_secrets.plugins.databricks import DatabricksTokenDetector
from detect_secrets.plugins.notion import NotionTokenDetector
from detect_secrets.plugins.supabase import SupabaseKeyDetector
from detect_secrets.plugins.ethereum import EthereumPrivateKeyDetector
from detect_secrets.plugins.firebase import FirebaseApiKeyDetector
from detect_secrets.plugins.gitlab_pat import GitLabPatDetector
from detect_secrets.plugins.docker_secrets import DockerRegistryTokenDetector
from detect_secrets.plugins.kubernetes import KubernetesSecretDetector
from detect_secrets.plugins.terraform import TerraformSecretDetector
from detect_secrets.plugins.aws_bedrock import AWSBedrockDetector
from detect_secrets.plugins.hashicorp_vault import HashiCorpVaultTokenDetector
from detect_secrets.plugins.test_credential_filter import is_likely_fake


class TestAnthropicDetector:
    def test_detect_api_key(self):
        d = AnthropicApiKeyDetector()
        assert list(d.analyze_line('f', 'key = "sk-ant-api03-abc123def456ghi789jkl"', 1))

    def test_no_false_positive_on_partial(self):
        d = AnthropicApiKeyDetector()
        assert not list(d.analyze_line('f', 'sk-ant-short', 1))


class TestHuggingFaceDetector:
    def test_detect_user_token(self):
        d = HuggingFaceTokenDetector()
        assert list(d.analyze_line('f', 'HF_TOKEN=hf_abcdefghijklmnopqrstuvwxyz0123456789ab', 1))

    def test_detect_org_token(self):
        d = HuggingFaceTokenDetector()
        assert list(d.analyze_line('f', 'api_org_abcdefghijklmnopqrstuvwxyz012345678901234567', 1))


class TestDatabricksDetector:
    def test_detect_token(self):
        d = DatabricksTokenDetector()
        assert list(d.analyze_line('f', 'token = "dapi0123456789abcdef0123456789abcdef01"', 1))


class TestFirebaseDetector:
    def test_detect_api_key(self):
        d = FirebaseApiKeyDetector()
        assert list(d.analyze_line('f', 'apiKey: "AIzaSyBcDeFgHiJkLmNoPqRsTuVwXyZ01234567"', 1))


class TestGitLabPatDetector:
    def test_detect_pat(self):
        d = GitLabPatDetector()
        assert list(d.analyze_line('f', 'GITLAB_TOKEN=glpat-xYz123AbCdEfGhIjKlMn', 1))

    def test_detect_deploy_token(self):
        d = GitLabPatDetector()
        assert list(d.analyze_line('f', 'token = "gldt-xYz123AbCdEfGhIjKlMn"', 1))

    def test_detect_runner_token(self):
        d = GitLabPatDetector()
        assert list(d.analyze_line('f', 'RUNNER_TOKEN=glrt-xYz123AbCdEfGhIjKlMn', 1))


class TestNotionDetector:
    def test_detect_secret(self):
        d = NotionTokenDetector()
        assert list(d.analyze_line('f', 'NOTION=secret_abcdefghijklmnopqrstuvwxyz0123456789ABCD', 1))

    def test_detect_ntn_token(self):
        d = NotionTokenDetector()
        assert list(d.analyze_line('f', 'token=ntn_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH', 1))


class TestEthereumDetector:
    def test_detect_private_key(self):
        d = EthereumPrivateKeyDetector()
        assert list(d.analyze_line('f', 'private_key = 0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab', 1))


class TestDockerDetector:
    def test_detect_pat(self):
        d = DockerRegistryTokenDetector()
        assert list(d.analyze_line('f', 'DOCKER_TOKEN=dckr_pat_abc123def456ghi789jkl', 1))

    def test_detect_config_auth(self):
        d = DockerRegistryTokenDetector()
        assert list(d.analyze_line('f', '"auth": "dXNlcjpwYXNzd29yZDEyMw=="', 1))


class TestKubernetesDetector:
    def test_detect_service_account_jwt(self):
        d = KubernetesSecretDetector()
        line = 'token: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJrdWJlcm5ldGVzIn0.sig'
        assert list(d.analyze_line('f', line, 1))


class TestTerraformDetector:
    def test_detect_hardcoded_key(self):
        d = TerraformSecretDetector()
        assert list(d.analyze_line('f', 'access_key = "AKIAIOSFODNN7REALKEY1"', 1))

    def test_no_false_positive_on_var_ref(self):
        d = TerraformSecretDetector()
        assert not list(d.analyze_line('f', 'access_key = "var.aws_access_key"', 1))


class TestBedrockDetector:
    def test_detect_arn(self):
        d = AWSBedrockDetector()
        assert list(d.analyze_line('f', 'arn:aws:bedrock:us-east-1:123456789012:inference-profile/abc-123', 1))


class TestVaultDetector:
    def test_detect_service_token(self):
        d = HashiCorpVaultTokenDetector()
        assert list(d.analyze_line('f', 'VAULT_TOKEN=hvs.CAESIG1234567890abcdefghij', 1))

    def test_detect_batch_token(self):
        d = HashiCorpVaultTokenDetector()
        assert list(d.analyze_line('f', 'token = "hvb.AAAAAQKxyz1234567890abcde"', 1))


class TestFakeCredentialFilter:
    def test_catches_aws_example(self):
        assert is_likely_fake('AKIAIOSFODNN7EXAMPLE')

    def test_catches_placeholder(self):
        assert is_likely_fake('your_api_key')

    def test_catches_repeated_x(self):
        assert is_likely_fake('xxxxxxxxxxxxxxxxxxxx')

    def test_passes_real_key(self):
        assert not is_likely_fake('sk-ant-real123abc456def789ghi')

    def test_catches_example_text(self):
        assert is_likely_fake('this-is-an-example-key')
