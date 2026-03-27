import pytest

from detect_secrets.plugins.env_file import EnvFileSecretDetector


class TestEnvFileSecretDetector:
    """Tests for the .env file secret detector."""

    # --- Positive cases: should detect secrets ---

    @pytest.mark.parametrize(
        'payload',
        [
            'DATABASE_PASSWORD=hunter2',
            'DB_PASSWORD=s3cret!value',
            'SECRET_KEY=a1b2c3d4e5f6g7h8i9j0',
            'API_KEY=sk-1234567890abcdef',
            'PRIVATE_KEY=MIIEvgIBADANBgkqhkiG9w',
            'AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCY',
            'STRIPE_SECRET=sk_live_abc123def456',
            'JWT_SECRET=my-super-long-jwt-secret-key-here',
            'REDIS_PASSWORD=r3d1s_p@ss!',
            'SMTP_PASSWORD=mailpass123',
            'MONGO_URI=mongodb://user:pass@host:27017/db',
            'CLIENT_SECRET=oauth-client-secret-value',
            'GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxx',
            'SESSION_SECRET=keyboard-cat-session-key',
            'ENCRYPTION_KEY=aes-256-key-value-here',
            'DB_URL=postgres://user:pass@localhost/mydb',
            'TOKEN=bearer-token-value-12345',
            'AUTH_TOKEN=eyJhbGciOiJIUzI1NiJ9.payload',
        ],
    )
    def test_detect_secrets_in_env_file(self, payload):
        logic = EnvFileSecretDetector()
        output = logic.analyze_line(filename='.env', line=payload)
        assert len(output) >= 1, f'Should detect secret in: {payload}'

    @pytest.mark.parametrize(
        'payload',
        [
            'PASSWORD=mypassword123',
            'SECRET=real-secret-value',
            'ACCESS_TOKEN=abc123xyz',
        ],
    )
    def test_detect_in_env_local(self, payload):
        """Should activate on .env.local files."""
        logic = EnvFileSecretDetector()
        output = logic.analyze_line(filename='.env.local', line=payload)
        assert len(output) >= 1

    @pytest.mark.parametrize(
        'payload',
        [
            'PASSWORD=mypassword123',
            'SECRET=real-secret-value',
        ],
    )
    def test_detect_in_production_env(self, payload):
        """Should activate on production.env files."""
        logic = EnvFileSecretDetector()
        output = logic.analyze_line(filename='production.env', line=payload)
        assert len(output) >= 1

    def test_detect_in_env_production(self):
        """Should activate on .env.production files."""
        logic = EnvFileSecretDetector()
        output = logic.analyze_line(filename='.env.production', line='SECRET_KEY=abc123')
        assert len(output) >= 1

    def test_detect_quoted_values(self):
        """Should detect secrets in quoted values."""
        logic = EnvFileSecretDetector()
        output = logic.analyze_line(filename='.env', line='PASSWORD="hunter2"')
        assert len(output) >= 1

    def test_detect_single_quoted_values(self):
        """Should detect secrets in single-quoted values."""
        logic = EnvFileSecretDetector()
        output = logic.analyze_line(filename='.env', line="PASSWORD='hunter2'")
        assert len(output) >= 1

    # --- Negative cases: should NOT detect ---

    @pytest.mark.parametrize(
        'payload',
        [
            '# DATABASE_PASSWORD=hunter2',           # commented out
            '#SECRET_KEY=abc123',                     # commented out (no space)
            '',                                       # empty line
            'PASSWORD=',                              # empty value
            'PASSWORD= ',                             # whitespace-only value
            'SECRET_KEY=${MY_SECRET}',                # shell variable expansion
            'API_KEY=$API_KEY_FROM_ENV',              # shell variable reference
            'TOKEN=<your-token-here>',                # angle bracket placeholder
            'SECRET={{vault_secret}}',                # template placeholder
            'PASSWORD=TODO',                          # TODO marker
            'SECRET_KEY=CHANGEME',                    # CHANGEME placeholder
            'API_KEY=REPLACE_ME',                     # REPLACE_ME placeholder
            'TOKEN=YOUR_TOKEN_HERE',                  # YOUR_x_HERE placeholder
            'PASSWORD=xxxxxxxx',                      # xxx placeholder
            'SECRET=XXXXXXXX',                        # XXX placeholder
            'API_KEY=placeholder',                    # literal placeholder
            'TOKEN=dummy',                            # dummy value
            'SECRET=example',                         # example value
            'PASSWORD=test',                          # test value
            'API_KEY=fake',                           # fake value
            'TOKEN=mock',                             # mock value
            'DB_PASSWORD=none',                       # none value
            'SECRET=null',                            # null value
            'ENABLE_FEATURE=true',                    # boolean (non-sensitive key)
            'APP_NAME=my-cool-app',                   # non-sensitive key
            'PORT=3000',                              # non-sensitive key
            'NODE_ENV=production',                    # non-sensitive key
            'DEBUG=false',                            # non-sensitive key + boolean
        ],
    )
    def test_no_false_positives(self, payload):
        logic = EnvFileSecretDetector()
        output = logic.analyze_line(filename='.env', line=payload)
        assert len(output) == 0, f'Should NOT detect secret in: {payload}'

    def test_non_env_file_ignored(self):
        """Should not activate on non-.env files."""
        logic = EnvFileSecretDetector()
        output = logic.analyze_line(filename='config.py', line='PASSWORD=hunter2')
        assert len(output) == 0

    def test_non_env_js_file_ignored(self):
        """Should not activate on .js files."""
        logic = EnvFileSecretDetector()
        output = logic.analyze_line(filename='app.js', line='SECRET_KEY=abc123')
        assert len(output) == 0

    def test_non_env_yaml_file_ignored(self):
        """Should not activate on .yaml files."""
        logic = EnvFileSecretDetector()
        output = logic.analyze_line(filename='config.yaml', line='API_KEY=abc123')
        assert len(output) == 0

    def test_env_in_path_not_matched(self):
        """File named '.environment' should not match."""
        logic = EnvFileSecretDetector()
        output = logic.analyze_line(filename='.environment', line='PASSWORD=hunter2')
        assert len(output) == 0

    def test_secret_type(self):
        logic = EnvFileSecretDetector()
        assert logic.secret_type == 'Environment Variable Secret'

    def test_confidence_attribute(self):
        logic = EnvFileSecretDetector()
        assert logic.confidence == 0.70

    def test_path_with_directories(self):
        """Should work with full paths containing .env files."""
        logic = EnvFileSecretDetector()
        output = logic.analyze_line(
            filename='project/config/.env.local',
            line='DATABASE_PASSWORD=mydbpass123',
        )
        assert len(output) >= 1

    def test_path_with_directories_non_env(self):
        """Should not match .env as directory name."""
        logic = EnvFileSecretDetector()
        output = logic.analyze_line(
            filename='.env/config.py',
            line='DATABASE_PASSWORD=mydbpass123',
        )
        assert len(output) == 0
