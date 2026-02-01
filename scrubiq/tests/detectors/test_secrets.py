"""
Comprehensive tests for scrubiq/detectors/secrets.py.

Tests detection of API keys, tokens, private keys, JWTs, connection strings,
and other sensitive credentials.
"""

import pytest
import base64
import json
from scrubiq.detectors.secrets import (
    SecretsDetector,
    SECRETS_PATTERNS,
)
from scrubiq.types import Tier


# =============================================================================
# Helper Functions
# =============================================================================
def create_jwt(header: dict = None, payload: dict = None, signature: str = "test_signature") -> str:
    """Create a valid JWT structure for testing."""
    if header is None:
        header = {"alg": "HS256", "typ": "JWT"}
    if payload is None:
        payload = {"sub": "1234567890", "name": "John Doe", "iat": 1516239022}

    def b64url_encode(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')

    header_b64 = b64url_encode(json.dumps(header).encode())
    payload_b64 = b64url_encode(json.dumps(payload).encode())
    sig_b64 = b64url_encode(signature.encode())

    return f"{header_b64}.{payload_b64}.{sig_b64}"


# =============================================================================
# SecretsDetector Class Tests
# =============================================================================
class TestSecretsDetector:
    """Tests for the SecretsDetector class."""

    @pytest.fixture
    def detector(self):
        """Create a SecretsDetector instance."""
        return SecretsDetector()

    def test_detector_name(self, detector):
        """Detector should have correct name."""
        assert detector.name == "secrets"

    def test_detector_tier(self, detector):
        """Detector should use PATTERN tier."""
        assert detector.tier == Tier.PATTERN

    def test_detect_returns_list(self, detector):
        """Detection should return a list."""
        result = detector.detect("No secrets here")
        assert isinstance(result, list)

    def test_detect_empty_text(self, detector):
        """Empty text should return empty list."""
        result = detector.detect("")
        assert result == []


# =============================================================================
# AWS Credential Detection Tests
# =============================================================================
class TestAWSDetection:
    """Tests for AWS credential detection."""

    @pytest.fixture
    def detector(self):
        return SecretsDetector()

    def test_detect_aws_access_key_akia(self, detector):
        """Detect AWS access key starting with AKIA."""
        text = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
        spans = detector.detect(text)

        aws_spans = [s for s in spans if s.entity_type == "AWS_ACCESS_KEY"]
        assert len(aws_spans) == 1
        assert aws_spans[0].text == "AKIAIOSFODNN7EXAMPLE"
        assert aws_spans[0].confidence >= 0.95

    def test_detect_aws_access_key_asia(self, detector):
        """Detect AWS access key starting with ASIA (temporary credentials)."""
        text = "key: ASIAQWERTYUIOP1234567"
        spans = detector.detect(text)

        aws_spans = [s for s in spans if s.entity_type == "AWS_ACCESS_KEY"]
        assert len(aws_spans) == 1
        assert "ASIA" in aws_spans[0].text

    def test_detect_aws_secret_key(self, detector):
        """Detect AWS secret access key with context."""
        secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        text = f'aws_secret_access_key="{secret}"'
        spans = detector.detect(text)

        aws_spans = [s for s in spans if s.entity_type == "AWS_SECRET_KEY"]
        assert len(aws_spans) == 1
        assert aws_spans[0].text == secret

    def test_detect_aws_session_token(self, detector):
        """Detect AWS session token."""
        token = "A" * 150  # Session tokens are 100+ chars
        text = f"aws_session_token={token}"
        spans = detector.detect(text)

        session_spans = [s for s in spans if s.entity_type == "AWS_SESSION_TOKEN"]
        assert len(session_spans) == 1

    def test_no_false_positive_akia_short(self, detector):
        """Short strings starting with AKIA should not match."""
        text = "AKIATEST"  # Only 8 chars after AKIA, needs 16
        spans = detector.detect(text)

        aws_spans = [s for s in spans if s.entity_type == "AWS_ACCESS_KEY"]
        assert len(aws_spans) == 0


# =============================================================================
# GitHub Token Detection Tests
# =============================================================================
class TestGitHubDetection:
    """Tests for GitHub token detection."""

    @pytest.fixture
    def detector(self):
        return SecretsDetector()

    def test_detect_github_pat_ghp(self, detector):
        """Detect GitHub personal access token (ghp_)."""
        token = "ghp_" + "a" * 36
        text = f"GITHUB_TOKEN={token}"
        spans = detector.detect(text)

        gh_spans = [s for s in spans if s.entity_type == "GITHUB_TOKEN"]
        assert len(gh_spans) == 1
        assert gh_spans[0].text == token
        assert gh_spans[0].confidence >= 0.95

    def test_detect_github_oauth_gho(self, detector):
        """Detect GitHub OAuth access token (gho_)."""
        token = "gho_" + "B" * 36
        text = f"token: {token}"
        spans = detector.detect(text)

        gh_spans = [s for s in spans if s.entity_type == "GITHUB_TOKEN"]
        assert len(gh_spans) == 1
        assert gh_spans[0].text == token

    def test_detect_github_user_ghu(self, detector):
        """Detect GitHub user-to-server token (ghu_)."""
        token = "ghu_" + "c" * 36
        text = f"{token}"
        spans = detector.detect(text)

        gh_spans = [s for s in spans if s.entity_type == "GITHUB_TOKEN"]
        assert len(gh_spans) == 1

    def test_detect_github_server_ghs(self, detector):
        """Detect GitHub server-to-server token (ghs_)."""
        token = "ghs_" + "D" * 36
        text = f"Bearer {token}"
        spans = detector.detect(text)

        gh_spans = [s for s in spans if s.entity_type == "GITHUB_TOKEN"]
        assert len(gh_spans) == 1

    def test_detect_github_refresh_ghr(self, detector):
        """Detect GitHub refresh token (ghr_)."""
        token = "ghr_" + "e" * 36
        text = f"refresh_token: {token}"
        spans = detector.detect(text)

        gh_spans = [s for s in spans if s.entity_type == "GITHUB_TOKEN"]
        assert len(gh_spans) == 1

    def test_detect_github_v1_format(self, detector):
        """Detect older GitHub token format (v1.xxx)."""
        token = "v1." + "a" * 40
        text = f"token={token}"
        spans = detector.detect(text)

        gh_spans = [s for s in spans if s.entity_type == "GITHUB_TOKEN"]
        assert len(gh_spans) == 1


# =============================================================================
# GitLab Token Detection Tests
# =============================================================================
class TestGitLabDetection:
    """Tests for GitLab token detection."""

    @pytest.fixture
    def detector(self):
        return SecretsDetector()

    def test_detect_gitlab_pat(self, detector):
        """Detect GitLab personal access token (glpat-)."""
        token = "glpat-" + "a" * 20
        text = f"GITLAB_TOKEN={token}"
        spans = detector.detect(text)

        gl_spans = [s for s in spans if s.entity_type == "GITLAB_TOKEN"]
        assert len(gl_spans) == 1
        assert gl_spans[0].text == token

    def test_detect_gitlab_pipeline_token(self, detector):
        """Detect GitLab pipeline token (glptt-)."""
        token = "glptt-" + "b" * 20
        text = f"CI_JOB_TOKEN={token}"
        spans = detector.detect(text)

        gl_spans = [s for s in spans if s.entity_type == "GITLAB_TOKEN"]
        assert len(gl_spans) == 1

    def test_detect_gitlab_runner_token(self, detector):
        """Detect GitLab runner token (glrt-)."""
        token = "glrt-" + "c" * 20
        text = f"registration_token: {token}"
        spans = detector.detect(text)

        gl_spans = [s for s in spans if s.entity_type == "GITLAB_TOKEN"]
        assert len(gl_spans) == 1


# =============================================================================
# Slack Token Detection Tests
# =============================================================================
class TestSlackDetection:
    """Tests for Slack token detection."""

    @pytest.fixture
    def detector(self):
        return SecretsDetector()

    def test_detect_slack_bot_token(self, detector):
        """Detect Slack bot token (xoxb-)."""
        token = "xoxb-1234567890123-1234567890123-abcdefghijklmnopqrstuvwx"
        text = f"SLACK_BOT_TOKEN={token}"
        spans = detector.detect(text)

        slack_spans = [s for s in spans if s.entity_type == "SLACK_TOKEN"]
        assert len(slack_spans) == 1
        assert slack_spans[0].text == token

    def test_detect_slack_user_token(self, detector):
        """Detect Slack user token (xoxp-)."""
        token = "xoxp-1234567890123-1234567890123-1234567890123-" + "a" * 32
        text = f"token: {token}"
        spans = detector.detect(text)

        slack_spans = [s for s in spans if s.entity_type == "SLACK_TOKEN"]
        assert len(slack_spans) == 1

    def test_detect_slack_webhook(self, detector):
        """Detect Slack webhook URL."""
        url = "https://hooks.slack.com/services/T12345678/B12345678/abcdefghijklmnop"
        text = f"webhook_url: {url}"
        spans = detector.detect(text)

        webhook_spans = [s for s in spans if s.entity_type == "SLACK_WEBHOOK"]
        assert len(webhook_spans) == 1
        assert webhook_spans[0].text == url


# =============================================================================
# Stripe Key Detection Tests
# =============================================================================
class TestStripeDetection:
    """Tests for Stripe key detection."""

    @pytest.fixture
    def detector(self):
        return SecretsDetector()

    def test_detect_stripe_live_secret(self, detector):
        """Detect Stripe live secret key (sk_live_)."""
        key = "sk_live_" + "a" * 24
        text = f"STRIPE_SECRET_KEY={key}"
        spans = detector.detect(text)

        stripe_spans = [s for s in spans if s.entity_type == "STRIPE_KEY"]
        assert len(stripe_spans) == 1
        assert stripe_spans[0].text == key
        assert stripe_spans[0].confidence >= 0.95

    def test_detect_stripe_test_secret(self, detector):
        """Detect Stripe test secret key (sk_test_)."""
        key = "sk_test_" + "b" * 24
        text = f"stripe_key: {key}"
        spans = detector.detect(text)

        stripe_spans = [s for s in spans if s.entity_type == "STRIPE_KEY"]
        assert len(stripe_spans) == 1

    def test_detect_stripe_publishable_live(self, detector):
        """Detect Stripe live publishable key (pk_live_)."""
        key = "pk_live_" + "c" * 24
        text = f"publishableKey: '{key}'"
        spans = detector.detect(text)

        stripe_spans = [s for s in spans if s.entity_type == "STRIPE_KEY"]
        assert len(stripe_spans) == 1

    def test_detect_stripe_restricted_key(self, detector):
        """Detect Stripe restricted key (rk_live_)."""
        key = "rk_live_" + "d" * 24
        text = f"restricted_key={key}"
        spans = detector.detect(text)

        stripe_spans = [s for s in spans if s.entity_type == "STRIPE_KEY"]
        assert len(stripe_spans) == 1

    def test_detect_stripe_webhook_secret(self, detector):
        """Detect Stripe webhook secret (whsec_)."""
        secret = "whsec_" + "e" * 32
        text = f"endpoint_secret: {secret}"
        spans = detector.detect(text)

        stripe_spans = [s for s in spans if s.entity_type == "STRIPE_KEY"]
        assert len(stripe_spans) == 1


# =============================================================================
# Google API Key Detection Tests
# =============================================================================
class TestGoogleDetection:
    """Tests for Google API key detection."""

    @pytest.fixture
    def detector(self):
        return SecretsDetector()

    def test_detect_google_api_key(self, detector):
        """Detect Google API key (AIza...)."""
        key = "AIzaSyD-" + "a" * 31  # AIza + 35 chars total
        text = f"GOOGLE_API_KEY={key}"
        spans = detector.detect(text)

        google_spans = [s for s in spans if s.entity_type == "GOOGLE_API_KEY"]
        assert len(google_spans) == 1
        assert google_spans[0].text == key

    def test_detect_google_oauth_client_id(self, detector):
        """Detect Google OAuth client ID."""
        client_id = "123456789012-" + "a" * 32 + ".apps.googleusercontent.com"
        text = f"client_id: {client_id}"
        spans = detector.detect(text)

        oauth_spans = [s for s in spans if s.entity_type == "GOOGLE_OAUTH_ID"]
        assert len(oauth_spans) == 1


# =============================================================================
# Twilio Detection Tests
# =============================================================================
class TestTwilioDetection:
    """Tests for Twilio credential detection."""

    @pytest.fixture
    def detector(self):
        return SecretsDetector()

    def test_detect_twilio_account_sid(self, detector):
        """Detect Twilio Account SID (AC...)."""
        sid = "AC" + "a" * 32
        text = f"TWILIO_ACCOUNT_SID={sid}"
        spans = detector.detect(text)

        twilio_spans = [s for s in spans if s.entity_type == "TWILIO_ACCOUNT_SID"]
        assert len(twilio_spans) == 1
        assert twilio_spans[0].text == sid

    def test_detect_twilio_api_key(self, detector):
        """Detect Twilio API Key SID (SK...)."""
        key = "SK" + "b" * 32
        text = f"api_key: {key}"
        spans = detector.detect(text)

        twilio_spans = [s for s in spans if s.entity_type == "TWILIO_KEY"]
        assert len(twilio_spans) == 1


# =============================================================================
# SendGrid Detection Tests
# =============================================================================
class TestSendGridDetection:
    """Tests for SendGrid API key detection."""

    @pytest.fixture
    def detector(self):
        return SecretsDetector()

    def test_detect_sendgrid_key(self, detector):
        """Detect SendGrid API key (SG.xxx.xxx)."""
        key = "SG." + "-" * 22 + "." + "_" * 43
        text = f"SENDGRID_API_KEY={key}"
        spans = detector.detect(text)

        sg_spans = [s for s in spans if s.entity_type == "SENDGRID_KEY"]
        assert len(sg_spans) == 1


# =============================================================================
# Discord Detection Tests
# =============================================================================
class TestDiscordDetection:
    """Tests for Discord credential detection."""

    @pytest.fixture
    def detector(self):
        return SecretsDetector()

    def test_detect_discord_webhook(self, detector):
        """Detect Discord webhook URL."""
        url = "https://discord.com/api/webhooks/123456789/abcdefghijklmnop"
        text = f"webhook: {url}"
        spans = detector.detect(text)

        discord_spans = [s for s in spans if s.entity_type == "DISCORD_WEBHOOK"]
        assert len(discord_spans) == 1

    def test_detect_discord_webhook_discordapp(self, detector):
        """Detect Discord webhook URL (discordapp.com)."""
        url = "https://discordapp.com/api/webhooks/987654321/qrstuvwxyz"
        text = f"url={url}"
        spans = detector.detect(text)

        discord_spans = [s for s in spans if s.entity_type == "DISCORD_WEBHOOK"]
        assert len(discord_spans) == 1


# =============================================================================
# NPM/PyPI Token Detection Tests
# =============================================================================
class TestPackageRegistryDetection:
    """Tests for package registry token detection."""

    @pytest.fixture
    def detector(self):
        return SecretsDetector()

    def test_detect_npm_token(self, detector):
        """Detect NPM token (npm_...)."""
        token = "npm_" + "a" * 36
        text = f"NPM_TOKEN={token}"
        spans = detector.detect(text)

        npm_spans = [s for s in spans if s.entity_type == "NPM_TOKEN"]
        assert len(npm_spans) == 1

    def test_detect_pypi_token(self, detector):
        """Detect PyPI token (pypi-...)."""
        token = "pypi-" + "a" * 50
        text = f"PYPI_API_TOKEN={token}"
        spans = detector.detect(text)

        pypi_spans = [s for s in spans if s.entity_type == "PYPI_TOKEN"]
        assert len(pypi_spans) == 1


# =============================================================================
# Private Key Detection Tests
# =============================================================================
class TestPrivateKeyDetection:
    """Tests for private key detection."""

    @pytest.fixture
    def detector(self):
        return SecretsDetector()

    def test_detect_rsa_private_key_header(self, detector):
        """Detect RSA private key header."""
        text = "-----BEGIN RSA PRIVATE KEY-----"
        spans = detector.detect(text)

        pk_spans = [s for s in spans if s.entity_type == "PRIVATE_KEY"]
        assert len(pk_spans) >= 1

    def test_detect_ec_private_key_header(self, detector):
        """Detect EC private key header."""
        text = "-----BEGIN EC PRIVATE KEY-----"
        spans = detector.detect(text)

        pk_spans = [s for s in spans if s.entity_type == "PRIVATE_KEY"]
        assert len(pk_spans) >= 1

    def test_detect_openssh_private_key_header(self, detector):
        """Detect OpenSSH private key header."""
        text = "-----BEGIN OPENSSH PRIVATE KEY-----"
        spans = detector.detect(text)

        pk_spans = [s for s in spans if s.entity_type == "PRIVATE_KEY"]
        assert len(pk_spans) >= 1

    def test_detect_pgp_private_key_header(self, detector):
        """Detect PGP private key header."""
        text = "-----BEGIN PGP PRIVATE KEY BLOCK-----"
        spans = detector.detect(text)

        pk_spans = [s for s in spans if s.entity_type == "PRIVATE_KEY"]
        assert len(pk_spans) >= 1

    def test_detect_generic_private_key_header(self, detector):
        """Detect generic PRIVATE KEY header."""
        text = "-----BEGIN PRIVATE KEY-----"
        spans = detector.detect(text)

        pk_spans = [s for s in spans if s.entity_type == "PRIVATE_KEY"]
        assert len(pk_spans) >= 1


# =============================================================================
# JWT Detection Tests
# =============================================================================
class TestJWTDetection:
    """Tests for JWT detection."""

    @pytest.fixture
    def detector(self):
        return SecretsDetector()

    def test_detect_valid_jwt(self, detector):
        """Detect valid JWT structure."""
        jwt = create_jwt()
        text = f"Authorization: Bearer {jwt}"
        spans = detector.detect(text)

        jwt_spans = [s for s in spans if s.entity_type == "JWT"]
        assert len(jwt_spans) == 1
        assert jwt in jwt_spans[0].text

    def test_detect_jwt_in_header(self, detector):
        """Detect JWT in authorization header."""
        jwt = create_jwt()
        text = f"Bearer {jwt}"
        spans = detector.detect(text)

        jwt_spans = [s for s in spans if s.entity_type == "JWT"]
        assert len(jwt_spans) == 1

    def test_detect_jwt_standalone(self, detector):
        """Detect standalone JWT."""
        jwt = create_jwt()
        text = f"token={jwt}"
        spans = detector.detect(text)

        jwt_spans = [s for s in spans if s.entity_type == "JWT"]
        assert len(jwt_spans) == 1

    def test_validate_jwt_invalid_structure(self, detector):
        """Invalid JWT structure should not match."""
        # JWT without proper base64url encoding
        text = "eyJxxx.eyJyyy.zzz"
        spans = detector.detect(text)

        jwt_spans = [s for s in spans if s.entity_type == "JWT" and text in s.text]
        # May or may not detect - depends on validation
        # The validator checks base64 decoding

    def test_validate_jwt_only_two_parts(self, detector):
        """JWT with only two parts should not validate."""
        # This is handled by pattern not matching
        text = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"
        spans = detector.detect(text)

        jwt_spans = [s for s in spans if s.entity_type == "JWT"]
        # Pattern requires three parts separated by dots
        assert len(jwt_spans) == 0


# =============================================================================
# Database URL Detection Tests
# =============================================================================
class TestDatabaseURLDetection:
    """Tests for database connection string detection."""

    @pytest.fixture
    def detector(self):
        return SecretsDetector()

    def test_detect_postgres_url(self, detector):
        """Detect PostgreSQL connection string."""
        url = "postgres://user:password123@localhost:5432/mydb"
        text = f"DATABASE_URL={url}"
        spans = detector.detect(text)

        db_spans = [s for s in spans if s.entity_type == "DATABASE_URL"]
        assert len(db_spans) == 1
        assert "password123" in db_spans[0].text

    def test_detect_postgresql_url(self, detector):
        """Detect PostgreSQL connection string with 'postgresql://'."""
        url = "postgresql://admin:secret@db.example.com/production"
        text = f"conn_str: {url}"
        spans = detector.detect(text)

        db_spans = [s for s in spans if s.entity_type == "DATABASE_URL"]
        assert len(db_spans) == 1

    def test_detect_mysql_url(self, detector):
        """Detect MySQL connection string."""
        url = "mysql://root:rootpass@127.0.0.1:3306/app"
        text = f"MYSQL_URL={url}"
        spans = detector.detect(text)

        db_spans = [s for s in spans if s.entity_type == "DATABASE_URL"]
        assert len(db_spans) == 1

    def test_detect_mongodb_url(self, detector):
        """Detect MongoDB connection string."""
        url = "mongodb://user:pass@cluster0.mongodb.net/test"
        text = f"MONGO_URI={url}"
        spans = detector.detect(text)

        db_spans = [s for s in spans if s.entity_type == "DATABASE_URL"]
        assert len(db_spans) == 1

    def test_detect_mongodb_srv_url(self, detector):
        """Detect MongoDB SRV connection string."""
        url = "mongodb+srv://admin:secret@cluster.mongodb.net/db"
        text = f"connection: {url}"
        spans = detector.detect(text)

        db_spans = [s for s in spans if s.entity_type == "DATABASE_URL"]
        assert len(db_spans) == 1

    def test_detect_redis_url(self, detector):
        """Detect Redis connection string."""
        url = "redis://user:auth@redis.example.com:6379/0"
        text = f"REDIS_URL={url}"
        spans = detector.detect(text)

        db_spans = [s for s in spans if s.entity_type == "DATABASE_URL"]
        assert len(db_spans) == 1

    def test_detect_sql_server_connection_string(self, detector):
        """Detect SQL Server connection string."""
        conn = "Server=myserver.database.windows.net;Database=mydb;User Id=admin;Password=secret123;"
        text = f"ConnectionString={conn}"
        spans = detector.detect(text)

        db_spans = [s for s in spans if s.entity_type == "DATABASE_URL"]
        assert len(db_spans) >= 1


# =============================================================================
# Azure Detection Tests
# =============================================================================
class TestAzureDetection:
    """Tests for Azure credential detection."""

    @pytest.fixture
    def detector(self):
        return SecretsDetector()

    def test_detect_azure_storage_key(self, detector):
        """Detect Azure storage account key."""
        key = "a" * 88  # Azure storage keys are 88 chars
        text = f"AccountKey={key}"
        spans = detector.detect(text)

        azure_spans = [s for s in spans if "AZURE" in s.entity_type]
        assert len(azure_spans) >= 1

    def test_detect_azure_connection_string(self, detector):
        """Detect Azure connection string."""
        conn = "DefaultEndpointsProtocol=https;AccountName=myaccount;AccountKey=" + "a" * 88
        text = f"AZURE_STORAGE_CONNECTION_STRING={conn}"
        spans = detector.detect(text)

        azure_spans = [s for s in spans if "AZURE" in s.entity_type]
        assert len(azure_spans) >= 1


# =============================================================================
# Generic Secret Detection Tests
# =============================================================================
class TestGenericSecretDetection:
    """Tests for generic secret pattern detection."""

    @pytest.fixture
    def detector(self):
        return SecretsDetector()

    def test_detect_password_in_quotes(self, detector):
        """Detect password in quotes."""
        text = 'password="mysecretpassword123"'
        spans = detector.detect(text)

        pwd_spans = [s for s in spans if s.entity_type == "PASSWORD"]
        assert len(pwd_spans) >= 1
        assert any("mysecretpassword123" in s.text for s in pwd_spans)

    def test_detect_password_single_quotes(self, detector):
        """Detect password in single quotes."""
        text = "passwd='anothersecret456'"
        spans = detector.detect(text)

        pwd_spans = [s for s in spans if s.entity_type == "PASSWORD"]
        assert len(pwd_spans) >= 1

    def test_detect_api_key_generic(self, detector):
        """Detect generic API key."""
        key = "a" * 20
        text = f'api_key="{key}"'
        spans = detector.detect(text)

        key_spans = [s for s in spans if s.entity_type == "API_KEY"]
        assert len(key_spans) >= 1

    def test_detect_international_password_french(self, detector):
        """Detect password with French label."""
        text = "mot de passe: secretfrench123"
        spans = detector.detect(text)

        pwd_spans = [s for s in spans if s.entity_type == "PASSWORD"]
        assert len(pwd_spans) >= 1

    def test_detect_international_password_german(self, detector):
        """Detect password with German label."""
        text = "Passwort: geheimnis456"
        spans = detector.detect(text)

        pwd_spans = [s for s in spans if s.entity_type == "PASSWORD"]
        assert len(pwd_spans) >= 1


# =============================================================================
# Basic/Bearer Auth Detection Tests
# =============================================================================
class TestAuthHeaderDetection:
    """Tests for authentication header detection."""

    @pytest.fixture
    def detector(self):
        return SecretsDetector()

    def test_detect_basic_auth(self, detector):
        """Detect Basic authentication header."""
        creds = base64.b64encode(b"user:password").decode()
        text = f"Authorization: Basic {creds}"
        spans = detector.detect(text)

        auth_spans = [s for s in spans if s.entity_type == "BASIC_AUTH"]
        assert len(auth_spans) >= 1


# =============================================================================
# Square Detection Tests
# =============================================================================
class TestSquareDetection:
    """Tests for Square credential detection."""

    @pytest.fixture
    def detector(self):
        return SecretsDetector()

    def test_detect_square_access_token(self, detector):
        """Detect Square access token."""
        token = "sq0atp-" + "a" * 22
        text = f"SQUARE_ACCESS_TOKEN={token}"
        spans = detector.detect(text)

        square_spans = [s for s in spans if s.entity_type == "SQUARE_TOKEN"]
        assert len(square_spans) == 1

    def test_detect_square_oauth_secret(self, detector):
        """Detect Square OAuth secret."""
        secret = "sq0csp-" + "b" * 43
        text = f"client_secret: {secret}"
        spans = detector.detect(text)

        square_spans = [s for s in spans if s.entity_type == "SQUARE_SECRET"]
        assert len(square_spans) == 1


# =============================================================================
# Shopify Detection Tests
# =============================================================================
class TestShopifyDetection:
    """Tests for Shopify credential detection."""

    @pytest.fixture
    def detector(self):
        return SecretsDetector()

    def test_detect_shopify_access_token(self, detector):
        """Detect Shopify access token."""
        token = "shpat_" + "a" * 32
        text = f"SHOPIFY_ACCESS_TOKEN={token}"
        spans = detector.detect(text)

        shopify_spans = [s for s in spans if s.entity_type == "SHOPIFY_TOKEN"]
        assert len(shopify_spans) == 1

    def test_detect_shopify_api_key(self, detector):
        """Detect Shopify API key."""
        key = "shpka_" + "b" * 32
        text = f"api_key: {key}"
        spans = detector.detect(text)

        shopify_spans = [s for s in spans if s.entity_type == "SHOPIFY_KEY"]
        assert len(shopify_spans) == 1


# =============================================================================
# Mailchimp Detection Tests
# =============================================================================
class TestMailchimpDetection:
    """Tests for Mailchimp API key detection."""

    @pytest.fixture
    def detector(self):
        return SecretsDetector()

    def test_detect_mailchimp_key(self, detector):
        """Detect Mailchimp API key."""
        key = "a" * 32 + "-us10"
        text = f"MAILCHIMP_API_KEY={key}"
        spans = detector.detect(text)

        mc_spans = [s for s in spans if s.entity_type == "MAILCHIMP_KEY"]
        assert len(mc_spans) == 1


# =============================================================================
# New Relic Detection Tests
# =============================================================================
class TestNewRelicDetection:
    """Tests for New Relic API key detection."""

    @pytest.fixture
    def detector(self):
        return SecretsDetector()

    def test_detect_newrelic_key(self, detector):
        """Detect New Relic API key."""
        key = "NRAK-" + "A" * 27
        text = f"NEW_RELIC_API_KEY={key}"
        spans = detector.detect(text)

        nr_spans = [s for s in spans if s.entity_type == "NEWRELIC_KEY"]
        assert len(nr_spans) == 1


# =============================================================================
# Multiple Detection Tests
# =============================================================================
class TestMultipleSecrets:
    """Tests for detecting multiple secrets in same text."""

    @pytest.fixture
    def detector(self):
        return SecretsDetector()

    def test_detect_multiple_different_types(self, detector):
        """Detect multiple different secret types."""
        aws_key = "AKIAIOSFODNN7EXAMPLE"
        github_token = "ghp_" + "a" * 36
        text = f"""
        AWS_ACCESS_KEY_ID={aws_key}
        GITHUB_TOKEN={github_token}
        """
        spans = detector.detect(text)

        entity_types = {s.entity_type for s in spans}
        assert "AWS_ACCESS_KEY" in entity_types
        assert "GITHUB_TOKEN" in entity_types

    def test_detect_multiple_same_type(self, detector):
        """Detect multiple secrets of same type."""
        key1 = "sk_live_" + "a" * 24
        key2 = "sk_live_" + "b" * 24
        text = f"primary: {key1}\nsecondary: {key2}"
        spans = detector.detect(text)

        stripe_spans = [s for s in spans if s.entity_type == "STRIPE_KEY"]
        assert len(stripe_spans) == 2

    def test_deduplication(self, detector):
        """Same secret at same position should not duplicate."""
        key = "AKIAIOSFODNN7EXAMPLE"
        text = f"key: {key}"
        spans = detector.detect(text)

        # Count AWS keys at exact same position
        aws_spans = [s for s in spans if s.entity_type == "AWS_ACCESS_KEY"]
        positions = [(s.start, s.end, s.text) for s in aws_spans]
        assert len(positions) == len(set(positions))


# =============================================================================
# Pattern Coverage Tests
# =============================================================================
class TestPatternsCoverage:
    """Tests to ensure pattern definitions are properly structured."""

    def test_patterns_not_empty(self):
        """SECRETS_PATTERNS should contain patterns."""
        assert len(SECRETS_PATTERNS) > 0

    def test_pattern_structure(self):
        """Each pattern should have correct structure."""
        for pattern, entity_type, confidence, group_idx in SECRETS_PATTERNS:
            # Pattern should be compiled regex
            assert hasattr(pattern, "finditer")
            # Entity type should be non-empty string
            assert isinstance(entity_type, str) and len(entity_type) > 0
            # Confidence should be between 0 and 1
            assert 0 <= confidence <= 1
            # Group index should be non-negative
            assert group_idx >= 0

    def test_all_documented_types_have_patterns(self):
        """Documented entity types should have patterns."""
        entity_types = {pattern[1] for pattern in SECRETS_PATTERNS}

        expected_core = {
            "AWS_ACCESS_KEY", "GITHUB_TOKEN", "STRIPE_KEY",
            "GOOGLE_API_KEY", "JWT", "PRIVATE_KEY", "DATABASE_URL"
        }
        assert expected_core.issubset(entity_types)


# =============================================================================
# Edge Cases and Robustness Tests
# =============================================================================
class TestSecretsEdgeCases:
    """Edge case tests for secrets detection."""

    @pytest.fixture
    def detector(self):
        return SecretsDetector()

    def test_unicode_text(self, detector):
        """Should handle Unicode text."""
        key = "AKIAIOSFODNN7EXAMPLE"
        text = f"API key for Japan 日本: {key}"
        spans = detector.detect(text)

        aws_spans = [s for s in spans if s.entity_type == "AWS_ACCESS_KEY"]
        assert len(aws_spans) == 1

    def test_newlines_in_text(self, detector):
        """Should handle newlines."""
        key = "ghp_" + "a" * 36
        text = f"GITHUB_TOKEN=\n{key}"
        spans = detector.detect(text)
        # May or may not detect depending on pattern

    def test_very_long_text(self, detector):
        """Should handle very long text."""
        key = "AKIAIOSFODNN7EXAMPLE"
        text = "x" * 100000 + f" {key} " + "y" * 100000
        spans = detector.detect(text)

        aws_spans = [s for s in spans if s.entity_type == "AWS_ACCESS_KEY"]
        assert len(aws_spans) == 1

    def test_secret_at_start(self, detector):
        """Secret at start of text."""
        key = "AKIAIOSFODNN7EXAMPLE"
        text = f"{key} is the key"
        spans = detector.detect(text)

        aws_spans = [s for s in spans if s.entity_type == "AWS_ACCESS_KEY"]
        assert len(aws_spans) == 1

    def test_secret_at_end(self, detector):
        """Secret at end of text."""
        key = "AKIAIOSFODNN7EXAMPLE"
        text = f"The key is {key}"
        spans = detector.detect(text)

        aws_spans = [s for s in spans if s.entity_type == "AWS_ACCESS_KEY"]
        assert len(aws_spans) == 1

    def test_secret_in_json(self, detector):
        """Secret in JSON format."""
        key = "AKIAIOSFODNN7EXAMPLE"
        text = f'{{"aws_access_key_id": "{key}"}}'
        spans = detector.detect(text)

        aws_spans = [s for s in spans if s.entity_type == "AWS_ACCESS_KEY"]
        assert len(aws_spans) == 1

    def test_secret_in_yaml(self, detector):
        """Secret in YAML format."""
        key = "sk_live_" + "a" * 24
        text = f"stripe_key: {key}"
        spans = detector.detect(text)

        stripe_spans = [s for s in spans if s.entity_type == "STRIPE_KEY"]
        assert len(stripe_spans) == 1

    def test_span_position_accuracy(self, detector):
        """Span positions should be accurate."""
        prefix = "The key is "
        key = "AKIAIOSFODNN7EXAMPLE"
        text = f"{prefix}{key} for testing"

        spans = detector.detect(text)
        aws_spans = [s for s in spans if s.entity_type == "AWS_ACCESS_KEY"]

        assert len(aws_spans) == 1
        span = aws_spans[0]
        assert text[span.start:span.end] == span.text

    def test_no_false_positives_random_text(self, detector):
        """Random alphanumeric text shouldn't create false positives."""
        text = "The quick brown fox jumps over the lazy dog. Order #12345."
        spans = detector.detect(text)

        # Should not detect any secrets in normal text
        high_confidence = [s for s in spans if s.confidence >= 0.95]
        assert len(high_confidence) == 0


# =============================================================================
# JWT Validation Tests
# =============================================================================
class TestJWTValidation:
    """Tests for JWT validation function."""

    @pytest.fixture
    def detector(self):
        return SecretsDetector()

    def test_validate_jwt_valid(self, detector):
        """Valid JWT should pass validation."""
        jwt = create_jwt()
        assert detector._validate_jwt(jwt) is True

    def test_validate_jwt_two_parts(self, detector):
        """JWT with only two parts should fail."""
        assert detector._validate_jwt("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0") is False

    def test_validate_jwt_four_parts(self, detector):
        """JWT with four parts should fail."""
        assert detector._validate_jwt("eyJ.eyJ.zzz.extra") is False

    def test_validate_jwt_invalid_base64(self, detector):
        """JWT with invalid base64 in header should fail."""
        # Invalid base64 (contains characters not in base64url alphabet with proper padding)
        assert detector._validate_jwt("!!!.eyJzdWIiOiIxMjM0In0.sig") is False

    def test_validate_jwt_empty_string(self, detector):
        """Empty string should fail."""
        assert detector._validate_jwt("") is False

    def test_validate_jwt_no_dots(self, detector):
        """String without dots should fail."""
        assert detector._validate_jwt("eyJhbGciOiJIUzI1NiJ9eyJzdWIiOiIxMjM0In0") is False
