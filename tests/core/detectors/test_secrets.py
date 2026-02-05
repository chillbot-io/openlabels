"""
Comprehensive tests for the Secrets Detector.

Tests detection of API keys, tokens, private keys, JWTs, connection strings,
and other sensitive credentials that should never be exposed.

Entity Types tested:
- AWS_ACCESS_KEY, AWS_SECRET_KEY, AWS_SESSION_TOKEN
- GITHUB_TOKEN, GITLAB_TOKEN
- SLACK_TOKEN, SLACK_WEBHOOK
- STRIPE_KEY, GOOGLE_API_KEY
- TWILIO_KEY, SENDGRID_KEY
- DISCORD_TOKEN, DISCORD_WEBHOOK
- NPM_TOKEN, PYPI_TOKEN
- PRIVATE_KEY, JWT, BEARER_TOKEN
- DATABASE_URL, AZURE_KEY

NOTE: Test tokens in this file are intentionally fake/invalid.
They are constructed using string concatenation to avoid triggering
secret scanning tools while still testing pattern detection.
"""

import pytest
from openlabels.core.detectors.secrets import SecretsDetector
from openlabels.core.types import Tier


# =============================================================================
# TEST TOKEN BUILDERS - Construct fake tokens to avoid secret scanner detection
# =============================================================================
# These helpers build test tokens by concatenating parts so scanners don't
# see complete token patterns in the source code.

def _fake_stripe_key(prefix: str) -> str:
    """Build fake Stripe key: prefix + 25 chars."""
    return prefix + "FAKETEST" + "0" * 17

def _fake_slack_token(prefix: str) -> str:
    """Build fake Slack token."""
    return prefix + "FAKE" + "0" * 9 + "-" + "FAKE" + "0" * 9 + "-" + "FAKETEST" + "0" * 12

def _fake_twilio_sid(prefix: str) -> str:
    """Build fake Twilio SID: prefix + 32 chars."""
    return prefix + "FAKETEST" + "0" * 24

def _fake_github_token(prefix: str) -> str:
    """Build fake GitHub token: prefix + 36 chars."""
    return prefix + "FAKETEST" + "0" * 28

def _fake_discord_token() -> str:
    """Build fake Discord bot token."""
    # Format: [MN]{23+}.{6}.{27+} - must start with M or N
    return "M" + "T" * 23 + "." + "abcdef" + "." + "a" * 27

def _fake_shopify_token(prefix: str) -> str:
    """Build fake Shopify token: prefix + 32 lowercase hex."""
    return prefix + "abcdef0123456789abcdef0123456789"

def _fake_square_token(prefix: str) -> str:
    """Build fake Square token."""
    if "csp" in prefix:
        # sq0csp- needs 43 chars
        return prefix + "abcdefghij0123456789abcdefghij0123456789abc"
    # sq0atp- needs 22 chars
    return prefix + "abcdefghij0123456789ab"

def _fake_mailchimp_key() -> str:
    """Build fake Mailchimp API key: 32 lowercase hex + -us{1-2 digits}."""
    return "abcdef0123456789abcdef0123456789" + "-us01"


# =============================================================================
# DETECTOR INITIALIZATION TESTS
# =============================================================================

class TestSecretsDetectorInit:
    """Test detector initialization and configuration."""

    @pytest.fixture
    def detector(self):
        """Create a SecretsDetector instance."""
        return SecretsDetector()

    def test_detector_name(self, detector):
        """Test detector has correct name."""
        assert detector.name == "secrets"

    def test_detector_tier(self, detector):
        """Test detector uses PATTERN tier."""
        assert detector.tier == Tier.PATTERN

    def test_detector_is_available(self, detector):
        """Test detector reports availability."""
        assert detector.is_available() is True


# =============================================================================
# AWS CREDENTIAL TESTS
# =============================================================================

class TestAWSCredentials:
    """Test detection of AWS credentials."""

    @pytest.fixture
    def detector(self):
        return SecretsDetector()

    def test_detect_aws_access_key_akia(self, detector):
        """Test AWS access key ID with AKIA prefix."""
        text = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
        spans = detector.detect(text)

        aws_spans = [s for s in spans if s.entity_type == "AWS_ACCESS_KEY"]
        assert len(aws_spans) >= 1
        assert any(s.text == "AKIAIOSFODNN7EXAMPLE" for s in aws_spans)

    def test_detect_aws_access_key_asia(self, detector):
        """Test AWS temporary access key with ASIA prefix."""
        text = "temp_key=ASIAWXYZABCD12345678"
        spans = detector.detect(text)

        aws_spans = [s for s in spans if s.entity_type == "AWS_ACCESS_KEY"]
        assert len(aws_spans) >= 1
        assert any(s.text.startswith("ASIA") for s in aws_spans)

    def test_detect_aws_access_key_aida(self, detector):
        """Test AWS IAM user access key with AIDA prefix."""
        text = "IAM user key: AIDAEXAMPLEUSER12345"
        spans = detector.detect(text)

        aws_spans = [s for s in spans if s.entity_type == "AWS_ACCESS_KEY"]
        assert len(aws_spans) >= 1

    def test_detect_aws_access_key_agpa(self, detector):
        """Test AWS group access key with AGPA prefix."""
        # AGPA prefix + 16 chars = 20 total
        text = "group_id=AGPA1234567890ABCDEF"
        spans = detector.detect(text)

        aws_spans = [s for s in spans if s.entity_type == "AWS_ACCESS_KEY"]
        assert len(aws_spans) >= 1

    def test_detect_aws_secret_key_labeled(self, detector):
        """Test AWS secret key with label."""
        text = "aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        spans = detector.detect(text)

        secret_spans = [s for s in spans if s.entity_type == "AWS_SECRET_KEY"]
        assert len(secret_spans) >= 1

    def test_detect_aws_secret_key_json_format(self, detector):
        """Test AWS secret key in JSON format."""
        text = '"secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"'
        spans = detector.detect(text)

        secret_spans = [s for s in spans if s.entity_type == "AWS_SECRET_KEY"]
        assert len(secret_spans) >= 1

    def test_detect_aws_session_token(self, detector):
        """Test AWS session token detection."""
        token = "A" * 150  # Session tokens are 100+ chars
        text = f"aws_session_token={token}"
        spans = detector.detect(text)

        session_spans = [s for s in spans if s.entity_type == "AWS_SESSION_TOKEN"]
        assert len(session_spans) >= 1

    def test_aws_key_high_confidence(self, detector):
        """Test AWS access key has high confidence."""
        text = "AKIAIOSFODNN7EXAMPLE"
        spans = detector.detect(text)

        aws_spans = [s for s in spans if s.entity_type == "AWS_ACCESS_KEY"]
        assert len(aws_spans) >= 1
        assert all(s.confidence >= 0.95 for s in aws_spans)

    def test_aws_key_in_config_file(self, detector):
        """Test AWS key detection in config file format."""
        text = """[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"""
        spans = detector.detect(text)

        aws_access_spans = [s for s in spans if s.entity_type == "AWS_ACCESS_KEY"]
        aws_secret_spans = [s for s in spans if s.entity_type == "AWS_SECRET_KEY"]

        assert len(aws_access_spans) >= 1
        assert len(aws_secret_spans) >= 1


# =============================================================================
# GITHUB TOKEN TESTS
# =============================================================================

class TestGitHubTokens:
    """Test detection of GitHub tokens."""

    @pytest.fixture
    def detector(self):
        return SecretsDetector()

    def test_detect_github_pat_ghp(self, detector):
        """Test GitHub Personal Access Token (classic) with ghp_ prefix."""
        text = "GITHUB_TOKEN=" + _fake_github_token("ghp_") + ""
        spans = detector.detect(text)

        gh_spans = [s for s in spans if s.entity_type == "GITHUB_TOKEN"]
        assert len(gh_spans) >= 1
        assert any(s.text.startswith("ghp_") for s in gh_spans)

    def test_detect_github_oauth_token_gho(self, detector):
        """Test GitHub OAuth access token with gho_ prefix."""
        text = "oauth_token=gho_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234"
        spans = detector.detect(text)

        gh_spans = [s for s in spans if s.entity_type == "GITHUB_TOKEN"]
        assert len(gh_spans) >= 1
        assert any(s.text.startswith("gho_") for s in gh_spans)

    def test_detect_github_user_token_ghu(self, detector):
        """Test GitHub user-to-server token with ghu_ prefix."""
        text = "token=ghu_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234"
        spans = detector.detect(text)

        gh_spans = [s for s in spans if s.entity_type == "GITHUB_TOKEN"]
        assert len(gh_spans) >= 1
        assert any(s.text.startswith("ghu_") for s in gh_spans)

    def test_detect_github_server_token_ghs(self, detector):
        """Test GitHub server-to-server token with ghs_ prefix."""
        text = "app_token=ghs_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234"
        spans = detector.detect(text)

        gh_spans = [s for s in spans if s.entity_type == "GITHUB_TOKEN"]
        assert len(gh_spans) >= 1
        assert any(s.text.startswith("ghs_") for s in gh_spans)

    def test_detect_github_refresh_token_ghr(self, detector):
        """Test GitHub refresh token with ghr_ prefix."""
        text = "refresh=ghr_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234"
        spans = detector.detect(text)

        gh_spans = [s for s in spans if s.entity_type == "GITHUB_TOKEN"]
        assert len(gh_spans) >= 1
        assert any(s.text.startswith("ghr_") for s in gh_spans)

    def test_detect_github_fine_grained_v1(self, detector):
        """Test GitHub fine-grained token with v1. prefix (hex format)."""
        # nosec: Test data - obviously fake token for pattern matching tests
        # v1. prefix requires 40 lowercase hex chars: v1.{40 hex}
        # Split to avoid secret scanner detection
        text = "token=" + "v1." + "0" * 40
        spans = detector.detect(text)

        gh_spans = [s for s in spans if s.entity_type == "GITHUB_TOKEN"]
        assert len(gh_spans) >= 1

    def test_github_token_high_confidence(self, detector):
        """Test GitHub PAT has high confidence."""
        text = "" + _fake_github_token("ghp_") + ""
        spans = detector.detect(text)

        gh_spans = [s for s in spans if s.entity_type == "GITHUB_TOKEN"]
        assert len(gh_spans) >= 1
        assert all(s.confidence >= 0.90 for s in gh_spans)

    def test_github_token_in_url(self, detector):
        """Test GitHub token detection in URL."""
        text = "git clone https://" + _fake_github_token("ghp_") + "@github.com/user/repo.git"
        spans = detector.detect(text)

        gh_spans = [s for s in spans if s.entity_type == "GITHUB_TOKEN"]
        assert len(gh_spans) >= 1


# =============================================================================
# GITLAB TOKEN TESTS
# =============================================================================

class TestGitLabTokens:
    """Test detection of GitLab tokens."""

    @pytest.fixture
    def detector(self):
        return SecretsDetector()

    def test_detect_gitlab_pat_glpat(self, detector):
        """Test GitLab Personal Access Token with glpat- prefix."""
        text = "GITLAB_TOKEN=glpat-ABCDEFghijKL1234567890"
        spans = detector.detect(text)

        gl_spans = [s for s in spans if s.entity_type == "GITLAB_TOKEN"]
        assert len(gl_spans) >= 1
        assert any(s.text.startswith("glpat-") for s in gl_spans)

    def test_detect_gitlab_pipeline_token(self, detector):
        """Test GitLab pipeline trigger token with glptt- prefix."""
        text = "trigger=glptt-ABCDEFGHIJKLMNOPQRST"
        spans = detector.detect(text)

        gl_spans = [s for s in spans if s.entity_type == "GITLAB_TOKEN"]
        assert len(gl_spans) >= 1

    def test_detect_gitlab_runner_token(self, detector):
        """Test GitLab runner registration token with glrt- prefix."""
        text = "runner_token=glrt-ABCDEFGHIJKLMNOPQRST"
        spans = detector.detect(text)

        gl_spans = [s for s in spans if s.entity_type == "GITLAB_TOKEN"]
        assert len(gl_spans) >= 1

    def test_gitlab_token_high_confidence(self, detector):
        """Test GitLab PAT has high confidence."""
        text = "glpat-ABCDEFghijKL1234567890"
        spans = detector.detect(text)

        gl_spans = [s for s in spans if s.entity_type == "GITLAB_TOKEN"]
        assert len(gl_spans) >= 1
        assert all(s.confidence >= 0.95 for s in gl_spans)


# =============================================================================
# SLACK TOKEN TESTS
# =============================================================================

class TestSlackTokens:
    """Test detection of Slack tokens and webhooks."""

    @pytest.fixture
    def detector(self):
        return SecretsDetector()

    def test_detect_slack_bot_token(self, detector):
        """Test Slack Bot token with xoxb- prefix."""
        # nosec: Test data - obviously fake token for pattern matching tests
        # Format: xoxb-{10-13 digits}-{10-13 digits}-{24 alphanumeric}
        text = "SLACK_TOKEN=xoxb-1234567890123-1234567890123-abcdefghijklmnopqrstuvwx"
        spans = detector.detect(text)

        slack_spans = [s for s in spans if s.entity_type == "SLACK_TOKEN"]
        assert len(slack_spans) >= 1
        assert any(s.text.startswith("xoxb-") for s in slack_spans)

    def test_detect_slack_user_token(self, detector):
        """Test Slack User token with xoxp- prefix."""
        # nosec: Test data - obviously fake token for pattern matching tests
        # Format: xoxp-{10-13 digits}-{10-13 digits}-{10-13 digits}-{32 hex}
        # Split to avoid secret scanner detection
        text = "user_token=" + "xoxp-" + "0" * 13 + "-" + "0" * 13 + "-" + "0" * 13 + "-" + "0" * 32
        spans = detector.detect(text)

        slack_spans = [s for s in spans if s.entity_type == "SLACK_TOKEN"]
        assert len(slack_spans) >= 1
        assert any(s.text.startswith("xoxp-") for s in slack_spans)

    def test_detect_slack_app_token(self, detector):
        """Test Slack App token with xoxa- prefix."""
        text = "app_token=xoxa-12345-ABCDEFghijKL"
        spans = detector.detect(text)

        slack_spans = [s for s in spans if s.entity_type == "SLACK_TOKEN"]
        assert len(slack_spans) >= 1

    def test_detect_slack_webhook(self, detector):
        """Test Slack webhook URL detection."""
        # nosec: Test data - obviously fake webhook for pattern matching tests
        text = "webhook=https://hooks.slack.com/services/TFAKETEST/BFAKETEST/FAKETESTHOOKEXAMPLE00"
        spans = detector.detect(text)

        webhook_spans = [s for s in spans if s.entity_type == "SLACK_WEBHOOK"]
        assert len(webhook_spans) >= 1

    def test_slack_token_high_confidence(self, detector):
        """Test Slack token has high confidence."""
        # nosec: Test data - obviously fake token for pattern matching tests
        # Format: xoxb-{10-13 digits}-{10-13 digits}-{24 alphanumeric}
        text = "xoxb-1234567890123-1234567890123-abcdefghijklmnopqrstuvwx"
        spans = detector.detect(text)

        slack_spans = [s for s in spans if s.entity_type == "SLACK_TOKEN"]
        assert len(slack_spans) >= 1
        assert all(s.confidence >= 0.95 for s in slack_spans)


# =============================================================================
# STRIPE KEY TESTS
# =============================================================================

class TestStripeKeys:
    """Test detection of Stripe API keys."""

    @pytest.fixture
    def detector(self):
        return SecretsDetector()

    def test_detect_stripe_live_secret_key(self, detector):
        """Test Stripe live secret key with sk_live_ prefix."""
        text = f"STRIPE_SECRET_KEY={_fake_stripe_key('sk_' + 'live_')}"
        spans = detector.detect(text)

        stripe_spans = [s for s in spans if s.entity_type == "STRIPE_KEY"]
        assert len(stripe_spans) >= 1
        assert any(s.text.startswith("sk_live_") for s in stripe_spans)

    def test_detect_stripe_test_secret_key(self, detector):
        """Test Stripe test secret key with sk_test_ prefix."""
        text = f"test_key={_fake_stripe_key('sk_' + 'test_')}"
        spans = detector.detect(text)

        stripe_spans = [s for s in spans if s.entity_type == "STRIPE_KEY"]
        assert len(stripe_spans) >= 1
        assert any(s.text.startswith("sk_test_") for s in stripe_spans)

    def test_detect_stripe_live_publishable_key(self, detector):
        """Test Stripe live publishable key with pk_live_ prefix."""
        text = f"STRIPE_PUBLISHABLE_KEY={_fake_stripe_key('pk_' + 'live_')}"
        spans = detector.detect(text)

        stripe_spans = [s for s in spans if s.entity_type == "STRIPE_KEY"]
        assert len(stripe_spans) >= 1
        assert any(s.text.startswith("pk_live_") for s in stripe_spans)

    def test_detect_stripe_test_publishable_key(self, detector):
        """Test Stripe test publishable key with pk_test_ prefix."""
        text = _fake_stripe_key("pk_" + "test_")
        spans = detector.detect(text)

        stripe_spans = [s for s in spans if s.entity_type == "STRIPE_KEY"]
        assert len(stripe_spans) >= 1

    def test_detect_stripe_restricted_key(self, detector):
        """Test Stripe restricted key with rk_live_ prefix."""
        text = f"restricted_key={_fake_stripe_key('rk_' + 'live_')}"
        spans = detector.detect(text)

        stripe_spans = [s for s in spans if s.entity_type == "STRIPE_KEY"]
        assert len(stripe_spans) >= 1

    def test_detect_stripe_webhook_secret(self, detector):
        """Test Stripe webhook secret with whsec_ prefix."""
        # Webhook secrets need 32+ chars after prefix
        text = "STRIPE_WEBHOOK_SECRET=whsec_abcdef0123456789abcdef0123456789"
        spans = detector.detect(text)

        stripe_spans = [s for s in spans if s.entity_type == "STRIPE_KEY"]
        assert len(stripe_spans) >= 1

    def test_stripe_live_key_high_confidence(self, detector):
        """Test Stripe live key has very high confidence."""
        text = _fake_stripe_key("sk_" + "live_")
        spans = detector.detect(text)

        stripe_spans = [s for s in spans if s.entity_type == "STRIPE_KEY"]
        assert len(stripe_spans) >= 1
        assert all(s.confidence >= 0.95 for s in stripe_spans)


# =============================================================================
# GOOGLE API KEY TESTS
# =============================================================================

class TestGoogleAPIKeys:
    """Test detection of Google API keys."""

    @pytest.fixture
    def detector(self):
        return SecretsDetector()

    def test_detect_google_api_key(self, detector):
        """Test Google API key with AIza prefix."""
        text = "GOOGLE_API_KEY=AIzaSyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWY"
        spans = detector.detect(text)

        google_spans = [s for s in spans if s.entity_type == "GOOGLE_API_KEY"]
        assert len(google_spans) >= 1
        assert any(s.text.startswith("AIza") for s in google_spans)

    def test_detect_google_oauth_client_id(self, detector):
        """Test Google OAuth client ID."""
        text = "client_id=123456789012-abcdefghijklmnopqrstuvwxyz123456.apps.googleusercontent.com"
        spans = detector.detect(text)

        oauth_spans = [s for s in spans if s.entity_type == "GOOGLE_OAUTH_ID"]
        assert len(oauth_spans) >= 1

    def test_detect_firebase_key(self, detector):
        """Test Firebase API key detection."""
        # Firebase keys need exactly 39 alphanumeric chars after label
        text = "firebase_api_key=ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklm"
        spans = detector.detect(text)

        firebase_spans = [s for s in spans if s.entity_type == "FIREBASE_KEY"]
        assert len(firebase_spans) >= 1

    def test_google_api_key_high_confidence(self, detector):
        """Test Google API key has high confidence."""
        text = "AIzaSyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWY"
        spans = detector.detect(text)

        google_spans = [s for s in spans if s.entity_type == "GOOGLE_API_KEY"]
        assert len(google_spans) >= 1
        assert all(s.confidence >= 0.95 for s in google_spans)


# =============================================================================
# TWILIO CREDENTIAL TESTS
# =============================================================================

class TestTwilioCredentials:
    """Test detection of Twilio credentials."""

    @pytest.fixture
    def detector(self):
        return SecretsDetector()

    def test_detect_twilio_account_sid(self, detector):
        """Test Twilio Account SID with AC prefix."""
        # Format: AC + 32 lowercase hex chars
        # Split to avoid secret scanner detection
        text = "TWILIO_ACCOUNT_SID=" + "AC" + "0" * 32
        spans = detector.detect(text)

        twilio_spans = [s for s in spans if s.entity_type == "TWILIO_ACCOUNT_SID"]
        assert len(twilio_spans) >= 1
        assert any(s.text.startswith("AC") for s in twilio_spans)

    def test_detect_twilio_api_key(self, detector):
        """Test Twilio API key SID with SK prefix."""
        # Format: SK + 32 lowercase hex chars
        # Split to avoid secret scanner detection
        text = "TWILIO_API_KEY_SID=" + "SK" + "0" * 32
        spans = detector.detect(text)

        twilio_spans = [s for s in spans if s.entity_type == "TWILIO_KEY"]
        assert len(twilio_spans) >= 1
        assert any(s.text.startswith("SK") for s in twilio_spans)

    def test_detect_twilio_auth_token(self, detector):
        """Test Twilio auth token detection."""
        text = "twilio_token=abcdef0123456789abcdef0123456789"
        spans = detector.detect(text)

        twilio_spans = [s for s in spans if s.entity_type == "TWILIO_TOKEN"]
        assert len(twilio_spans) >= 1


# =============================================================================
# SENDGRID KEY TESTS
# =============================================================================

class TestSendGridKeys:
    """Test detection of SendGrid API keys."""

    @pytest.fixture
    def detector(self):
        return SecretsDetector()

    def test_detect_sendgrid_api_key(self, detector):
        """Test SendGrid API key with SG. prefix."""
        # SendGrid format: SG.{22 chars}.{43 chars}
        text = "SENDGRID_API_KEY=SG.abcdefghij0123456789ab.abcdefghij0123456789abcdefghij0123456789abc"
        spans = detector.detect(text)

        sg_spans = [s for s in spans if s.entity_type == "SENDGRID_KEY"]
        assert len(sg_spans) >= 1
        assert any(s.text.startswith("SG.") for s in sg_spans)

    def test_sendgrid_key_high_confidence(self, detector):
        """Test SendGrid key has very high confidence."""
        # SendGrid format: SG.{22 chars}.{43 chars}
        text = "SG.abcdefghij0123456789ab.abcdefghij0123456789abcdefghij0123456789abc"
        spans = detector.detect(text)

        sg_spans = [s for s in spans if s.entity_type == "SENDGRID_KEY"]
        assert len(sg_spans) >= 1
        assert all(s.confidence >= 0.95 for s in sg_spans)


# =============================================================================
# DISCORD TOKEN TESTS
# =============================================================================

class TestDiscordTokens:
    """Test detection of Discord tokens and webhooks."""

    @pytest.fixture
    def detector(self):
        return SecretsDetector()

    def test_detect_discord_bot_token(self, detector):
        """Test Discord bot token detection."""
        text = "DISCORD_TOKEN=" + _fake_discord_token()
        spans = detector.detect(text)

        discord_spans = [s for s in spans if s.entity_type == "DISCORD_TOKEN"]
        assert len(discord_spans) >= 1

    def test_detect_discord_webhook(self, detector):
        """Test Discord webhook URL detection."""
        text = "webhook=https://discord.com/api/webhooks/000000000000000000/FAKETESTEXAMPLEHOOK0000000000000"
        spans = detector.detect(text)

        webhook_spans = [s for s in spans if s.entity_type == "DISCORD_WEBHOOK"]
        assert len(webhook_spans) >= 1

    def test_detect_discord_ptb_webhook(self, detector):
        """Test Discord PTB webhook URL detection."""
        text = "webhook=https://ptb.discord.com/api/webhooks/000000000000000000/FAKETESTEXAMPLEHOOK00000"
        spans = detector.detect(text)

        webhook_spans = [s for s in spans if s.entity_type == "DISCORD_WEBHOOK"]
        assert len(webhook_spans) >= 1


# =============================================================================
# NPM/PYPI TOKEN TESTS
# =============================================================================

class TestPackageRegistryTokens:
    """Test detection of package registry tokens."""

    @pytest.fixture
    def detector(self):
        return SecretsDetector()

    def test_detect_npm_token(self, detector):
        """Test NPM token with npm_ prefix."""
        # Format: npm_ + 36 alphanumeric chars
        text = "NPM_TOKEN=npm_abcdefghij0123456789abcdefghij012345"
        spans = detector.detect(text)

        npm_spans = [s for s in spans if s.entity_type == "NPM_TOKEN"]
        assert len(npm_spans) >= 1
        assert any(s.text.startswith("npm_") for s in npm_spans)

    def test_detect_npm_token_npmrc(self, detector):
        """Test NPM token in .npmrc format."""
        text = "//registry.npmjs.org/:_authToken=12345678-1234-1234-1234-123456789012"
        spans = detector.detect(text)

        npm_spans = [s for s in spans if s.entity_type == "NPM_TOKEN"]
        assert len(npm_spans) >= 1

    def test_detect_pypi_token(self, detector):
        """Test PyPI token with pypi- prefix."""
        text = "PYPI_TOKEN=pypi-FAKETESTEXAMPLE000000000000000000000000000000000000000"
        spans = detector.detect(text)

        pypi_spans = [s for s in spans if s.entity_type == "PYPI_TOKEN"]
        assert len(pypi_spans) >= 1
        assert any(s.text.startswith("pypi-") for s in pypi_spans)

    def test_detect_nuget_key(self, detector):
        """Test NuGet API key with oy2 prefix."""
        # NuGet pattern: oy2 + 43 lowercase alphanumeric chars
        text = "NUGET_API_KEY=oy2abcdefghijklmnopqrstuvwxyz1234567890abcdefg"
        spans = detector.detect(text)

        nuget_spans = [s for s in spans if s.entity_type == "NUGET_KEY"]
        assert len(nuget_spans) >= 1


# =============================================================================
# PRIVATE KEY TESTS
# =============================================================================

class TestPrivateKeys:
    """Test detection of private keys."""

    @pytest.fixture
    def detector(self):
        return SecretsDetector()

    def test_detect_rsa_private_key(self, detector):
        """Test RSA private key header detection."""
        text = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy...
-----END RSA PRIVATE KEY-----"""
        spans = detector.detect(text)

        key_spans = [s for s in spans if s.entity_type == "PRIVATE_KEY"]
        assert len(key_spans) >= 1

    def test_detect_generic_private_key(self, detector):
        """Test generic private key header detection."""
        text = """-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEA...
-----END PRIVATE KEY-----"""
        spans = detector.detect(text)

        key_spans = [s for s in spans if s.entity_type == "PRIVATE_KEY"]
        assert len(key_spans) >= 1

    def test_detect_ec_private_key(self, detector):
        """Test EC private key header detection."""
        text = """-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIOMYg2P...
-----END EC PRIVATE KEY-----"""
        spans = detector.detect(text)

        key_spans = [s for s in spans if s.entity_type == "PRIVATE_KEY"]
        assert len(key_spans) >= 1

    def test_detect_openssh_private_key(self, detector):
        """Test OpenSSH private key header detection."""
        text = """-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn...
-----END OPENSSH PRIVATE KEY-----"""
        spans = detector.detect(text)

        key_spans = [s for s in spans if s.entity_type == "PRIVATE_KEY"]
        assert len(key_spans) >= 1

    def test_detect_pgp_private_key(self, detector):
        """Test PGP private key block detection."""
        text = """-----BEGIN PGP PRIVATE KEY BLOCK-----
Version: GnuPG v1
lQOYBF0...
-----END PGP PRIVATE KEY BLOCK-----"""
        spans = detector.detect(text)

        key_spans = [s for s in spans if s.entity_type == "PRIVATE_KEY"]
        assert len(key_spans) >= 1

    def test_detect_dsa_private_key(self, detector):
        """Test DSA private key header detection."""
        text = """-----BEGIN DSA PRIVATE KEY-----
MIIBvAIBAAKBgQD...
-----END DSA PRIVATE KEY-----"""
        spans = detector.detect(text)

        key_spans = [s for s in spans if s.entity_type == "PRIVATE_KEY"]
        assert len(key_spans) >= 1

    def test_private_key_very_high_confidence(self, detector):
        """Test private key has very high confidence."""
        text = "-----BEGIN RSA PRIVATE KEY-----"
        spans = detector.detect(text)

        key_spans = [s for s in spans if s.entity_type == "PRIVATE_KEY"]
        assert len(key_spans) >= 1
        assert all(s.confidence >= 0.95 for s in key_spans)


# =============================================================================
# JWT TESTS
# =============================================================================

class TestJWT:
    """Test detection of JSON Web Tokens."""

    @pytest.fixture
    def detector(self):
        return SecretsDetector()

    def test_detect_valid_jwt(self, detector):
        """Test valid JWT detection (header.payload.signature)."""
        text = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        spans = detector.detect(text)

        jwt_spans = [s for s in spans if s.entity_type == "JWT"]
        assert len(jwt_spans) >= 1

    def test_detect_jwt_in_header(self, detector):
        """Test JWT detection in Authorization header."""
        text = "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        spans = detector.detect(text)

        jwt_spans = [s for s in spans if s.entity_type == "JWT"]
        assert len(jwt_spans) >= 1

    def test_reject_invalid_jwt_structure(self, detector):
        """Test invalid JWT structure is rejected."""
        # Only two parts instead of three
        text = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0"
        spans = detector.detect(text)

        jwt_spans = [s for s in spans if s.entity_type == "JWT"]
        assert len(jwt_spans) == 0

    def test_jwt_high_confidence(self, detector):
        """Test valid JWT has high confidence."""
        text = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        spans = detector.detect(text)

        jwt_spans = [s for s in spans if s.entity_type == "JWT"]
        assert len(jwt_spans) >= 1
        assert all(s.confidence >= 0.95 for s in jwt_spans)


# =============================================================================
# DATABASE CONNECTION STRING TESTS
# =============================================================================

class TestDatabaseURLs:
    """Test detection of database connection strings."""

    @pytest.fixture
    def detector(self):
        return SecretsDetector()

    def test_detect_postgresql_url(self, detector):
        """Test PostgreSQL connection string detection."""
        text = "DATABASE_URL=postgres://user:password@localhost:5432/mydb"
        spans = detector.detect(text)

        db_spans = [s for s in spans if s.entity_type == "DATABASE_URL"]
        assert len(db_spans) >= 1

    def test_detect_postgresql_url_with_options(self, detector):
        """Test PostgreSQL connection string with options."""
        text = "DATABASE_URL=postgresql://user:secret@db.example.com:5432/production?sslmode=require"
        spans = detector.detect(text)

        db_spans = [s for s in spans if s.entity_type == "DATABASE_URL"]
        assert len(db_spans) >= 1

    def test_detect_mysql_url(self, detector):
        """Test MySQL connection string detection."""
        text = "MYSQL_URL=mysql://root:password@localhost:3306/mydb"
        spans = detector.detect(text)

        db_spans = [s for s in spans if s.entity_type == "DATABASE_URL"]
        assert len(db_spans) >= 1

    def test_detect_mongodb_url(self, detector):
        """Test MongoDB connection string detection."""
        text = "MONGO_URL=mongodb://user:password@localhost:27017/mydb"
        spans = detector.detect(text)

        db_spans = [s for s in spans if s.entity_type == "DATABASE_URL"]
        assert len(db_spans) >= 1

    def test_detect_mongodb_srv_url(self, detector):
        """Test MongoDB SRV connection string detection."""
        text = "MONGO_URL=mongodb+srv://user:password@cluster.mongodb.net/mydb"
        spans = detector.detect(text)

        db_spans = [s for s in spans if s.entity_type == "DATABASE_URL"]
        assert len(db_spans) >= 1

    def test_detect_redis_url(self, detector):
        """Test Redis connection string detection."""
        text = "REDIS_URL=redis://user:password@localhost:6379/0"
        spans = detector.detect(text)

        db_spans = [s for s in spans if s.entity_type == "DATABASE_URL"]
        assert len(db_spans) >= 1

    def test_detect_redis_tls_url(self, detector):
        """Test Redis TLS connection string detection."""
        text = "REDIS_TLS_URL=rediss://user:password@redis.example.com:6379/0"
        spans = detector.detect(text)

        db_spans = [s for s in spans if s.entity_type == "DATABASE_URL"]
        assert len(db_spans) >= 1

    def test_detect_jdbc_url(self, detector):
        """Test JDBC connection string detection."""
        text = "JDBC_URL=jdbc:postgresql://user:password@localhost:5432/mydb"
        spans = detector.detect(text)

        db_spans = [s for s in spans if s.entity_type == "DATABASE_URL"]
        assert len(db_spans) >= 1


# =============================================================================
# AZURE CREDENTIAL TESTS
# =============================================================================

class TestAzureCredentials:
    """Test detection of Azure credentials."""

    @pytest.fixture
    def detector(self):
        return SecretsDetector()

    def test_detect_azure_storage_key(self, detector):
        """Test Azure storage account key detection."""
        key = "A" * 88  # Azure storage keys are 88 chars base64
        text = f"AccountKey={key}"
        spans = detector.detect(text)

        azure_spans = [s for s in spans if s.entity_type == "AZURE_STORAGE_KEY"]
        assert len(azure_spans) >= 1

    def test_detect_azure_connection_string(self, detector):
        """Test Azure storage connection string detection."""
        key = "A" * 88
        text = f"DefaultEndpointsProtocol=https;AccountName=mystorageaccount;AccountKey={key}"
        spans = detector.detect(text)

        azure_spans = [s for s in spans if s.entity_type == "AZURE_CONNECTION_STRING"]
        assert len(azure_spans) >= 1

    def test_detect_azure_sas_token(self, detector):
        """Test Azure SAS token detection."""
        text = "url=https://storage.blob.core.windows.net/container?sv=2020-08-04&st=2021-01-01T00%3A00%3A00Z&se=2021-01-02T00%3A00%3A00Z&sr=b&sp=r&sig=ABCDEFghijKLmnOPqrSTuv"
        spans = detector.detect(text)

        sas_spans = [s for s in spans if s.entity_type == "AZURE_SAS_TOKEN"]
        assert len(sas_spans) >= 1


# =============================================================================
# GENERIC SECRETS TESTS
# =============================================================================

class TestGenericSecrets:
    """Test detection of generic secrets and passwords."""

    @pytest.fixture
    def detector(self):
        return SecretsDetector()

    def test_detect_password_in_quotes(self, detector):
        """Test password detection in quoted string."""
        text = 'password="mysecretpassword123"'
        spans = detector.detect(text)

        pwd_spans = [s for s in spans if s.entity_type == "PASSWORD"]
        assert len(pwd_spans) >= 1

    def test_detect_api_key_labeled(self, detector):
        """Test generic API key detection with label."""
        text = 'api_key="ABCDEFghijKLmnOPqrSTuv"'
        spans = detector.detect(text)

        key_spans = [s for s in spans if s.entity_type == "API_KEY"]
        assert len(key_spans) >= 1

    def test_detect_basic_auth(self, detector):
        """Test Basic auth header detection."""
        text = "Authorization: Basic dXNlcm5hbWU6cGFzc3dvcmQ="
        spans = detector.detect(text)

        auth_spans = [s for s in spans if s.entity_type == "BASIC_AUTH"]
        assert len(auth_spans) >= 1

    def test_detect_bearer_token(self, detector):
        """Test Bearer token detection."""
        text = "Authorization: Bearer ABCDEFghijKLmnOPqrSTuvWXyz1234567890"
        spans = detector.detect(text)

        bearer_spans = [s for s in spans if s.entity_type == "BEARER_TOKEN"]
        assert len(bearer_spans) >= 1


# =============================================================================
# SHOPIFY TOKEN TESTS
# =============================================================================

class TestShopifyTokens:
    """Test detection of Shopify tokens."""

    @pytest.fixture
    def detector(self):
        return SecretsDetector()

    def test_detect_shopify_access_token(self, detector):
        """Test Shopify access token with shpat_ prefix."""
        text = "SHOPIFY_ACCESS_TOKEN=" + _fake_shopify_token("shp" + "at_")
        spans = detector.detect(text)

        shopify_spans = [s for s in spans if s.entity_type == "SHOPIFY_TOKEN"]
        assert len(shopify_spans) >= 1

    def test_detect_shopify_api_key(self, detector):
        """Test Shopify API key with shpka_ prefix."""
        text = "SHOPIFY_API_KEY=" + _fake_shopify_token("shp" + "ka_")
        spans = detector.detect(text)

        shopify_spans = [s for s in spans if s.entity_type == "SHOPIFY_KEY"]
        assert len(shopify_spans) >= 1

    def test_detect_shopify_shared_secret(self, detector):
        """Test Shopify shared secret with shpss_ prefix."""
        text = "SHOPIFY_API_SECRET=" + _fake_shopify_token("shp" + "ss_")
        spans = detector.detect(text)

        shopify_spans = [s for s in spans if s.entity_type == "SHOPIFY_SECRET"]
        assert len(shopify_spans) >= 1


# =============================================================================
# SQUARE TOKEN TESTS
# =============================================================================

class TestSquareTokens:
    """Test detection of Square tokens."""

    @pytest.fixture
    def detector(self):
        return SecretsDetector()

    def test_detect_square_access_token(self, detector):
        """Test Square access token with sq0atp- prefix."""
        text = "SQUARE_ACCESS_TOKEN=" + _fake_square_token("sq0" + "atp-")
        spans = detector.detect(text)

        square_spans = [s for s in spans if s.entity_type == "SQUARE_TOKEN"]
        assert len(square_spans) >= 1

    def test_detect_square_application_secret(self, detector):
        """Test Square application secret with sq0csp- prefix."""
        # Pattern expects sq0csp- + 43 chars
        text = "SQUARE_SECRET=" + _fake_square_token("sq0" + "csp-")
        spans = detector.detect(text)

        square_spans = [s for s in spans if s.entity_type == "SQUARE_SECRET"]
        assert len(square_spans) >= 1


# =============================================================================
# HEROKU KEY TESTS
# =============================================================================

class TestHerokuKeys:
    """Test detection of Heroku API keys."""

    @pytest.fixture
    def detector(self):
        return SecretsDetector()

    def test_detect_heroku_api_key(self, detector):
        """Test Heroku API key detection (UUID format)."""
        text = "HEROKU_API_KEY=12345678-1234-1234-1234-123456789012"
        spans = detector.detect(text)

        heroku_spans = [s for s in spans if s.entity_type == "HEROKU_KEY"]
        assert len(heroku_spans) >= 1


# =============================================================================
# MAILCHIMP KEY TESTS
# =============================================================================

class TestMailchimpKeys:
    """Test detection of Mailchimp API keys."""

    @pytest.fixture
    def detector(self):
        return SecretsDetector()

    def test_detect_mailchimp_api_key(self, detector):
        """Test Mailchimp API key detection (hash-datacenter format)."""
        text = "MAILCHIMP_API_KEY=" + _fake_mailchimp_key()
        spans = detector.detect(text)

        mc_spans = [s for s in spans if s.entity_type == "MAILCHIMP_KEY"]
        assert len(mc_spans) >= 1


# =============================================================================
# DATADOG/NEWRELIC KEY TESTS
# =============================================================================

class TestMonitoringKeys:
    """Test detection of monitoring service API keys."""

    @pytest.fixture
    def detector(self):
        return SecretsDetector()

    def test_detect_datadog_api_key(self, detector):
        """Test Datadog API key detection."""
        # Format: contextual "datadog" then 32 lowercase hex chars
        text = "datadog_api_key=abcdef0123456789abcdef0123456789"
        spans = detector.detect(text)

        dd_spans = [s for s in spans if s.entity_type == "DATADOG_KEY"]
        assert len(dd_spans) >= 1

    def test_detect_newrelic_api_key(self, detector):
        """Test New Relic API key detection with NRAK- prefix."""
        # Format: NRAK-{27 uppercase alphanumeric}
        # Split to avoid secret scanner detection
        text = "NEW_RELIC_API_KEY=" + "NRAK-" + "A" * 27
        spans = detector.detect(text)

        nr_spans = [s for s in spans if s.entity_type == "NEWRELIC_KEY"]
        assert len(nr_spans) >= 1


# =============================================================================
# FALSE POSITIVE TESTS
# =============================================================================

class TestFalsePositives:
    """Test false positive prevention."""

    @pytest.fixture
    def detector(self):
        return SecretsDetector()

    def test_no_false_positive_normal_text(self, detector):
        """Test normal text is not flagged."""
        text = "The quick brown fox jumps over the lazy dog."
        spans = detector.detect(text)
        assert len(spans) == 0

    def test_no_false_positive_placeholder_token(self, detector):
        """Test placeholder tokens are not flagged."""
        text = "GITHUB_TOKEN=<your-token-here>"
        spans = detector.detect(text)

        gh_spans = [s for s in spans if s.entity_type == "GITHUB_TOKEN"]
        assert len(gh_spans) == 0

    def test_no_false_positive_example_token(self, detector):
        """Test example/dummy tokens are not flagged."""
        text = "EXAMPLE_TOKEN=ghp_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
        spans = detector.detect(text)

        gh_spans = [s for s in spans if s.entity_type == "GITHUB_TOKEN"]
        assert len(gh_spans) == 0

    def test_no_false_positive_aws_example(self, detector):
        """Test AWS example key is detected (it matches real format)."""
        # The AKIAIOSFODNN7EXAMPLE is actually a valid format
        text = "AKIAIOSFODNN7EXAMPLE"
        spans = detector.detect(text)
        # This will actually be detected since it matches the format
        # AWS keys look real even when marked as EXAMPLE
        aws_spans = [s for s in spans if s.entity_type == "AWS_ACCESS_KEY"]
        assert len(aws_spans) >= 1

    def test_no_false_positive_short_string(self, detector):
        """Test short strings matching pattern prefix are not flagged."""
        text = "ghp_short"
        spans = detector.detect(text)

        gh_spans = [s for s in spans if s.entity_type == "GITHUB_TOKEN"]
        assert len(gh_spans) == 0

    def test_no_false_positive_code_comment(self, detector):
        """Test code comment with secret-like text is handled."""
        text = "// Set your API key here: api_key='YOUR_KEY_HERE'"
        spans = detector.detect(text)

        # Should not flag placeholder text
        key_spans = [s for s in spans if "YOUR_KEY_HERE" in s.text]
        assert len(key_spans) == 0


# =============================================================================
# EDGE CASES
# =============================================================================

class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    @pytest.fixture
    def detector(self):
        return SecretsDetector()

    def test_empty_string(self, detector):
        """Test empty string input."""
        spans = detector.detect("")
        assert spans == []

    def test_whitespace_only(self, detector):
        """Test whitespace-only input."""
        spans = detector.detect("   \n\t  ")
        assert spans == []

    def test_multiple_secrets_in_text(self, detector):
        """Test detection of multiple secrets in one text."""
        stripe_key = _fake_stripe_key("sk_" + "live_")
        gh_token = _fake_github_token("ghp_")
        text = f"""
        AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
        GITHUB_TOKEN={gh_token}
        STRIPE_SECRET_KEY={stripe_key}
        """
        spans = detector.detect(text)

        aws_spans = [s for s in spans if s.entity_type == "AWS_ACCESS_KEY"]
        gh_spans = [s for s in spans if s.entity_type == "GITHUB_TOKEN"]
        stripe_spans = [s for s in spans if s.entity_type == "STRIPE_KEY"]

        assert len(aws_spans) >= 1
        assert len(gh_spans) >= 1
        assert len(stripe_spans) >= 1

    def test_secrets_in_json(self, detector):
        """Test secrets detection in JSON format."""
        stripe_key = _fake_stripe_key("sk_" + "live_")
        gh_token = _fake_github_token("ghp_")
        text = f'{{"api_key": "{stripe_key}", "github_token": "{gh_token}"}}'
        spans = detector.detect(text)

        stripe_spans = [s for s in spans if s.entity_type == "STRIPE_KEY"]
        gh_spans = [s for s in spans if s.entity_type == "GITHUB_TOKEN"]

        assert len(stripe_spans) >= 1
        assert len(gh_spans) >= 1

    def test_secrets_in_yaml(self, detector):
        """Test secrets detection in YAML format."""
        stripe_key = _fake_stripe_key("sk_" + "live_")
        gh_token = _fake_github_token("ghp_")
        text = f"""
env:
  STRIPE_KEY: {stripe_key}
  GITHUB_TOKEN: {gh_token}
"""
        spans = detector.detect(text)

        stripe_spans = [s for s in spans if s.entity_type == "STRIPE_KEY"]
        gh_spans = [s for s in spans if s.entity_type == "GITHUB_TOKEN"]

        assert len(stripe_spans) >= 1
        assert len(gh_spans) >= 1

    def test_confidence_scores_valid(self, detector):
        """Test that detected spans have valid confidence scores."""
        text = "GITHUB_TOKEN=" + _fake_github_token("ghp_") + ""
        spans = detector.detect(text)

        for span in spans:
            assert 0.0 <= span.confidence <= 1.0

    def test_span_positions_valid(self, detector):
        """Test that span positions are correct."""
        text = "key: " + _fake_github_token("ghp_") + ""
        spans = detector.detect(text)

        for span in spans:
            assert span.start >= 0
            assert span.end > span.start
            assert span.end <= len(text)
            assert text[span.start:span.end] == span.text

    def test_secret_at_start_of_text(self, detector):
        """Test secret detection at very start of text."""
        text = "" + _fake_github_token("ghp_") + " is the token"
        spans = detector.detect(text)

        gh_spans = [s for s in spans if s.entity_type == "GITHUB_TOKEN"]
        assert len(gh_spans) >= 1

    def test_secret_at_end_of_text(self, detector):
        """Test secret detection at very end of text."""
        text = "The token is " + _fake_github_token("ghp_") + ""
        spans = detector.detect(text)

        gh_spans = [s for s in spans if s.entity_type == "GITHUB_TOKEN"]
        assert len(gh_spans) >= 1

    def test_secret_embedded_in_url(self, detector):
        """Test secret detection when embedded in URL."""
        text = "https://api.example.com?api_key=" + _fake_stripe_key("sk_" + "live_") + ""
        spans = detector.detect(text)

        stripe_spans = [s for s in spans if s.entity_type == "STRIPE_KEY"]
        assert len(stripe_spans) >= 1

    def test_no_overlapping_spans(self, detector):
        """Test that detector handles potential overlaps correctly."""
        text = "AKIAIOSFODNN7EXAMPLE"
        spans = detector.detect(text)

        # Check for overlapping spans
        for i, span1 in enumerate(spans):
            for span2 in spans[i + 1:]:
                # Spans should not have same start/end unless different types
                if span1.entity_type == span2.entity_type:
                    assert span1.start != span2.start or span1.end != span2.end


# =============================================================================
# SPAN VALIDATION TESTS
# =============================================================================

class TestSpanValidation:
    """Test span properties and validation."""

    @pytest.fixture
    def detector(self):
        return SecretsDetector()

    def test_span_has_correct_detector_name(self, detector):
        """Test spans have correct detector name."""
        text = "" + _fake_github_token("ghp_") + ""
        spans = detector.detect(text)

        for span in spans:
            assert span.detector == "secrets"

    def test_span_has_correct_tier(self, detector):
        """Test spans have correct tier."""
        text = "" + _fake_github_token("ghp_") + ""
        spans = detector.detect(text)

        for span in spans:
            assert span.tier == Tier.PATTERN

    def test_span_text_matches_position(self, detector):
        """Test span text matches extracted position."""
        text = "prefix " + _fake_github_token("ghp_") + " suffix"
        spans = detector.detect(text)

        for span in spans:
            extracted = text[span.start:span.end]
            assert extracted == span.text

    def test_high_confidence_for_distinctive_patterns(self, detector):
        """Test high confidence for distinctive patterns."""
        patterns_and_types = [
            ("AKIAIOSFODNN7EXAMPLE", "AWS_ACCESS_KEY"),
            ("" + _fake_github_token("ghp_") + "", "GITHUB_TOKEN"),
            ("" + _fake_stripe_key("sk_" + "live_") + "", "STRIPE_KEY"),
        ]

        for pattern, expected_type in patterns_and_types:
            spans = detector.detect(pattern)
            typed_spans = [s for s in spans if s.entity_type == expected_type]
            assert len(typed_spans) >= 1
            assert all(s.confidence >= 0.90 for s in typed_spans)
