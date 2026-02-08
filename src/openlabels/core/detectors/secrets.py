"""
Secrets and credential detector.

Detects API keys, tokens, private keys, JWTs, connection strings,
and other sensitive credentials that should never be exposed.

All patterns have high confidence (0.90+) because they use distinctive
prefixes or formats that are unlikely to appear in normal text.

Entity Types:
- AWS_ACCESS_KEY, AWS_SECRET_KEY, AWS_SESSION_TOKEN
- GITHUB_TOKEN, GITLAB_TOKEN
- SLACK_TOKEN, SLACK_WEBHOOK
- STRIPE_KEY, GOOGLE_API_KEY
- TWILIO_KEY, SENDGRID_KEY
- DISCORD_TOKEN, DISCORD_WEBHOOK
- NPM_TOKEN, PYPI_TOKEN
- PRIVATE_KEY, JWT, BEARER_TOKEN
- DATABASE_URL, AZURE_KEY
- And more...
"""

import base64
import binascii
import re
from typing import List

from ..types import Span, Tier
from .base import BaseDetector
from .pattern_registry import PatternDefinition, _p
from .registry import register_detector


# Pattern definitions: immutable frozen dataclass tuples
_AWS_KEY_PREFIXES = r'(?:AKIA|ABIA|ACCA|AGPA|AIDA|AIPA|ANPA|ANVA|APKA|AROA|ASCA|ASIA)'

SECRETS_PATTERNS: tuple[PatternDefinition, ...] = (
    # --- AWS ---
    _p(rf'\b({_AWS_KEY_PREFIXES}[A-Z0-9]{{16}})\b', 'AWS_ACCESS_KEY', 0.99, 1),
    _p(r'(?:aws_secret_access_key|aws_secret|secret_key|secretaccesskey)["\s:=]+([A-Za-z0-9+/]{40})', 'AWS_SECRET_KEY', 0.95, 1, flags=re.I),
    _p(r'(?:aws_session_token|session_token)["\s:=]+([A-Za-z0-9+/=]{100,})', 'AWS_SESSION_TOKEN', 0.92, 1, flags=re.I),

    # --- GITHUB ---
    _p(r'\b(ghp_[a-zA-Z0-9]{36})\b', 'GITHUB_TOKEN', 0.99, 1),
    _p(r'\b(gho_[a-zA-Z0-9]{36})\b', 'GITHUB_TOKEN', 0.99, 1),
    _p(r'\b(ghu_[a-zA-Z0-9]{36})\b', 'GITHUB_TOKEN', 0.99, 1),
    _p(r'\b(ghs_[a-zA-Z0-9]{36})\b', 'GITHUB_TOKEN', 0.99, 1),
    _p(r'\b(ghr_[a-zA-Z0-9]{36})\b', 'GITHUB_TOKEN', 0.99, 1),
    _p(r'\b(v1\.[a-f0-9]{40})\b', 'GITHUB_TOKEN', 0.90, 1),

    # --- GITLAB ---
    _p(r'\b(glpat-[a-zA-Z0-9\-_]{20,})\b', 'GITLAB_TOKEN', 0.99, 1),
    _p(r'\b(glptt-[a-zA-Z0-9]{20,})\b', 'GITLAB_TOKEN', 0.98, 1),
    _p(r'\b(glrt-[a-zA-Z0-9\-_]{20,})\b', 'GITLAB_TOKEN', 0.98, 1),

    # --- SLACK ---
    _p(r'\b(xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24})\b', 'SLACK_TOKEN', 0.99, 1),
    _p(r'\b(xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-f0-9]{32})\b', 'SLACK_TOKEN', 0.99, 1),
    _p(r'\b(xoxa-[0-9]+-[a-zA-Z0-9]+)\b', 'SLACK_TOKEN', 0.95, 1),
    _p(r'\b(xoxr-[0-9]+-[a-zA-Z0-9]+)\b', 'SLACK_TOKEN', 0.95, 1),
    _p(r'(https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+)', 'SLACK_WEBHOOK', 0.99, 1),

    # --- STRIPE ---
    _p(r'\b(sk_live_[a-zA-Z0-9]{24,})\b', 'STRIPE_KEY', 0.99, 1),
    _p(r'\b(sk_test_[a-zA-Z0-9]{24,})\b', 'STRIPE_KEY', 0.90, 1),
    _p(r'\b(pk_live_[a-zA-Z0-9]{24,})\b', 'STRIPE_KEY', 0.95, 1),
    _p(r'\b(pk_test_[a-zA-Z0-9]{24,})\b', 'STRIPE_KEY', 0.85, 1),
    _p(r'\b(rk_live_[a-zA-Z0-9]{24,})\b', 'STRIPE_KEY', 0.99, 1),
    _p(r'\b(whsec_[a-zA-Z0-9]{32,})\b', 'STRIPE_KEY', 0.98, 1),

    # --- GOOGLE ---
    _p(r'\b(AIza[a-zA-Z0-9\-_]{35})\b', 'GOOGLE_API_KEY', 0.98, 1),
    _p(r'\b(\d{12}-[a-z0-9]{32}\.apps\.googleusercontent\.com)\b', 'GOOGLE_OAUTH_ID', 0.95, 1),
    _p(r'(?:client_secret|google_secret)["\s:=]+([a-zA-Z0-9\-_]{24})', 'GOOGLE_OAUTH_SECRET', 0.90, 1, flags=re.I),
    _p(r'(?:firebase|fcm)["\s:=_-]*(?:api[_-]?key|server[_-]?key)["\s:=]+([a-zA-Z0-9\-_]{39})', 'FIREBASE_KEY', 0.95, 1, flags=re.I),

    # --- TWILIO ---
    _p(r'\b(AC[a-f0-9]{32})\b', 'TWILIO_ACCOUNT_SID', 0.98, 1),
    _p(r'\b(SK[a-f0-9]{32})\b', 'TWILIO_KEY', 0.98, 1),
    _p(r'(?:twilio|auth)[_\s]*token["\s:=]+([a-f0-9]{32})\b', 'TWILIO_TOKEN', 0.92, 1, flags=re.I),

    # --- SENDGRID ---
    _p(r'\b(SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43})\b', 'SENDGRID_KEY', 0.99, 1),

    # --- MAILCHIMP ---
    _p(r'\b([a-f0-9]{32}-us[0-9]{1,2})\b', 'MAILCHIMP_KEY', 0.98, 1),

    # --- DISCORD ---
    _p(r'\b([MN][a-zA-Z0-9]{23,}\.[a-zA-Z0-9\-_]{6}\.[a-zA-Z0-9\-_]{27,})\b', 'DISCORD_TOKEN', 0.95, 1),
    _p(r'(https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/[0-9]+/[a-zA-Z0-9\-_]+)', 'DISCORD_WEBHOOK', 0.98, 1),

    # --- NPM / PYPI / NUGET ---
    _p(r'\b(npm_[a-zA-Z0-9]{36})\b', 'NPM_TOKEN', 0.99, 1),
    _p(r'//registry\.npmjs\.org/:_authToken=([a-f0-9\-]{36})', 'NPM_TOKEN', 0.95, 1),
    _p(r'\b(pypi-[a-zA-Z0-9\-_]{50,})\b', 'PYPI_TOKEN', 0.99, 1),
    _p(r'\b(oy2[a-z0-9]{43})\b', 'NUGET_KEY', 0.95, 1),

    # --- HEROKU ---
    _p(r'(?:heroku|HEROKU)[_\s]*(?:api[_\s]*)?(?:key|token)["\s:=]+([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})', 'HEROKU_KEY', 0.95, 1, flags=re.I),

    # --- SQUARE ---
    _p(r'\b(sq0atp-[a-zA-Z0-9\-_]{22})\b', 'SQUARE_TOKEN', 0.98, 1),
    _p(r'\b(sq0csp-[a-zA-Z0-9\-_]{43})\b', 'SQUARE_SECRET', 0.98, 1),

    # --- SHOPIFY ---
    _p(r'\b(shpat_[a-f0-9]{32})\b', 'SHOPIFY_TOKEN', 0.99, 1),
    _p(r'\b(shpka_[a-f0-9]{32})\b', 'SHOPIFY_KEY', 0.99, 1),
    _p(r'\b(shpss_[a-f0-9]{32})\b', 'SHOPIFY_SECRET', 0.99, 1),

    # --- DATADOG / MONITORING ---
    _p(r'(?:datadog|dd)[_\s]*(?:api[_\s]*)?key["\s:=]+([a-f0-9]{32})\b', 'DATADOG_KEY', 0.92, 1, flags=re.I),
    _p(r'\b(NRAK-[A-Z0-9]{27})\b', 'NEWRELIC_KEY', 0.98, 1),

    # --- PRIVATE KEYS (PEM) ---
    _p(r'(-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----)', 'PRIVATE_KEY', 0.99, 1),
    _p(r'-----BEGIN [A-Z ]+ PRIVATE KEY-----\s*([A-Za-z0-9+/=\s]{64,})\s*-----END', 'PRIVATE_KEY', 0.99, 1),
    _p(r'(-----BEGIN OPENSSH PRIVATE KEY-----)', 'PRIVATE_KEY', 0.99, 1),
    _p(r'(-----BEGIN PGP PRIVATE KEY BLOCK-----)', 'PRIVATE_KEY', 0.99, 1),

    # --- JWT ---
    _p(r'\b(eyJ[a-zA-Z0-9\-_]+\.eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+)\b', 'JWT', 0.98, 1),

    # --- AUTH HEADERS ---
    _p(r'\b(Basic\s+[a-zA-Z0-9+/=]{20,})\b', 'BASIC_AUTH', 0.95, 1),
    _p(r'(?:Authorization|Bearer)[:\s]+Bearer\s+([a-zA-Z0-9\-_\.]{20,})', 'BEARER_TOKEN', 0.90, 1, flags=re.I),

    # --- DATABASE CONNECTION STRINGS ---
    _p(r'(postgres(?:ql)?://[^:]+:[^@]+@[^\s"\'<>]+)', 'DATABASE_URL', 0.98, 1, flags=re.I),
    _p(r'(mysql://[^:]+:[^@]+@[^\s"\'<>]+)', 'DATABASE_URL', 0.98, 1, flags=re.I),
    _p(r'(mongodb(?:\+srv)?://[^:]+:[^@]+@[^\s"\'<>]+)', 'DATABASE_URL', 0.98, 1, flags=re.I),
    _p(r'(redis://[^:]+:[^@]+@[^\s"\'<>]+)', 'DATABASE_URL', 0.98, 1, flags=re.I),
    _p(r'(rediss://[^:]+:[^@]+@[^\s"\'<>]+)', 'DATABASE_URL', 0.98, 1, flags=re.I),
    _p(r'(jdbc:[a-z]+://[^:]+:[^@]+@[^\s"\'<>]+)', 'DATABASE_URL', 0.95, 1, flags=re.I),
    _p(r'(Server=[^;]+;.*Password=[^;]+)', 'DATABASE_URL', 0.92, 1, flags=re.I),

    # --- AZURE ---
    _p(r'(?:AccountKey|azure[_\s]*storage[_\s]*key)["\s:=]+([a-zA-Z0-9+/=]{88})', 'AZURE_STORAGE_KEY', 0.98, 1, flags=re.I),
    _p(r'(DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[a-zA-Z0-9+/=]+)', 'AZURE_CONNECTION_STRING', 0.98, 1),
    _p(r'(\?sv=\d{4}-\d{2}-\d{2}&[^"\s]+sig=[a-zA-Z0-9%]+)', 'AZURE_SAS_TOKEN', 0.95, 1),
    _p(r'(Endpoint=sb://[^;]+;SharedAccessKeyName=[^;]+;SharedAccessKey=[a-zA-Z0-9+/=]+)', 'AZURE_CONNECTION_STRING', 0.98, 1),

    # --- GENERIC SECRETS (CONTEXTUAL) ---
    _p(r'(?:password|passwd|pwd)["\s:=]+["\']([^"\']{8,})["\']', 'PASSWORD', 0.85, 1, flags=re.I),
    _p(r'(?:password|passwd|pwd|mot de passe|passwort|contraseña|wachtwoord|parola|senha)[:\s]+([^\s,.<>]{5,30})', 'PASSWORD', 0.80, 1, flags=re.I),
    _p(r'(?:api[_\s]?key|apikey|api[_\s]?secret)["\s:=]+["\']([a-zA-Z0-9\-_]{16,})["\']', 'API_KEY', 0.85, 1, flags=re.I),
    _p(r'(?:secret|token|credential)["\s:=]+["\']([a-zA-Z0-9\-_]{16,})["\']', 'SECRET', 0.80, 1, flags=re.I),
    _p(r'(?:private[_\s]?key|priv[_\s]?key)["\s:=]+["\']([a-zA-Z0-9+/=\-_]{20,})["\']', 'PRIVATE_KEY', 0.85, 1, flags=re.I),
)


@register_detector
class SecretsDetector(BaseDetector):
    """
    Detects API keys, tokens, and other secrets.

    High confidence patterns - these formats are distinctive
    and unlikely to appear in normal text.
    """

    name = "secrets"
    tier = Tier.PATTERN

    def detect(self, text: str) -> List[Span]:
        spans = []
        seen = set()

        for pdef in SECRETS_PATTERNS:
            for match in pdef.pattern.finditer(text):
                if pdef.group > 0 and match.lastindex and pdef.group <= match.lastindex:
                    value = match.group(pdef.group)
                    start = match.start(pdef.group)
                    end = match.end(pdef.group)
                else:
                    value = match.group(0)
                    start = match.start()
                    end = match.end()

                if not value or not value.strip():
                    continue

                key = (start, end, value)
                if key in seen:
                    continue
                seen.add(key)

                # Additional validation for JWTs
                if pdef.entity_type == 'JWT':
                    if not self._validate_jwt(value):
                        continue

                span = Span(
                    start=start,
                    end=end,
                    text=value,
                    entity_type=pdef.entity_type,
                    confidence=pdef.confidence,
                    detector=self.name,
                    tier=self.tier,
                )
                spans.append(span)

        return spans

    def _validate_jwt(self, token: str) -> bool:
        """Basic JWT structure validation."""
        parts = token.split('.')
        if len(parts) != 3:
            return False

        for part in parts[:2]:
            try:
                padded = part + '=' * (4 - len(part) % 4)
                padded = padded.replace('-', '+').replace('_', '/')
                base64.b64decode(padded)
            except (ValueError, binascii.Error):
                # Invalid Base64 in header or payload - not a valid JWT
                return False

        return True
