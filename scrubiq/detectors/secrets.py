"""Tier 2: Secrets and credential detectors.

Detects API keys, tokens, private keys, JWTs, connection strings,
and other sensitive credentials that should never be exposed.

All patterns have high confidence (0.90+) because they use distinctive
prefixes or formats that are unlikely to appear in normal text.

Entity Types:
- AWS_ACCESS_KEY: AWS access key IDs (AKIA...)
- AWS_SECRET_KEY: AWS secret access keys (contextual)
- GITHUB_TOKEN: GitHub personal access tokens (ghp_, gho_, ghs_, ghu_)
- GITLAB_TOKEN: GitLab personal access tokens (glpat-)
- SLACK_TOKEN: Slack bot/user tokens (xoxb-, xoxp-, xoxa-, xoxr-)
- SLACK_WEBHOOK: Slack webhook URLs
- STRIPE_KEY: Stripe API keys (sk_live_, pk_live_, etc.)
- GOOGLE_API_KEY: Google API keys (AIza...)
- TWILIO_KEY: Twilio API keys and account SIDs
- SENDGRID_KEY: SendGrid API keys
- DISCORD_TOKEN: Discord bot tokens
- DISCORD_WEBHOOK: Discord webhook URLs
- NPM_TOKEN: NPM access tokens
- PYPI_TOKEN: PyPI API tokens
- PRIVATE_KEY: PEM-encoded private keys
- JWT: JSON Web Tokens
- BASIC_AUTH: Basic authentication headers
- BEARER_TOKEN: Bearer tokens in auth context
- DATABASE_URL: Connection strings with credentials
- AZURE_KEY: Azure storage keys and connection strings
- HEROKU_KEY: Heroku API keys
- MAILCHIMP_KEY: Mailchimp API keys
- SQUARE_KEY: Square API keys
- GENERIC_SECRET: Generic secret patterns (password=, api_key=, etc.)
"""

import base64
import binascii
import re
from typing import List, Tuple

from ..types import Span, Tier
from .base import BaseDetector


# Pattern definitions: (regex, entity_type, confidence, group_index, flags)
# group_index: which capture group contains the value (0 = whole match)

SECRETS_PATTERNS: List[Tuple[re.Pattern, str, float, int]] = []


def _add(pattern: str, entity_type: str, confidence: float, group: int = 0, flags: int = 0):
    """Helper to compile and add patterns."""
    SECRETS_PATTERNS.append((re.compile(pattern, flags), entity_type, confidence, group))


# --- AWS ---
# AWS Access Key ID: Always starts with AKIA, ABIA, ACCA, AGPA, AIDA, AIPA, ANPA, ANVA, APKA, AROA, ASCA, ASIA
_AWS_KEY_PREFIXES = r'(?:AKIA|ABIA|ACCA|AGPA|AIDA|AIPA|ANPA|ANVA|APKA|AROA|ASCA|ASIA)'
_add(rf'\b({_AWS_KEY_PREFIXES}[A-Z0-9]{{16}})\b', 'AWS_ACCESS_KEY', 0.99, 1)

# AWS Secret Access Key: 40 characters, base64-ish, usually after aws_secret or similar context
_add(r'(?:aws_secret_access_key|aws_secret|secret_key|secretaccesskey)["\s:=]+([A-Za-z0-9+/]{40})', 'AWS_SECRET_KEY', 0.95, 1, re.I)

# AWS Session Token (temporary credentials)
_add(r'(?:aws_session_token|session_token)["\s:=]+([A-Za-z0-9+/=]{100,})', 'AWS_SESSION_TOKEN', 0.92, 1, re.I)


# --- GITHUB ---
# GitHub Personal Access Token (classic and fine-grained)
_add(r'\b(ghp_[a-zA-Z0-9]{36})\b', 'GITHUB_TOKEN', 0.99, 1)  # Personal access token
_add(r'\b(gho_[a-zA-Z0-9]{36})\b', 'GITHUB_TOKEN', 0.99, 1)  # OAuth access token
_add(r'\b(ghu_[a-zA-Z0-9]{36})\b', 'GITHUB_TOKEN', 0.99, 1)  # User-to-server token
_add(r'\b(ghs_[a-zA-Z0-9]{36})\b', 'GITHUB_TOKEN', 0.99, 1)  # Server-to-server token
_add(r'\b(ghr_[a-zA-Z0-9]{36})\b', 'GITHUB_TOKEN', 0.99, 1)  # Refresh token

# GitHub App installation token (older format)
_add(r'\b(v1\.[a-f0-9]{40})\b', 'GITHUB_TOKEN', 0.90, 1)


# --- GITLAB ---
# GitLab Personal Access Token
_add(r'\b(glpat-[a-zA-Z0-9\-_]{20,})\b', 'GITLAB_TOKEN', 0.99, 1)

# GitLab Pipeline Token
_add(r'\b(glptt-[a-zA-Z0-9]{20,})\b', 'GITLAB_TOKEN', 0.98, 1)

# GitLab Runner Token
_add(r'\b(glrt-[a-zA-Z0-9\-_]{20,})\b', 'GITLAB_TOKEN', 0.98, 1)


# --- SLACK ---
# Slack Bot Token
_add(r'\b(xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24})\b', 'SLACK_TOKEN', 0.99, 1)

# Slack User Token
_add(r'\b(xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-f0-9]{32})\b', 'SLACK_TOKEN', 0.99, 1)

# Slack App Token
_add(r'\b(xoxa-[0-9]+-[a-zA-Z0-9]+)\b', 'SLACK_TOKEN', 0.95, 1)

# Slack Configuration Token
_add(r'\b(xoxr-[0-9]+-[a-zA-Z0-9]+)\b', 'SLACK_TOKEN', 0.95, 1)

# Slack Webhook URL
_add(r'(https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+)', 'SLACK_WEBHOOK', 0.99, 1)


# --- STRIPE ---
# Stripe Secret Key (live)
_add(r'\b(sk_live_[a-zA-Z0-9]{24,})\b', 'STRIPE_KEY', 0.99, 1)

# Stripe Secret Key (test) - lower confidence since it's test
_add(r'\b(sk_test_[a-zA-Z0-9]{24,})\b', 'STRIPE_KEY', 0.90, 1)

# Stripe Publishable Key (live)
_add(r'\b(pk_live_[a-zA-Z0-9]{24,})\b', 'STRIPE_KEY', 0.95, 1)

# Stripe Publishable Key (test)
_add(r'\b(pk_test_[a-zA-Z0-9]{24,})\b', 'STRIPE_KEY', 0.85, 1)

# Stripe Restricted Key
_add(r'\b(rk_live_[a-zA-Z0-9]{24,})\b', 'STRIPE_KEY', 0.99, 1)
_add(r'\b(rk_test_[a-zA-Z0-9]{24,})\b', 'STRIPE_KEY', 0.90, 1)

# Stripe Webhook Secret
_add(r'\b(whsec_[a-zA-Z0-9]{32,})\b', 'STRIPE_KEY', 0.98, 1)


# --- GOOGLE ---
# Google API Key
_add(r'\b(AIza[a-zA-Z0-9\-_]{35})\b', 'GOOGLE_API_KEY', 0.98, 1)

# Google OAuth Client ID
_add(r'\b(\d{12}-[a-z0-9]{32}\.apps\.googleusercontent\.com)\b', 'GOOGLE_OAUTH_ID', 0.95, 1)

# Google OAuth Client Secret (contextual)
_add(r'(?:client_secret|google_secret)["\s:=]+([a-zA-Z0-9\-_]{24})', 'GOOGLE_OAUTH_SECRET', 0.90, 1, re.I)

# Firebase API Key (same format as Google)
_add(r'(?:firebase|fcm)["\s:=_-]*(?:api[_-]?key|server[_-]?key)["\s:=]+([a-zA-Z0-9\-_]{39})', 'FIREBASE_KEY', 0.95, 1, re.I)


# --- TWILIO ---
# Twilio Account SID
_add(r'\b(AC[a-f0-9]{32})\b', 'TWILIO_ACCOUNT_SID', 0.98, 1)

# Twilio API Key SID
_add(r'\b(SK[a-f0-9]{32})\b', 'TWILIO_KEY', 0.98, 1)

# Twilio Auth Token (contextual)
_add(r'(?:twilio|auth)[_\s]*token["\s:=]+([a-f0-9]{32})\b', 'TWILIO_TOKEN', 0.92, 1, re.I)


# --- SENDGRID ---
# SendGrid API Key
_add(r'\b(SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43})\b', 'SENDGRID_KEY', 0.99, 1)


# --- MAILCHIMP ---
# Mailchimp API Key: 32 hex chars + datacenter
_add(r'\b([a-f0-9]{32}-us[0-9]{1,2})\b', 'MAILCHIMP_KEY', 0.98, 1)


# --- DISCORD ---
# Discord Bot Token: base64 user id + timestamp + hmac
_add(r'\b([MN][a-zA-Z0-9]{23,}\.[a-zA-Z0-9\-_]{6}\.[a-zA-Z0-9\-_]{27,})\b', 'DISCORD_TOKEN', 0.95, 1)

# Discord Webhook URL
_add(r'(https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/[0-9]+/[a-zA-Z0-9\-_]+)', 'DISCORD_WEBHOOK', 0.98, 1)


# --- NPM / PYPI / NUGET ---
# NPM Token
_add(r'\b(npm_[a-zA-Z0-9]{36})\b', 'NPM_TOKEN', 0.99, 1)

# NPM Token (older format)
_add(r'//registry\.npmjs\.org/:_authToken=([a-f0-9\-]{36})', 'NPM_TOKEN', 0.95, 1)

# PyPI Token
_add(r'\b(pypi-[a-zA-Z0-9\-_]{50,})\b', 'PYPI_TOKEN', 0.99, 1)

# NuGet API Key
_add(r'\b(oy2[a-z0-9]{43})\b', 'NUGET_KEY', 0.95, 1)


# --- HEROKU ---
# Heroku API Key (UUID format in heroku context)
_add(r'(?:heroku|HEROKU)[_\s]*(?:api[_\s]*)?(?:key|token)["\s:=]+([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})', 'HEROKU_KEY', 0.95, 1, re.I)


# --- SQUARE ---
# Square Access Token
_add(r'\b(sq0atp-[a-zA-Z0-9\-_]{22})\b', 'SQUARE_TOKEN', 0.98, 1)

# Square OAuth Secret
_add(r'\b(sq0csp-[a-zA-Z0-9\-_]{43})\b', 'SQUARE_SECRET', 0.98, 1)


# --- SHOPIFY ---
# Shopify Access Token
_add(r'\b(shpat_[a-f0-9]{32})\b', 'SHOPIFY_TOKEN', 0.99, 1)

# Shopify API Key
_add(r'\b(shpka_[a-f0-9]{32})\b', 'SHOPIFY_KEY', 0.99, 1)

# Shopify Shared Secret
_add(r'\b(shpss_[a-f0-9]{32})\b', 'SHOPIFY_SECRET', 0.99, 1)


# --- DATADOG / MONITORING ---
# Datadog API Key
_add(r'(?:datadog|dd)[_\s]*(?:api[_\s]*)?key["\s:=]+([a-f0-9]{32})\b', 'DATADOG_KEY', 0.92, 1, re.I)

# Datadog Application Key
_add(r'(?:datadog|dd)[_\s]*(?:app(?:lication)?[_\s]*)?key["\s:=]+([a-f0-9]{40})\b', 'DATADOG_KEY', 0.92, 1, re.I)

# New Relic API Key
_add(r'\b(NRAK-[A-Z0-9]{27})\b', 'NEWRELIC_KEY', 0.98, 1)


# --- PRIVATE KEYS (PEM) ---
# RSA/DSA/EC Private Key Header
_add(r'(-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----)', 'PRIVATE_KEY', 0.99, 1)

# Private Key content (base64 block after header)
_add(r'-----BEGIN [A-Z ]+ PRIVATE KEY-----\s*([A-Za-z0-9+/=\s]{64,})\s*-----END', 'PRIVATE_KEY', 0.99, 1)

# SSH Private Key (OpenSSH format)
_add(r'(-----BEGIN OPENSSH PRIVATE KEY-----)', 'PRIVATE_KEY', 0.99, 1)

# PGP Private Key
_add(r'(-----BEGIN PGP PRIVATE KEY BLOCK-----)', 'PRIVATE_KEY', 0.99, 1)


# --- JWT ---
# JSON Web Token: header.payload.signature (all base64url)
_add(r'\b(eyJ[a-zA-Z0-9\-_]+\.eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+)\b', 'JWT', 0.98, 1)


# --- AUTH HEADERS ---
# Basic Auth header
_add(r'\b(Basic\s+[a-zA-Z0-9+/=]{20,})\b', 'BASIC_AUTH', 0.95, 1)

# Bearer Token (in authorization context)
_add(r'(?:Authorization|Bearer)[:\s]+Bearer\s+([a-zA-Z0-9\-_\.]{20,})', 'BEARER_TOKEN', 0.90, 1, re.I)


# --- DATABASE CONNECTION STRINGS ---
# PostgreSQL
_add(r'(postgres(?:ql)?://[^:]+:[^@]+@[^\s"\'<>]+)', 'DATABASE_URL', 0.98, 1, re.I)

# MySQL
_add(r'(mysql://[^:]+:[^@]+@[^\s"\'<>]+)', 'DATABASE_URL', 0.98, 1, re.I)

# MongoDB
_add(r'(mongodb(?:\+srv)?://[^:]+:[^@]+@[^\s"\'<>]+)', 'DATABASE_URL', 0.98, 1, re.I)

# Redis
_add(r'(redis://[^:]+:[^@]+@[^\s"\'<>]+)', 'DATABASE_URL', 0.98, 1, re.I)
_add(r'(rediss://[^:]+:[^@]+@[^\s"\'<>]+)', 'DATABASE_URL', 0.98, 1, re.I)

# Generic JDBC
_add(r'(jdbc:[a-z]+://[^:]+:[^@]+@[^\s"\'<>]+)', 'DATABASE_URL', 0.95, 1, re.I)

# SQL Server connection string
_add(r'(Server=[^;]+;.*Password=[^;]+)', 'DATABASE_URL', 0.92, 1, re.I)
_add(r'(Data Source=[^;]+;.*Password=[^;]+)', 'DATABASE_URL', 0.92, 1, re.I)


# --- AZURE ---
# Azure Storage Account Key
_add(r'(?:AccountKey|azure[_\s]*storage[_\s]*key)["\s:=]+([a-zA-Z0-9+/=]{88})', 'AZURE_STORAGE_KEY', 0.98, 1, re.I)

# Azure Connection String
_add(r'(DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[a-zA-Z0-9+/=]+)', 'AZURE_CONNECTION_STRING', 0.98, 1)

# Azure SAS Token
_add(r'(\?sv=\d{4}-\d{2}-\d{2}&[^"\s]+sig=[a-zA-Z0-9%]+)', 'AZURE_SAS_TOKEN', 0.95, 1)

# Azure Service Bus Connection String
_add(r'(Endpoint=sb://[^;]+;SharedAccessKeyName=[^;]+;SharedAccessKey=[a-zA-Z0-9+/=]+)', 'AZURE_CONNECTION_STRING', 0.98, 1)


# --- GENERIC SECRETS (CONTEXTUAL) ---
# Password in config/code (with quotes)
_add(r'(?:password|passwd|pwd)["\s:=]+["\']([^"\']{8,})["\']', 'PASSWORD', 0.85, 1, re.I)

# Password with international labels (FR: mot de passe, DE: Passwort, ES: contraseña, NL: wachtwoord, IT: parola/password, PT: senha)
# More permissive: no quotes required, min 5 chars, allows special chars
_add(r'(?:password|passwd|pwd|mot de passe|passwort|contraseña|wachtwoord|parola|senha)[:\s]+([^\s,.<>]{5,30})', 'PASSWORD', 0.80, 1, re.I)

# API key in config (generic)
_add(r'(?:api[_\s]?key|apikey|api[_\s]?secret)["\s:=]+["\']([a-zA-Z0-9\-_]{16,})["\']', 'API_KEY', 0.85, 1, re.I)

# Secret in config (generic)
_add(r'(?:secret|token|credential)["\s:=]+["\']([a-zA-Z0-9\-_]{16,})["\']', 'SECRET', 0.80, 1, re.I)

# Private key variable assignment
_add(r'(?:private[_\s]?key|priv[_\s]?key)["\s:=]+["\']([a-zA-Z0-9+/=\-_]{20,})["\']', 'PRIVATE_KEY', 0.85, 1, re.I)


# --- DETECTOR CLASS ---
class SecretsDetector(BaseDetector):
    """
    Detects API keys, tokens, and other secrets.
    
    High confidence patterns - these formats are distinctive
    and unlikely to appear in normal text.
    """
    
    name = "secrets"
    tier = Tier.PATTERN  # Same tier as patterns - format-based detection
    
    def detect(self, text: str) -> List[Span]:
        spans = []
        seen = set()  # Avoid duplicates
        
        for pattern, entity_type, confidence, group_idx in SECRETS_PATTERNS:
            for match in pattern.finditer(text):
                if group_idx > 0 and match.lastindex and group_idx <= match.lastindex:
                    value = match.group(group_idx)
                    start = match.start(group_idx)
                    end = match.end(group_idx)
                else:
                    value = match.group(0)
                    start = match.start()
                    end = match.end()
                
                if not value or not value.strip():
                    continue
                
                # Dedupe
                key = (start, end, value)
                if key in seen:
                    continue
                seen.add(key)
                
                # Additional validation for specific types
                if entity_type == 'JWT':
                    if not self._validate_jwt(value):
                        continue
                
                span = Span(
                    start=start,
                    end=end,
                    text=value,
                    entity_type=entity_type,
                    confidence=confidence,
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

        # Each part should be base64url
        for part in parts[:2]:  # Header and payload
            try:
                # Add padding if needed
                padded = part + '=' * (4 - len(part) % 4)
                # Replace URL-safe chars
                padded = padded.replace('-', '+').replace('_', '/')
                base64.b64decode(padded)
            except (ValueError, binascii.Error):
                return False

        return True
