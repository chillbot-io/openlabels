"""Tier 2: Secrets and credential detectors (API keys, tokens, private keys, JWTs)."""

import base64
import binascii
import logging
import regex  # Use regex module for ReDoS timeout protection (CVE-READY-003)
from typing import List, Tuple

from ..types import Span, Tier
from .base import BasePatternDetector
from .constants import (
    CONFIDENCE_HIGH,
    CONFIDENCE_LOW,
    CONFIDENCE_MEDIUM,
    CONFIDENCE_PERFECT,
    CONFIDENCE_RELIABLE,
    CONFIDENCE_VERY_HIGH,
    CONFIDENCE_WEAK,
)

logger = logging.getLogger(__name__)

from .pattern_registry import create_pattern_adder

SECRETS_PATTERNS: List[Tuple[regex.Pattern, str, float, int]] = []
_add = create_pattern_adder(SECRETS_PATTERNS)


# --- AWS ---
# AWS Access Key ID: Always starts with AKIA, ABIA, ACCA, AGPA, AIDA, AIPA, ANPA, ANVA, APKA, AROA, ASCA, ASIA
_AWS_KEY_PREFIXES = r'(?:AKIA|ABIA|ACCA|AGPA|AIDA|AIPA|ANPA|ANVA|APKA|AROA|ASCA|ASIA)'
_add(rf'\b({_AWS_KEY_PREFIXES}[A-Z0-9]{{16}})\b', 'AWS_ACCESS_KEY', CONFIDENCE_PERFECT, 1)

# AWS Secret Access Key: 40 characters, base64-ish, usually after aws_secret or similar context
_add(r'(?:aws_secret_access_key|aws_secret|secret_key|secretaccesskey)["\s:=]+([A-Za-z0-9+/]{40})', 'AWS_SECRET_KEY', CONFIDENCE_HIGH, 1, regex.I)

# AWS Session Token (temporary credentials)
_add(r'(?:aws_session_token|session_token)["\s:=]+([A-Za-z0-9+/=]{100,})', 'AWS_SESSION_TOKEN', CONFIDENCE_RELIABLE, 1, regex.I)


# --- GITHUB ---
# GitHub Personal Access Token (classic and fine-grained)
_add(r'\b(ghp_[a-zA-Z0-9]{36})\b', 'GITHUB_TOKEN', CONFIDENCE_PERFECT, 1)  # Personal access token
_add(r'\b(gho_[a-zA-Z0-9]{36})\b', 'GITHUB_TOKEN', CONFIDENCE_PERFECT, 1)  # OAuth access token
_add(r'\b(ghu_[a-zA-Z0-9]{36})\b', 'GITHUB_TOKEN', CONFIDENCE_PERFECT, 1)  # User-to-server token
_add(r'\b(ghs_[a-zA-Z0-9]{36})\b', 'GITHUB_TOKEN', CONFIDENCE_PERFECT, 1)  # Server-to-server token
_add(r'\b(ghr_[a-zA-Z0-9]{36})\b', 'GITHUB_TOKEN', CONFIDENCE_PERFECT, 1)  # Refresh token

# GitHub App installation token (older format)
_add(r'\b(v1\.[a-f0-9]{40})\b', 'GITHUB_TOKEN', CONFIDENCE_MEDIUM, 1)


# --- GITLAB ---
# GitLab Personal Access Token
_add(r'\b(glpat-[a-zA-Z0-9\-_]{20,})\b', 'GITLAB_TOKEN', CONFIDENCE_PERFECT, 1)

# GitLab Pipeline Token
_add(r'\b(glptt-[a-zA-Z0-9]{20,})\b', 'GITLAB_TOKEN', CONFIDENCE_VERY_HIGH, 1)

# GitLab Runner Token
_add(r'\b(glrt-[a-zA-Z0-9\-_]{20,})\b', 'GITLAB_TOKEN', CONFIDENCE_VERY_HIGH, 1)


# --- SLACK ---
# Slack Bot Token
_add(r'\b(xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24})\b', 'SLACK_TOKEN', CONFIDENCE_PERFECT, 1)

# Slack User Token
_add(r'\b(xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-f0-9]{32})\b', 'SLACK_TOKEN', CONFIDENCE_PERFECT, 1)

# Slack App Token
_add(r'\b(xoxa-[0-9]+-[a-zA-Z0-9]+)\b', 'SLACK_TOKEN', CONFIDENCE_HIGH, 1)

# Slack Configuration Token
_add(r'\b(xoxr-[0-9]+-[a-zA-Z0-9]+)\b', 'SLACK_TOKEN', CONFIDENCE_HIGH, 1)

# Slack Webhook URL
_add(r'(https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+)', 'SLACK_WEBHOOK', CONFIDENCE_PERFECT, 1)


# --- STRIPE ---
# Stripe Secret Key (live)
_add(r'\b(sk_live_[a-zA-Z0-9]{24,})\b', 'STRIPE_KEY', CONFIDENCE_PERFECT, 1)

# Stripe Secret Key (test) - lower confidence since it's test
_add(r'\b(sk_test_[a-zA-Z0-9]{24,})\b', 'STRIPE_KEY', CONFIDENCE_MEDIUM, 1)

# Stripe Publishable Key (live)
_add(r'\b(pk_live_[a-zA-Z0-9]{24,})\b', 'STRIPE_KEY', CONFIDENCE_HIGH, 1)

# Stripe Publishable Key (test)
_add(r'\b(pk_test_[a-zA-Z0-9]{24,})\b', 'STRIPE_KEY', CONFIDENCE_LOW, 1)

# Stripe Restricted Key
_add(r'\b(rk_live_[a-zA-Z0-9]{24,})\b', 'STRIPE_KEY', CONFIDENCE_PERFECT, 1)
_add(r'\b(rk_test_[a-zA-Z0-9]{24,})\b', 'STRIPE_KEY', CONFIDENCE_MEDIUM, 1)

# Stripe Webhook Secret
_add(r'\b(whsec_[a-zA-Z0-9]{32,})\b', 'STRIPE_KEY', CONFIDENCE_VERY_HIGH, 1)


# --- GOOGLE ---
# Google API Key
_add(r'\b(AIza[a-zA-Z0-9\-_]{35})\b', 'GOOGLE_API_KEY', CONFIDENCE_VERY_HIGH, 1)

# Google OAuth Client ID
_add(r'\b(\d{12}-[a-z0-9]{32}\.apps\.googleusercontent\.com)\b', 'GOOGLE_OAUTH_ID', CONFIDENCE_HIGH, 1)

# Google OAuth Client Secret (contextual)
_add(r'(?:client_secret|google_secret)["\s:=]+([a-zA-Z0-9\-_]{24})', 'GOOGLE_OAUTH_SECRET', CONFIDENCE_MEDIUM, 1, regex.I)

# Firebase API Key (same format as Google)
_add(r'(?:firebase|fcm)["\s:=_-]*(?:api[_-]?key|server[_-]?key)["\s:=]+([a-zA-Z0-9\-_]{39})', 'FIREBASE_KEY', CONFIDENCE_HIGH, 1, regex.I)


# --- TWILIO ---
# Twilio Account SID
_add(r'\b(AC[a-f0-9]{32})\b', 'TWILIO_ACCOUNT_SID', CONFIDENCE_VERY_HIGH, 1)

# Twilio API Key SID
_add(r'\b(SK[a-f0-9]{32})\b', 'TWILIO_KEY', CONFIDENCE_VERY_HIGH, 1)

# Twilio Auth Token (contextual)
_add(r'(?:twilio|auth)[_\s]*token["\s:=]+([a-f0-9]{32})\b', 'TWILIO_TOKEN', CONFIDENCE_RELIABLE, 1, regex.I)


# --- SENDGRID ---
# SendGrid API Key
_add(r'\b(SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43})\b', 'SENDGRID_KEY', CONFIDENCE_PERFECT, 1)


# --- MAILCHIMP ---
# Mailchimp API Key: 32 hex chars + datacenter
_add(r'\b([a-f0-9]{32}-us[0-9]{1,2})\b', 'MAILCHIMP_KEY', CONFIDENCE_VERY_HIGH, 1)


# --- DISCORD ---
# Discord Bot Token: base64 user id + timestamp + hmac
_add(r'\b([MN][a-zA-Z0-9]{23,}\.[a-zA-Z0-9\-_]{6}\.[a-zA-Z0-9\-_]{27,})\b', 'DISCORD_TOKEN', CONFIDENCE_HIGH, 1)

# Discord Webhook URL
_add(r'(https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/[0-9]+/[a-zA-Z0-9\-_]+)', 'DISCORD_WEBHOOK', CONFIDENCE_VERY_HIGH, 1)


# --- NPM / PYPI / NUGET ---
# NPM Token
_add(r'\b(npm_[a-zA-Z0-9]{36})\b', 'NPM_TOKEN', CONFIDENCE_PERFECT, 1)

# NPM Token (older format)
_add(r'//registry\.npmjs\.org/:_authToken=([a-f0-9\-]{36})', 'NPM_TOKEN', CONFIDENCE_HIGH, 1)

# PyPI Token
_add(r'\b(pypi-[a-zA-Z0-9\-_]{50,})\b', 'PYPI_TOKEN', CONFIDENCE_PERFECT, 1)

# NuGet API Key
_add(r'\b(oy2[a-z0-9]{43})\b', 'NUGET_KEY', CONFIDENCE_HIGH, 1)


# --- HEROKU ---
# Heroku API Key (UUID format in heroku context)
_add(r'(?:heroku|HEROKU)[_\s]*(?:api[_\s]*)?(?:key|token)["\s:=]+([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})', 'HEROKU_KEY', CONFIDENCE_HIGH, 1, regex.I)


# --- SQUARE ---
# Square Access Token
_add(r'\b(sq0atp-[a-zA-Z0-9\-_]{22})\b', 'SQUARE_TOKEN', CONFIDENCE_VERY_HIGH, 1)

# Square OAuth Secret
_add(r'\b(sq0csp-[a-zA-Z0-9\-_]{43})\b', 'SQUARE_SECRET', CONFIDENCE_VERY_HIGH, 1)


# --- SHOPIFY ---
# Shopify Access Token
_add(r'\b(shpat_[a-f0-9]{32})\b', 'SHOPIFY_TOKEN', CONFIDENCE_PERFECT, 1)

# Shopify API Key
_add(r'\b(shpka_[a-f0-9]{32})\b', 'SHOPIFY_KEY', CONFIDENCE_PERFECT, 1)

# Shopify Shared Secret
_add(r'\b(shpss_[a-f0-9]{32})\b', 'SHOPIFY_SECRET', CONFIDENCE_PERFECT, 1)


# --- DATADOG / MONITORING ---
# Datadog API Key
_add(r'(?:datadog|dd)[_\s]*(?:api[_\s]*)?key["\s:=]+([a-f0-9]{32})\b', 'DATADOG_KEY', CONFIDENCE_RELIABLE, 1, regex.I)

# Datadog Application Key
_add(r'(?:datadog|dd)[_\s]*(?:app(?:lication)?[_\s]*)?key["\s:=]+([a-f0-9]{40})\b', 'DATADOG_KEY', CONFIDENCE_RELIABLE, 1, regex.I)

# New Relic API Key
_add(r'\b(NRAK-[A-Z0-9]{27})\b', 'NEWRELIC_KEY', CONFIDENCE_VERY_HIGH, 1)


# --- PRIVATE KEYS (PEM) ---
# RSA/DSA/EC Private Key Header
_add(r'(-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----)', 'PRIVATE_KEY', CONFIDENCE_PERFECT, 1)

# Private Key content (base64 block after header)
_add(r'-----BEGIN [A-Z ]+ PRIVATE KEY-----\s*([A-Za-z0-9+/=\s]{64,})\s*-----END', 'PRIVATE_KEY', CONFIDENCE_PERFECT, 1)

# SSH Private Key (OpenSSH format)
_add(r'(-----BEGIN OPENSSH PRIVATE KEY-----)', 'PRIVATE_KEY', CONFIDENCE_PERFECT, 1)

# PGP Private Key
_add(r'(-----BEGIN PGP PRIVATE KEY BLOCK-----)', 'PRIVATE_KEY', CONFIDENCE_PERFECT, 1)


# --- JWT ---
# JSON Web Token: header.payload.signature (all base64url)
_add(r'\b(eyJ[a-zA-Z0-9\-_]+\.eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+)\b', 'JWT', CONFIDENCE_VERY_HIGH, 1)


# --- AUTH HEADERS ---
# Basic Auth header
_add(r'\b(Basic\s+[a-zA-Z0-9+/=]{20,})\b', 'BASIC_AUTH', CONFIDENCE_HIGH, 1)

# Bearer Token (in authorization context)
_add(r'(?:Authorization|Bearer)[:\s]+Bearer\s+([a-zA-Z0-9\-_\.]{20,})', 'BEARER_TOKEN', CONFIDENCE_MEDIUM, 1, regex.I)


# --- DATABASE CONNECTION STRINGS ---
# PostgreSQL
_add(r'(postgres(?:ql)?://[^:]+:[^@]+@[^\s"\'<>]+)', 'DATABASE_URL', CONFIDENCE_VERY_HIGH, 1, regex.I)

# MySQL
_add(r'(mysql://[^:]+:[^@]+@[^\s"\'<>]+)', 'DATABASE_URL', CONFIDENCE_VERY_HIGH, 1, regex.I)

# MongoDB
_add(r'(mongodb(?:\+srv)?://[^:]+:[^@]+@[^\s"\'<>]+)', 'DATABASE_URL', CONFIDENCE_VERY_HIGH, 1, regex.I)

# Redis
_add(r'(redis://[^:]+:[^@]+@[^\s"\'<>]+)', 'DATABASE_URL', CONFIDENCE_VERY_HIGH, 1, regex.I)
_add(r'(rediss://[^:]+:[^@]+@[^\s"\'<>]+)', 'DATABASE_URL', CONFIDENCE_VERY_HIGH, 1, regex.I)

# Generic JDBC
_add(r'(jdbc:[a-z]+://[^:]+:[^@]+@[^\s"\'<>]+)', 'DATABASE_URL', CONFIDENCE_HIGH, 1, regex.I)

# SQL Server connection string
_add(r'(Server=[^;]+;.*Password=[^;]+)', 'DATABASE_URL', CONFIDENCE_RELIABLE, 1, regex.I)
_add(r'(Data Source=[^;]+;.*Password=[^;]+)', 'DATABASE_URL', CONFIDENCE_RELIABLE, 1, regex.I)


# --- AZURE ---
# Azure Storage Account Key
_add(r'(?:AccountKey|azure[_\s]*storage[_\s]*key)["\s:=]+([a-zA-Z0-9+/=]{88})', 'AZURE_STORAGE_KEY', CONFIDENCE_VERY_HIGH, 1, regex.I)

# Azure Connection String
_add(r'(DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[a-zA-Z0-9+/=]+)', 'AZURE_CONNECTION_STRING', CONFIDENCE_VERY_HIGH, 1)

# Azure SAS Token
_add(r'(\?sv=\d{4}-\d{2}-\d{2}&[^"\s]+sig=[a-zA-Z0-9%]+)', 'AZURE_SAS_TOKEN', CONFIDENCE_HIGH, 1)

# Azure Service Bus Connection String
_add(r'(Endpoint=sb://[^;]+;SharedAccessKeyName=[^;]+;SharedAccessKey=[a-zA-Z0-9+/=]+)', 'AZURE_CONNECTION_STRING', CONFIDENCE_VERY_HIGH, 1)


# --- AI/ML PLATFORMS ---
# OpenAI API Key (multiple formats)
_add(r'\b(sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20})\b', 'OPENAI_API_KEY', CONFIDENCE_PERFECT, 1)
_add(r'\b(sk-proj-[a-zA-Z0-9\-_]{20,})\b', 'OPENAI_API_KEY', CONFIDENCE_PERFECT, 1)
_add(r'\b(sk-[a-zA-Z0-9]{32,})\b', 'OPENAI_API_KEY', CONFIDENCE_HIGH, 1)

# Anthropic API Key
_add(r'\b(sk-ant-[a-zA-Z0-9\-_]{32,})\b', 'ANTHROPIC_API_KEY', CONFIDENCE_PERFECT, 1)

# Hugging Face Token
_add(r'\b(hf_[a-zA-Z0-9]{20,})\b', 'HUGGINGFACE_TOKEN', CONFIDENCE_PERFECT, 1)

# Cohere API Key
_add(r'(?:cohere)[_\s]*(?:api[_\s]*)?key["\s:=]+([a-zA-Z0-9]{20,})', 'COHERE_API_KEY', CONFIDENCE_RELIABLE, 1, regex.I)

# Replicate API Token
_add(r'\b(r8_[a-zA-Z0-9]{20,})\b', 'REPLICATE_API_KEY', CONFIDENCE_PERFECT, 1)

# Groq API Key
_add(r'\b(gsk_[a-zA-Z0-9]{48,})\b', 'GROQ_API_KEY', CONFIDENCE_PERFECT, 1)


# --- CI/CD PLATFORMS ---
# CircleCI API Token
_add(r'(?:circleci|circle)[_\s]*(?:api[_\s]*)?(?:token|key)["\s:=]+([a-f0-9]{40})', 'CIRCLECI_TOKEN', CONFIDENCE_RELIABLE, 1, regex.I)

# Azure DevOps Personal Access Token
_add(r'\b([a-z0-9]{52})\b(?=.*(?:azure|devops|visualstudio))', 'AZURE_DEVOPS_PAT', CONFIDENCE_MEDIUM, 1, regex.I)

# Vercel Token
_add(r'(?:vercel|zeit)[_\s]*(?:api[_\s]*)?(?:token|key)["\s:=]+([a-zA-Z0-9]{24})', 'VERCEL_TOKEN', CONFIDENCE_RELIABLE, 1, regex.I)

# Netlify Token
_add(r'(?:netlify)[_\s]*(?:api[_\s]*)?(?:token|key)["\s:=]+([a-zA-Z0-9\-_]{40,})', 'NETLIFY_TOKEN', CONFIDENCE_RELIABLE, 1, regex.I)

# Render API Key
_add(r'\b(rnd_[a-zA-Z0-9]{32})\b', 'RENDER_API_KEY', CONFIDENCE_VERY_HIGH, 1)

# Railway Token
_add(r'(?:railway)[_\s]*(?:api[_\s]*)?(?:token|key)["\s:=]+([a-f0-9\-]{36})', 'RAILWAY_TOKEN', CONFIDENCE_RELIABLE, 1, regex.I)

# Fly.io Token
_add(r'\b(fo1_[a-zA-Z0-9\-_]{40,})\b', 'FLY_TOKEN', CONFIDENCE_VERY_HIGH, 1)


# --- CONTAINER REGISTRIES ---
# Docker Hub Token
_add(r'\b(dckr_pat_[a-zA-Z0-9\-_]{20,})\b', 'DOCKER_HUB_TOKEN', CONFIDENCE_PERFECT, 1)


# --- COMMUNICATION PLATFORMS ---
# Telegram Bot Token (format: bot_id:token)
_add(r'\b(\d{8,10}:[a-zA-Z0-9_\-]{30,})\b', 'TELEGRAM_BOT_TOKEN', CONFIDENCE_VERY_HIGH, 1)

# Microsoft Teams Webhook
_add(r'(https://[a-z0-9]+\.webhook\.office\.com/webhookb2/[a-f0-9\-]+/IncomingWebhook/[a-zA-Z0-9]+/[a-f0-9\-]+)', 'TEAMS_WEBHOOK', CONFIDENCE_VERY_HIGH, 1)

# Twitch OAuth Token
_add(r'\b(oauth:[a-z0-9]{30})\b', 'TWITCH_TOKEN', CONFIDENCE_VERY_HIGH, 1, regex.I)

# Zoom JWT Token (contextual)
_add(r'(?:zoom)[_\s]*(?:jwt|api)[_\s]*(?:token|key|secret)["\s:=]+([a-zA-Z0-9\-_]{32,})', 'ZOOM_JWT', CONFIDENCE_RELIABLE, 1, regex.I)

# Zoom SDK Key/Secret
_add(r'(?:zoom)[_\s]*(?:sdk)[_\s]*(?:key|secret)["\s:=]+([a-zA-Z0-9]{22,})', 'ZOOM_SDK_KEY', CONFIDENCE_RELIABLE, 1, regex.I)


# --- ADDITIONAL PAYMENT PROCESSORS ---
# PayPal Client ID/Secret (contextual)
_add(r'(?:paypal)[_\s]*(?:client[_\s]*)?id["\s:=]+([A-Za-z0-9\-_]{80})', 'PAYPAL_CLIENT_ID', CONFIDENCE_RELIABLE, 1, regex.I)
_add(r'(?:paypal)[_\s]*(?:client[_\s]*)?secret["\s:=]+([A-Za-z0-9\-_]{80})', 'PAYPAL_SECRET', CONFIDENCE_RELIABLE, 1, regex.I)

# Plaid API Keys
_add(r'(?:plaid)[_\s]*(?:client[_\s]*)?id["\s:=]+([a-f0-9]{24})', 'PLAID_CLIENT_ID', CONFIDENCE_RELIABLE, 1, regex.I)
_add(r'(?:plaid)[_\s]*secret["\s:=]+([a-f0-9]{30})', 'PLAID_SECRET', CONFIDENCE_RELIABLE, 1, regex.I)

# Adyen API Key
_add(r'\b(AQE[a-zA-Z0-9\-_]{50,})\b', 'ADYEN_API_KEY', CONFIDENCE_VERY_HIGH, 1)


# --- SAAS PLATFORMS ---
# Atlassian API Token
_add(r'(?:atlassian|jira|confluence)[_\s]*(?:api[_\s]*)?(?:token|key)["\s:=]+([a-zA-Z0-9]{24})', 'ATLASSIAN_TOKEN', CONFIDENCE_RELIABLE, 1, regex.I)

# Notion API Token
_add(r'\b(secret_[a-zA-Z0-9]{32,})\b', 'NOTION_TOKEN', CONFIDENCE_PERFECT, 1)
_add(r'\b(ntn_[a-zA-Z0-9]{32,})\b', 'NOTION_TOKEN', CONFIDENCE_PERFECT, 1)

# Airtable API Key
_add(r'\b(key[a-zA-Z0-9]{14})\b', 'AIRTABLE_KEY', CONFIDENCE_MEDIUM, 1)
_add(r'\b(pat[a-zA-Z0-9]{10,}\.[a-f0-9]{32,})\b', 'AIRTABLE_KEY', CONFIDENCE_VERY_HIGH, 1)

# Linear API Key
_add(r'\b(lin_api_[a-zA-Z0-9]{20,})\b', 'LINEAR_TOKEN', CONFIDENCE_PERFECT, 1)

# Figma Access Token
_add(r'\b(figd_[a-zA-Z0-9\-_]{40,})\b', 'FIGMA_TOKEN', CONFIDENCE_VERY_HIGH, 1)

# Sentry DSN
_add(r'(https://[a-f0-9]+@(?:o\d+\.)?(?:sentry\.io|[a-z]+\.ingest\.sentry\.io)/\d+)', 'SENTRY_DSN', CONFIDENCE_VERY_HIGH, 1)

# PagerDuty API Key
_add(r'\b(u\+[a-zA-Z0-9\-_]{18})\b', 'PAGERDUTY_KEY', CONFIDENCE_HIGH, 1)

# LaunchDarkly SDK Key
_add(r'\b(sdk-[a-f0-9\-]{36})\b', 'LAUNCHDARKLY_KEY', CONFIDENCE_VERY_HIGH, 1)

# Segment Write Key
_add(r'(?:segment)[_\s]*(?:write[_\s]*)?key["\s:=]+([a-zA-Z0-9]{32})', 'SEGMENT_KEY', CONFIDENCE_RELIABLE, 1, regex.I)

# Intercom Access Token
_add(r'\b(dG9rO[a-zA-Z0-9\-_]{40,})\b', 'INTERCOM_TOKEN', CONFIDENCE_HIGH, 1)


# --- DATABASE PLATFORMS ---
# Supabase API Key
_add(r'\b(sbp_[a-f0-9]{40})\b', 'SUPABASE_KEY', CONFIDENCE_PERFECT, 1)
# Supabase anon/service key with context (HS256 JWT format)
_add(r'(?:supabase)[_\s]*(?:anon|service)?[_\s]*(?:key|token)["\s:=]+(eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+)', 'SUPABASE_KEY', CONFIDENCE_VERY_HIGH, 1, regex.I)

# PlanetScale Token
_add(r'\b(pscale_tkn_[a-zA-Z0-9\-_]{43})\b', 'PLANETSCALE_TOKEN', CONFIDENCE_PERFECT, 1)

# Databricks Token
_add(r'\b(dapi[a-f0-9]{32})\b', 'DATABRICKS_TOKEN', CONFIDENCE_VERY_HIGH, 1)

# Algolia Admin Key
_add(r'(?:algolia)[_\s]*(?:admin[_\s]*)?(?:api[_\s]*)?key["\s:=]+([a-f0-9]{32})', 'ALGOLIA_KEY', CONFIDENCE_RELIABLE, 1, regex.I)

# Grafana API Token
_add(r'\b(glc_[a-zA-Z0-9\-_]{32,})\b', 'GRAFANA_TOKEN', CONFIDENCE_VERY_HIGH, 1)
_add(r'\b(glsa_[a-zA-Z0-9\-_]{32,})\b', 'GRAFANA_TOKEN', CONFIDENCE_VERY_HIGH, 1)


# --- EMAIL SERVICES ---
# Postmark Server Token
_add(r'(?:postmark)[_\s]*(?:server[_\s]*)?(?:api[_\s]*)?(?:token|key)["\s:=]+([a-f0-9\-]{36})', 'POSTMARK_TOKEN', CONFIDENCE_RELIABLE, 1, regex.I)

# Mailgun API Key
_add(r'\b(key-[a-f0-9]{32})\b', 'MAILGUN_KEY', CONFIDENCE_VERY_HIGH, 1)

# Resend API Key
_add(r'\b(re_[a-zA-Z0-9]{32})\b', 'RESEND_KEY', CONFIDENCE_VERY_HIGH, 1)


# --- ADDITIONAL CLOUD PROVIDERS ---
# DigitalOcean Token
_add(r'\b(dop_v1_[a-f0-9]{64})\b', 'DIGITALOCEAN_TOKEN', CONFIDENCE_PERFECT, 1)

# Alibaba Cloud Access Key
_add(r'\b(LTAI[a-zA-Z0-9]{12,20})\b', 'ALIBABA_ACCESS_KEY', CONFIDENCE_VERY_HIGH, 1)


# --- GENERIC SECRETS (CONTEXTUAL) ---
# Password in config/code (with quotes)
_add(r'(?:password|passwd|pwd)["\s:=]+["\']([^"\']{8,})["\']', 'PASSWORD', CONFIDENCE_LOW, 1, regex.I)

# Password with international labels (FR: mot de passe, DE: Passwort, ES: contraseña, NL: wachtwoord, IT: parola/password, PT: senha)
# More permissive: no quotes required, min 5 chars, allows special chars
_add(r'(?:password|passwd|pwd|mot de passe|passwort|contraseña|wachtwoord|parola|senha)[:\s]+([^\s,.<>]{5,30})', 'PASSWORD', CONFIDENCE_WEAK, 1, regex.I)

# API key in config (generic)
_add(r'(?:api[_\s]?key|apikey|api[_\s]?secret)["\s:=]+["\']([a-zA-Z0-9\-_]{16,})["\']', 'API_KEY', CONFIDENCE_LOW, 1, regex.I)

# Secret in config (generic)
_add(r'(?:secret|token|credential)["\s:=]+["\']([a-zA-Z0-9\-_]{16,})["\']', 'SECRET', CONFIDENCE_WEAK, 1, regex.I)

# Private key variable assignment
_add(r'(?:private[_\s]?key|priv[_\s]?key)["\s:=]+["\']([a-zA-Z0-9+/=\-_]{20,})["\']', 'PRIVATE_KEY', CONFIDENCE_LOW, 1, regex.I)


# --- DETECTOR CLASS ---
class SecretsDetector(BasePatternDetector):
    """
    Detects API keys, tokens, and other secrets.

    High confidence patterns - these formats are distinctive
    and unlikely to appear in normal text.
    """

    name = "secrets"
    tier = Tier.PATTERN  # Same tier as patterns - format-based detection

    def get_patterns(self):
        """Return secrets patterns."""
        return SECRETS_PATTERNS

    def detect(self, text: str) -> List[Span]:
        """Detect secrets in text with logging."""
        spans = super().detect(text)

        if spans:
            # Summarize by entity type
            type_counts = {}
            for span in spans:
                type_counts[span.entity_type] = type_counts.get(span.entity_type, 0) + 1
            logger.info(f"SecretsDetector found {len(spans)} secrets: {type_counts}")

            # Log high-severity findings at DEBUG level (don't log actual values)
            high_severity = ['AWS_ACCESS_KEY', 'AWS_SECRET_KEY', 'PRIVATE_KEY', 'DATABASE_URL', 'PASSWORD']
            for span in spans:
                if span.entity_type in high_severity:
                    logger.debug(f"High-severity secret detected: {span.entity_type} at position {span.start}-{span.end}")

        return spans

    def _validate_match(self, entity_type: str, value: str) -> bool:
        """Validate matched values, especially JWTs."""
        if entity_type == 'JWT':
            is_valid = self._validate_jwt(value)
            if not is_valid:
                logger.debug(f"JWT validation failed for token at matched position")
            return is_valid
        return True

    def _validate_jwt(self, token: str) -> bool:
        """Basic JWT structure validation."""
        parts = token.split('.')
        if len(parts) != 3:
            logger.debug(f"JWT validation failed: expected 3 parts, got {len(parts)}")
            return False

        # Each part should be base64url
        for i, part in enumerate(parts[:2]):  # Header and payload
            try:
                # Add padding if needed
                padded = part + '=' * (4 - len(part) % 4)
                # Replace URL-safe chars
                padded = padded.replace('-', '+').replace('_', '/')
                base64.b64decode(padded)
            except (ValueError, binascii.Error) as e:
                logger.debug(f"JWT validation failed: part {i} is not valid base64url: {e}")
                return False

        return True
