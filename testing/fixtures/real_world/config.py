"""
Production configuration for the payment processing service.
"""
import os

# AWS Configuration
AWS_ACCESS_KEY = "AKIAI44QH8DHBEXAMPLE"
AWS_SECRET_KEY = "je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY"
AWS_REGION = "eu-west-1"

# GitHub integration
GITHUB_PAT = "ghp_R8nKbCdEfGhIjKlMnOpQrStUvWxYz0123456"

# Slack webhook for alerts
SLACK_WEBHOOK = "https://hooks.slack.com/services/T024BE7LD/B024BE7LD/abcdefghijklmnopqrstuvwx"

# Database connections
POSTGRES_URI = "postgresql://appuser:X9$kLm#2pQw@prod-db.us-east-1.rds.amazonaws.com:5432/payments"
MONGO_URI = "mongodb+srv://admin:M0ng0Secr3t!@cluster0.abc123.mongodb.net/analytics"

# Stripe keys for payment processing
STRIPE_API_KEY = "sk_live_0123456789abcdefghijklmn"

# Private key for JWT signing (RSA)
JWT_PRIVATE_KEY = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy5AoV7THGHvhBGbxmFHBDa
OpHMQjFqKyEJD3DsHYDnBMhrwbGEKJiWMPDgGmLEXHPmMYS2ePmHMBUPNQWDACLj
k6D9K1gRsA0aJ2iWuFJyMnWFgkdOnFRGYMBW3NlX6HmsE2DPlXRVUFkWaQih1pOP
-----END RSA PRIVATE KEY-----"""

# Ethereum wallet for gas payments
ETH_PRIVATE_KEY = "0x4c0883a69102937d6231471b5dbb6204fe512961708279f23efb77094a853287"
ethereum_private_key = "4c0883a69102937d6231471b5dbb6204fe512961708279f23efb77094a853287"

# HashiCorp Vault
VAULT_TOKEN = "hvs.CAESIGxyz789abc123def456ghi012jkl345mno678"

# HuggingFace
HF_TOKEN = "hf_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh"

# SendGrid
SENDGRID_KEY = "SG.xyzABCDEFGHIJKLMNOPQRST.1234567890abcdefghijklmnopqrstuvwxyz1234567"

# Notion
NOTION_TOKEN = "secret_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmn"

# PyPI
PYPI_TOKEN = "pypi-AgEIcHlwaS5vcmcABCDEFGHIJKLMNOPQRSTUVWXYZ"

# Databricks
DATABRICKS_TOKEN = "dapi0123456789abcdef0123456789abcdef"

# Telegram Bot
TELEGRAM_BOT_TOKEN = "6234567890:AAHfiqksKZ7MNvhKYOCMGZZsecrettoken"

# ============================================================
# FALSE POSITIVES - these should NOT be detected as real secrets
# ============================================================

# Hex color codes
BRAND_PRIMARY = "#FF5733"
BRAND_SECONDARY = "#2ECC71"
BACKGROUND_COLOR = "#1A1A2E"

# UUIDs
REQUEST_ID = "550e8400-e29b-41d4-a716-446655440000"
SESSION_ID = "6ba7b810-9dad-11d1-80b4-00c04fd430c8"
TRACE_ID = "f47ac10b-58cc-4372-a567-0e02b2c3d479"

# Example/placeholder values
EXAMPLE_KEY = "AKIAIOSFODNN7EXAMPLE"
PLACEHOLDER_TOKEN = "<your-github-token-here>"
TEMPLATE_SECRET = "${SECRET_KEY}"

# Git SHAs (40-char hex but not secrets)
LATEST_COMMIT = "da39a3ee5e6b4b0d3255bfef95601890afd80709"

# Base64 that is just data, not a secret
LOGO_BASE64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk"

# Version strings
API_VERSION = "v2.1.0"
BUILD_NUMBER = "20240315.1234"
