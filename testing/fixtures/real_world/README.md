# Invoice Processing Service

## Quick Start

Clone the repo and configure your environment:

```bash
export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMP04
export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYzzzKEY99999"
```

## API Authentication

Use your GitHub personal access token:

```
Authorization: Bearer ghp_nNmMlLkKjJiIhHgGfFeEdDcCbBaA9876543210
```

## Slack Integration

Configure the Slack bot token in your environment:

```
SLACK_BOT_TOKEN=xoxb-111222333444-555666777888-AbCdEfGhIjKlMnOpQrStUvWx
```

## Database Setup

Default connection string for local development:

```
postgresql://devuser:D3vP@ss2024@localhost:5432/invoices_dev
```

## Firebase Configuration

```json
{
  "apiKey": "AIzaSyBcDeFgHiJkLmNoPqRsTuVwXyZ99999999",
  "authDomain": "myapp.firebaseapp.com",
  "projectId": "myapp-prod"
}
```

## Example Configuration

Replace the placeholder values below with your actual keys:

| Setting | Value |
|---------|-------|
| API Key | `AKIAIOSFODNN7EXAMPLE` |
| Region  | `us-east-1` |
| Bucket  | `my-app-assets` |

## Monitoring

Sentry DSN: `https://abc123@o123456.ingest.sentry.io/1234567`

## Changelog

- v3.2.1: Fixed payment retry logic
- v3.2.0: Added Stripe webhook validation
- v3.1.0: Initial release
