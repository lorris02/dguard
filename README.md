# DGuard

A self-hosted compliance and audit-logging proxy for Anthropic API calls. Route your team's AI API traffic through DGuard to get full visibility, sensitive-data scanning, and automatic blocking — without touching your existing code beyond a base URL swap.

## How it works

```
Your App  →  DGuard (:8000)  →  api.anthropic.com
                  ↓
              SQLite log
```

Every request is scanned for sensitive data before being forwarded. High-risk content (API keys, AWS keys, private keys) is blocked and logged. 
