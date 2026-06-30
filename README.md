# DGuard

A self-hosted compliance and audit-logging proxy for Anthropic API calls. Route your team's AI API traffic through DGuard to get full visibility, sensitive-data scanning, and automatic blocking — without touching your existing code beyond a base URL swap.

## How it works

```
Your App  →  DGuard (:8000)  →  api.anthropic.com
                  ↓
              SQLite log
```

Every request is scanned for sensitive data before being forwarded. High-risk content (API keys, AWS keys, private keys) is blocked and logged. Lower-risk findings (emails, phone numbers, IPs, SSNs, credit cards) are flagged and logged but still forwarded.

## Setup

### 1. Clone and install

```bash
git clone <your-repo>
cd dguard
python -m venv venv
# Windows:
venv\Scripts\activate
# Mac/Linux:
source venv/bin/activate

pip install -r requirements.txt
```

### 2. Configure

```bash
cp .env.example .env
# Edit .env — add your Anthropic API key
```

`.env` settings:

| Variable | Required | Default | Description |
|---|---|---|---|
| `ANTHROPIC_API_KEY` | Yes | — | Your Anthropic API key |
| `DATABASE_PATH` | No | `dguard.db` | Path to the SQLite database file |
| `LOG_FULL_CONTENT` | No | `true` | Store prompt/response text in logs. Set `false` for metadata-only logging |

### 3. Run

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

For development with auto-reload:
```bash
uvicorn app.main:app --reload
```

## Pointing clients at the proxy

Change your Anthropic client's base URL from `https://api.anthropic.com` to `http://localhost:8000` (or your server's address). The proxy mirrors the exact same API surface.

**Python (anthropic SDK):**
```python
import anthropic

client = anthropic.Anthropic(
    api_key="any-string",          # proxy ignores this, uses its own key
    base_url="http://localhost:8000",
)

response = client.messages.create(
    model="claude-sonnet-4-6",
    max_tokens=1024,
    messages=[{"role": "user", "content": "Hello!"}],
    extra_headers={"X-User-Id": "user-123"},  # optional — for audit tracking
)
```

**curl:**
```bash
curl http://localhost:8000/v1/messages \
  -H "Content-Type: application/json" \
  -H "X-User-Id: user-123" \
  -d '{
    "model": "claude-sonnet-4-6",
    "max_tokens": 1024,
    "messages": [{"role": "user", "content": "Hello!"}]
  }'
```

## Audit log endpoints

| Endpoint | Description |
|---|---|
| `GET /logs` | Recent requests (metadata only, no prompt text) |
| `GET /logs?flagged_only=true` | Only flagged requests |
| `GET /logs?blocked_only=true` | Only blocked requests |
| `GET /logs?limit=100` | Control page size (max 500) |
| `GET /logs/{id}` | Full detail for one request, including prompt/response |
| `GET /health` | Liveness check |

## Scanning rules

| Pattern | Risk level | Action |
|---|---|---|
| API keys (`sk-`, `pk-`, etc.) | High | Block |
| AWS access keys (`AKIA...`) | High | Block |
| Private keys (PEM headers) | High | Block |
| SSNs | Medium | Flag + forward |
| Credit card numbers | Medium | Flag + forward |
| Email addresses | Low | Flag + forward |
| Phone numbers | Low | Flag + forward |
| IP addresses | Low | Flag + forward |

## Project structure

```
dguard/
├── app/
│   ├── main.py          # FastAPI app + startup
│   ├── config.py        # Settings from .env
│   ├── scanner.py       # Regex scanning logic
│   ├── db/
│   │   └── models.py    # SQLite connection + table init
│   └── routes/
│       ├── proxy.py     # POST /v1/messages
│       └── logs.py      # GET /logs, GET /logs/{id}
├── .env.example
├── requirements.txt
└── README.md
```
