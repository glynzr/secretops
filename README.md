# SecretOps 
## AI-Based Secret Management within DevSecOps Workflows

Graduation work project 

---

## Architecture

| Service       | Tech                          | Port | Role |
|---------------|-------------------------------|------|------|
| **Backend**   | Go 1.21 + Gin + SQLite (WAL)  | 8080 | REST API, credential storage, job dispatch |
| **CLI Service** | Python 3.11 + Flask          | 5001 | AI detection, remediation orchestration |
| **Frontend**  | Next.js 15 + React 19 + TS   | 3000 | Workflow UI |
| **Vault**     | HashiCorp Vault 1.17 (KV-v2) | 8200 | Poison injection, audit log |

---

## Quick Start

```bash
# 1. Clone and start
docker compose up --build

# 2. Open browser
open http://localhost:3000

# 3. Follow the 4-step workflow:
#    Step 1: Integrations — configure Claude AI, GitLab, Vault, Slack, Email
#    Step 2: Projects     — import GitLab repos, select AI model, click Analyze
#    Step 3: Findings     — review AI-detected secrets, trigger remediation
#    Step 4: Remediation  — monitor 7-stage pipeline, post-merge verification
```

---

## The 7-Stage Remediation Pipeline

| Stage | Name | Action |
|-------|------|--------|
| 0 | Git History Correlation | Scan commit log, calculate days_exposed, alert level |
| 1 | AI Patch Generation | LLM generates patched code + MR description |
| 2 | **Vault Poison Injection** | SECRETOPS_POISONED_... placeholder forces app runtime failure |
| 3 | GitLab MR | Branch + commit + MR with rotation checklist |
| 4 | GitLab Issue | Assigned to commit author via git blame |
| 5 | Slack + Email | Block Kit alert + HTML email to security team |
| 6 | Direct Revocation | AWS IAM / GitLab PAT / GitHub PAT API revocation |
| + | Post-Merge Verify | Vault value comparison → auto-close or escalate |

---

## AI Providers Supported

| Provider | Model | Privacy |
|----------|-------|---------|
| Claude (Anthropic) | claude-3-5-sonnet-20241022 | ZDR available |
| OpenAI | gpt-4o, gpt-4o-mini | ZDR enterprise |
| DeepSeek | deepseek-chat | PIPL applies |
| **Ollama (local)** | llama3.1:8b |  Zero external transmission |

Multiple API keys per provider supported — round-robin rotation on HTTP 429.

---

## Data Privacy Options

1. **Vendor ZDR agreement** — contractual guarantee, no training data use
2. **Accept provider defaults** — Anthropic/OpenAI don't train on API data by default  
3. **Local Ollama** — zero external transmission, on-premise GPU, F1=0.900

---

## Key Original Contributions

1. **Hybrid Triage Detection** — regex pre-filter + LLM, 60-65% API call reduction
2. **Vault Poison Injection** — novel soft-revocation working for ALL secret types
3. **AI-Generated MR with Rotation Guide** — inescapable remediation loop
4. **Git History Correlation** — days_exposed calculation + escalated alerts

---

## Environment Variables (optional, overridden by UI config)

```env
# Backend
PORT=8080
DB_PATH=/app/data/secretops.db

# CLI Service  
BACKEND_URL=http://backend:8080
CLI_PORT=5001
CONFIDENCE_THRESHOLD=0.70

# Fallback AI keys (overridden by DB config)
ANTHROPIC_API_KEY=sk-ant-...
OPENAI_API_KEY=sk-proj-...

# Vault
VAULT_ADDR=http://vault:8200
VAULT_TOKEN=root
```

---

## Development (without Docker)

```bash
# Backend
cd backend && go mod tidy && go run cmd/main.go

# CLI Service
cd cli && pip install -r requirements.txt && python service.py

# Frontend
cd frontend && npm install && npm run dev

# Vault (dev mode)
vault server -dev -dev-root-token-id=root
```
