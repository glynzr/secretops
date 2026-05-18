# SecretOps — Automated Secret Detection & Remediation Platform

SecretOps is a four-service microarchitecture for automated detection, triage, and remediation of exposed credentials in GitLab repositories.

---

## Architecture

| Service | Stack | Port |
|---------|-------|------|
| API Backend | Go 1.21 + Gin + SQLite (WAL) | 8080 |
| AI Engine | Python 3.11 + Flask | 5001 |
| Frontend | Next.js 15 + React 19 | 3000 |
| Vault | HashiCorp Vault 1.17 (KV-v2) | 8200 |

---

## Quick Start

### Prerequisites
- Docker 24+ and Docker Compose v2
- 4 GB RAM minimum

### 1. Clone and configure

```bash
git clone <your-repo>
cd secretops
cp .env.example .env
# Edit .env with your values
```

### 2. Generate a 32-byte encryption key

```bash
openssl rand -base64 24
# Paste output into ENCRYPTION_KEY in .env
```

### 3. Start all services

```bash
docker compose up -d
```

### 4. Open the dashboard

Visit **http://localhost:3000**

---

## Environment Variables

Create a `.env` file in the project root (Docker Compose will pick it up automatically):

```env
# Shared encryption key — must be exactly 32 bytes
ENCRYPTION_KEY=your-32-byte-key-here-changeme!!

# Vault (dev mode uses a static root token)
VAULT_TOKEN=secretops-root-token

# Optional: override default URLs
API_BACKEND_URL=http://localhost:8080
AI_ENGINE_URL=http://localhost:5001
```

> **Note:** In production, replace the Vault dev-mode container with a properly initialized Vault instance and update `VAULT_TOKEN` accordingly.

---

## First-Time Setup (UI Walkthrough)

1. **Integrations → GitLab** — Enter your GitLab URL and a Personal Access Token with `api` + `read_repository` scopes. Click **Save & Test**.
2. **Integrations → HashiCorp Vault** — Enter the Vault URL and root token. Click **Save & Test**.
3. **Integrations → AI Providers** — Add at least one provider (OpenAI, Anthropic, Groq, or local Ollama). Multiple keys enable automatic failover when rate limits are hit.
4. **Integrations → Slack** — Paste a Slack Incoming Webhook URL. Click **Save & Test**.
5. **Integrations → SMTP** — Configure email delivery. Click **Save & Test**.
6. **Integrations → Alert Recipients** — Add developers, team leads, and DevSecOps engineers who should receive alerts.
7. **Repositories** — Browse your GitLab projects and click **Add & Scan** on any repository.
8. Watch the **Scan** view for live progress.

---

## Detection Pipeline

```
Repository Clone
      │
      ▼
 git log -S  ──── Records first-seen commit, author, date, days exposed
      │
      ▼
 Regex Pre-Filter ──── 25+ provider-specific patterns (AWS, GitLab, Stripe, etc.)
      │               High-specificity match + entropy → confirmed (0.95 confidence)
      │               Matches false-positive patterns → rejected immediately
      │               Everything else ↓
      ▼
 LLM Classification ── Context window around candidate sent to AI
      │                 temperature=0.0 for deterministic results
      │                 Returns: is_secret, confidence, severity, reasoning
      ▼
 Git History Correlation ── Enriches with commit metadata
      │
      ▼
 Finding Saved → Appears in dashboard
```

---

## Remediation Pipeline

Triggered when a DevSecOps engineer marks a finding as **Confirmed**.

```
1. AI Patch Generation   — Context-aware code fix (env var / Vault path replacement)
2. Vault Injection       — Poison placeholder written to KV-v2 path
3. Branch Creation       — secretops/fix-{id}-{type} branch created via GitLab API
4. Commit & MR           — Patched file committed, MR opened with rotation checklist
5. Notifications         — Slack Block Kit alert + HTML email to all recipients
6. Revocation Attempt    — AWS IAM / GitLab PAT / GitHub PAT revocation (where API supports)
7. Verification Loop     — Background job reads Vault value daily and compares SHA-256 hash
```

The developer **must approve** the merge request. SecretOps never auto-merges.

---

## Rotation Verification

After the MR is merged, a background job runs daily:

| Vault value == original hash | Result |
|------------------------------|--------|
| Same as exposed credential   | Status stays **open**; daily reminders sent |
| Placeholder value detected   | Escalated reminder: "still contains placeholder" |
| Different hash (rotated!)    | Finding **auto-closed**; resolution alert sent |

---

## Supported Credential Types

Secret detection covers 25+ providers including:

- AWS Access Keys & Session Tokens
- GitLab & GitHub Personal Access Tokens
- OpenAI, Anthropic, Groq API Keys
- Stripe Live & Test Keys
- Slack Bot Tokens & Webhook URLs
- Google API Keys & Service Account credentials
- Notion, Twilio, SendGrid, npm, Docker Hub, Cloudflare

Revocation is automated for: **AWS IAM**, **GitLab PAT**, **GitHub PAT**. For all others, rotation instructions with provider URLs are included in the MR.

---

## Directory Structure

```
secretops/
├── api-backend/         Go REST API + SQLite
│   ├── cmd/main.go
│   ├── internal/
│   │   ├── api/         Handlers + Router
│   │   ├── crypto/      AES-GCM encryption
│   │   ├── db/          SQLite WAL schema
│   │   ├── models/      Go structs
│   │   └── services/    Async scan dispatch
│   └── Dockerfile
├── ai-engine/           Python detection + remediation
│   ├── app.py
│   ├── detection/       Regex patterns, LLM classifier, pipeline
│   ├── git_ops/         Clone, git log -S history
│   ├── remediation/     Pipeline, verifier
│   ├── notifications/   Slack Block Kit, HTML email
│   └── Dockerfile
├── frontend/            Next.js 15 dashboard
│   ├── src/
│   │   ├── app/         Layout, globals, page router
│   │   ├── components/  Sidebar + 7 view components
│   │   ├── lib/api.ts   Typed API client
│   │   └── types/       TypeScript interfaces
│   └── Dockerfile
├── vault-config/        Vault HCL config + init script
├── docker-compose.yml
└── README.md
```

---

## Development (without Docker)

### API Backend
```bash
cd api-backend
go mod tidy
DB_PATH=./dev.db ENCRYPTION_KEY=dev-key-32bytes-padded-here!! go run ./cmd/main.go
```

### AI Engine
```bash
cd ai-engine
pip install -r requirements.txt
API_BACKEND_URL=http://localhost:8080 python app.py
```

### Frontend
```bash
cd frontend
npm install
npm run dev
```

---

## Security Notes

- All credentials stored in SQLite are AES-GCM encrypted using `ENCRYPTION_KEY`
- The same encryption key must be set for both `api-backend` and `ai-engine`
- Vault is run in **dev mode** by default (data is ephemeral). For production, use the `vault.hcl` config in `vault-config/` and initialize properly with `vault-init.sh`
- The poison placeholder format is: `SECRETOPS_POISONED_{hash[:16]}_ROTATE_NOW`

---

