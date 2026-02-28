<div align="center">

# 🛡️ ShieldSentinel AI

**Enterprise AI Security Gateway — Real-time threat detection for LLM requests**

[![Next.js](https://img.shields.io/badge/Next.js-14.2-black?logo=next.js)](https://nextjs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5-blue?logo=typescript)](https://www.typescriptlang.org/)
[![Prisma](https://img.shields.io/badge/Prisma-5.22-2D3748?logo=prisma)](https://www.prisma.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

A production-ready middleware demo that intercepts every LLM request through a **three-layer security engine** — detecting PII leakage, prompt injection, and semantic vector attacks — before the message reaches any AI model.

</div>

---

## ✨ Features

| Layer | What it catches | Action |
|-------|----------------|--------|
| **PII Detection** | CN phone/ID card, email, API keys (OpenAI/AWS/Google), credit cards, IPv4, passwords (EN + CN) | Mask & pass through |
| **Prompt Injection** | 9 regex rules + 20 keyword entries, bilingual (EN/CN) | Block (HIGH/CRITICAL) |
| **Vector Similarity** | Cosine similarity against 10 canonical attack seed vectors, TF-weighted | Block if score ≥ 0.85 |

**Additional highlights:**
- 🔴 **Real-time streaming** — first SSE chunk carries scan metadata, rest is LLM content
- 📊 **Admin dashboard** — live Recharts analytics, threat pie, session ranking (15 s polling)
- 🎯 **Red Team Simulator** — 4 one-click attack payloads covering all threat types
- 📄 **GDPR compliance** — raw prompts stored as SHA-256 hash only (Article 5(1)(c))
- 🔄 **Automatic fallback** — Zhipu GLM-4v-plus → exponential backoff → OpenAI gpt-4o-mini
- 🌐 **Bilingual** — detection rules cover both English and Chinese attack patterns

---

## 🏗️ Architecture

```
User Input
    │
    ▼
┌─────────────────────────────────────────┐
│          Security Engine                │
│  ┌─────────────┐  ┌──────────────────┐  │
│  │ PII Detector│  │Injection Detector│  │
│  │  (regex +   │  │ (9 rules Layer 1 │  │
│  │  checksum)  │  │  20 kw Layer 2)  │  │
│  └──────┬──────┘  └────────┬─────────┘  │
│         │                  │            │
│         └──────┬───────────┘            │
│                ▼                        │
│  ┌─────────────────────────────────┐    │
│  │    Vector Similarity Detector   │    │
│  │  (TF cosine · 10 seed vectors)  │    │
│  └─────────────────────────────────┘    │
└──────────────────┬──────────────────────┘
                   │
         ┌─────────┴──────────┐
         │  deriveAttackType  │
         │  NONE / PII /      │
         │  INJECTION /       │
         │  VECTOR / COMBINED │
         └─────────┬──────────┘
                   │
      ┌────────────┴────────────┐
      │                         │
   BLOCKED                   PASSED
(HIGH/CRITICAL +          (masked prompt
 injection/vector)         → LLM)
```

---

## 🖥️ Pages

### `/chat` — Security Gateway Console
Dual-panel glassmorphism layout: left side is the conversation terminal, right side is the **Security Inspector** showing real-time scan results for every message.

### `/admin` — Security Dashboard
- **KPI cards** — 24 h scan count, block count, PII events, avg latency
- **Timeline** — 24 h hourly scan/block frequency chart
- **Threat Pie** — attack type breakdown (Prompt Injection / PII / Vector / Combined)
- **Session Ranking** — top sessions by threat detection rate
- **Red Team Simulator** — fire 4 pre-built attack payloads with one click
- **GDPR Report** — generate and download a Markdown compliance report

---

## 🚀 Getting Started

### Prerequisites

- Node.js ≥ 18
- A [Zhipu AI](https://open.bigmodel.cn/) API key (primary LLM)
- An [OpenAI](https://platform.openai.com/) API key (fallback)

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/YOUR_USERNAME/ShieldSentinel-AI.git
cd ShieldSentinel-AI

# 2. Install dependencies
npm install

# 3. Configure environment variables
cp .env.example .env
# Edit .env and fill in your API keys

# 4. Set up the database
npx prisma migrate deploy

# 5. Start the development server (port 3001)
npm run dev
```

Then open:
- **Chat Gateway** → http://localhost:3001/chat
- **Admin Dashboard** → http://localhost:3001/admin

### Environment Variables

```env
ZHIPU_API_KEY=your_zhipu_api_key_here
OPENAI_API_KEY=sk-your_openai_api_key_here
```

---

## 🔬 Security Engine Details

### PII Patterns

| Type | Example | Masked |
|------|---------|--------|
| `PHONE_CN` | `13812345678` | `138****5678` |
| `ID_CARD_CN` | `110101199003076515` | `110101********15*` |
| `EMAIL` | `user@example.com` | `us**@example.com` |
| `PASSWORD_KV` | `密码是 admin123` | `密码是 [REDACTED]` |
| `API_KEY_OPENAI` | `sk-abc...xyz` | `sk-***...xyz` |
| `API_KEY_AWS` | `AKIAIOSFODNN7EXAMPLE` | `AKIA************MPLE` |
| `CREDIT_CARD` | `4111 1111 1111 1111` | `**** **** **** 1111` |
| `IP_ADDRESS` | `192.168.1.100` | `192.168.***.***` |

### Injection Rules (Layer 1 — Regex)

`ROLE_OVERRIDE` · `SYSTEM_PROMPT_EXTRACTION` · `PRIVILEGE_ESCALATION` · `INDIRECT_INJECTION` · `CODE_EXECUTION` · `DATA_EXFILTRATION` · `DELIMITER_SMUGGLING` · `ROLEPLAY_BYPASS` · `SYSTEM_RESET_LOGIC`

### Vector Attack Seeds (Layer 3)

10 canonical attack seeds covering: Role Override/Jailbreak · System Prompt Extraction · Indirect Injection · Privilege Escalation · Data Exfiltration · Code Injection/RCE · Social Engineering/Persona Bypass · Delimiter Smuggling · Multi-language Obfuscation · System Reset/Memory Wipe

Similarity threshold: **0.85** · Security-critical terms boosted **×3** in TF weighting

### Risk & Action Matrix

| Risk Level | Trigger | Action |
|-----------|---------|--------|
| `LOW` | No signals | Pass through |
| `MEDIUM` | PII only | Mask PII → pass through |
| `HIGH` | Vector hit / strong keyword | **Block** |
| `CRITICAL` | Injection rule / PII + attack | **Block** |

---

## 🛠️ Tech Stack

| Category | Technology |
|----------|-----------|
| Framework | Next.js 14.2 (App Router) |
| Language | TypeScript 5 (strict) |
| Styling | Tailwind CSS 3 + Shadcn UI |
| Animation | Framer Motion 11 |
| Charts | Recharts 2 |
| Database | SQLite via Prisma 5 |
| AI SDK | OpenAI SDK v4 (Zhipu + OpenAI) |
| Validation | Zod 3 |

---

## 📁 Project Structure

```
src/
├── app/
│   ├── chat/page.tsx          # Security gateway chat UI
│   ├── admin/page.tsx         # Admin dashboard
│   └── api/
│       ├── chat/route.ts      # Streaming chat + scan API
│       ├── admin/stats/       # Dashboard data API
│       └── logs/              # Paginated audit log API
├── lib/security/
│   ├── engine.ts              # Main scan orchestrator
│   ├── pii-detector.ts        # PII detection & masking
│   ├── injection-detector.ts  # Rule-based injection detection
│   └── vector-detector.ts     # Cosine similarity engine
├── components/chat/
│   ├── UserTerminal.tsx        # Chat panel
│   └── SecurityInspector.tsx  # Real-time scan results panel
└── types/security.ts          # Shared TypeScript types
```

---

## 🗃️ Database

Audit logs are persisted to SQLite via Prisma (fire-and-forget, zero added latency):

```prisma
model SecurityLog {
  id             Int      @id @default(autoincrement())
  timestamp      DateTime @default(now())
  sessionId      String?
  promptHash     String   // SHA-256 of raw prompt (GDPR compliant)
  maskedPrompt   String
  riskLevel      String
  attackType     String
  blocked        Boolean
  triggeredRules String
  piiTypes       String
  latencyMs      Int
  modelUsed      String
}
```

> Raw prompt text is **never stored** — only its SHA-256 hash for deduplication audit purposes.

---

## 📄 License

[MIT](LICENSE) © 2026 Zhiwei Wang
