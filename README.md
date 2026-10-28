# GrayStrike — Autonomous AI Penetration Testing & Web Security Platform
**By Anas Technology | Powered by AnaOS Engine**

GrayStrike is an enterprise-grade autonomous offensive security platform engineered to stress-test web applications, modern AI-generated Jamstack apps, APIs, and cloud infrastructure using multi-agent exploit chains, continuous attack surface management (EASM), and formal risk reasoning.

---

## 🚀 Key Capabilities

- **41+ Specialized Security Micro-Agents:** Comprehensive coverage of OWASP Top 10 (SQLi, XSS, SSRF, CORS, Auth Bypass, IDOR) plus modern AI-generated app vulnerabilities (Supabase/Firebase RLS exposure, leaked frontend secrets, LLM prompt injection guards, and unauthenticated AI proxy routes).
- **Attack Path & Business Risk Graph:** Correlates isolated perimeter bugs into multi-stage exploit chains (Wiz / Pentera style), calculates financial blast radius, and highlights critical architectural Choke Points.
- **Continuous EASM & Shadow Asset Recon:** Certificate Transparency log monitoring (crt.sh), dangling CNAME takeover detection across 8 major cloud providers, and exposed S3 / Supabase storage bucket enumeration.
- **Automated QA & Regression Test Generator:** Produces 1-click reproducible test scripts in TypeScript (Vitest/Jest), Python (Pytest), Playwright E2E browser tests, and cURL commands.
- **Executive & Compliance Evidence Packet:** Generates official CISO-attested compliance PDFs for SOC 2 Type II, ISO/IEC 27001:2022, PCI-DSS v4.0, HIPAA, and GDPR.
- **CI/CD DevSecOps Integration:** Full OASIS SARIF 2.1.0 export and GitHub Actions / GitLab CI security gates via secure scoped API keys.

---

## 🛠️ Quick Start (Local Development)

### Prerequisites
- Python 3.11+
- Node.js 18+
- Docker & Docker Compose (optional)

### 1. Backend Setup
```bash
cd backend
python -m venv .venv
source .venv/bin/activate  # Or on Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp ../.env.example .env

# Run FastAPI Server
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

### 2. Frontend Setup
```bash
cd ../frontend
npm install
npm run dev
```
Open [http://localhost:3000](http://localhost:3000) in your browser.

---

## 🏛️ System Architecture

```
graystrike/
├── frontend/          # Next.js 14 App Router, Tailwind CSS, Lucide Icons
├── backend/           # FastAPI, SQLAlchemy Async, SQLite / PostgreSQL
│   ├── app/api/       # REST endpoints (Scans, Findings, EASM, Attack Paths, CI/CD)
│   ├── app/models/    # Relational Database Models
│   └── app/services/  # Core Engines (Attack Path, Scope, EASM, Compliance, QA Gen)
├── ai_engine/         # Multi-Agent Offensive Pipeline
│   ├── agents/        # 41 Specialized Micro-Agents (Core, Framework, RedTeam, AI-App)
│   ├── orchestrator/  # LangGraph Workflow & State Management
│   └── verification/  # Headless Chromium & Playwright Evidence Engine
└── docker/            # Production Container Configs
```

---

## 🛡️ License & Ethics
This platform is intended exclusively for authorized penetration testing, security research, and defensive posture evaluation. Unauthorized scanning against third-party targets without explicit ownership or consent is strictly prohibited.
