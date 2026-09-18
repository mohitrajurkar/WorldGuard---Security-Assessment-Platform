# 🛡️ SIH26163 — Security Assessment Platform for World Monitor

**Smart India Hackathon 2026** | **Problem Statement ID: SIH26163**  
*A tailored vulnerability scanner, threat correlation engine, and security posture auditor built specifically for the [World Monitor](https://worldmonitor.app) intelligence platform.*

---

## 📌 At a Glance

- **Primary Database:** **PostgreSQL** (default on port `5432` with database `wm_security`)
- **Zero-Setup Database Alternative:** Built-in **H2 embedded database** for instant testing without installing any database server
- **Backend:** Java 21, Spring Boot 3.3, Spring Data JPA, Hibernate, OpenPDF
- **Frontend:** React 18, TypeScript, Vite, Vanilla CSS (Dark Cyberpunk / Glassmorphic UI)
- **Scanning Capabilities:** Static AST / Semgrep rules (SAST), Live crawler & header probe (DAST), Edge API fuzzing, CVSS v3.1 scoring, and instant PDF report generation

---

## 📖 Why We Built This

[World Monitor](https://worldmonitor.app) is an open-source real-time geopolitical intelligence dashboard. Under the hood, it combines high-throughput Edge functions (Vercel), distributed caching (Upstash Redis), cloud backends (Convex), and dozens of external data sources.

While World Monitor is brilliant at aggregating global feeds, distributed edge architectures introduce unique security risks:
- Edge routes sometimes trust client-supplied headers (like `Origin` or `X-Forwarded-For`) to bypass rate limits or authentication.
- Preview deployments on `*.vercel.app` often end up with overly permissive CORS wildcards.
- Rapid client-side DOM rendering can open doors for stored or reflected XSS if raw feeds aren't strictly sanitized.
- Hardcoded fallback secrets in build bundles can leave backend relays exposed.

This platform was built from the ground up to **actively discover, grade, explain, and help remediate** these exact issues.

---

## 🗄️ Database: Is PostgreSQL Used?

**Yes! PostgreSQL is the primary, production database configured for this application.**

- **Default Configuration (`backend/src/main/resources/application.yml`):**
  - Driver: `org.postgresql.Driver`
  - URL: `jdbc:postgresql://localhost:5432/wm_security`
  - Username: `postgres`
  - Password: `postgres` (or set via `SPRING_DATASOURCE_PASSWORD`)
  - Hibernate DDL mode: `update` (tables and indexes are auto-created on first boot)

### Quick One-Time PostgreSQL Setup:
If you have PostgreSQL installed, create the database with:
```sql
CREATE DATABASE wm_security;
```
*(Or execute our prepared script: `psql -U postgres -f scripts/setup-postgres.sql`)*

### 💡 No PostgreSQL installed? Use the instant H2 mode!
You don't need to install PostgreSQL if you just want to run and test the project right away. The platform includes a pre-configured file-based H2 profile. Just run:
```bash
cd backend
mvn spring-boot:run -Dspring-boot.run.profiles=h2
```
This stores all audit data in `backend/data/security_platform` with zero external dependencies.

---

## 🏗️ Architecture Overview

```
                          ┌───────────────────────────┐
                          │   React 18 + Vite UI      │
                          │   (Dark Security HUD)     │
                          └─────────────┬─────────────┘
                                        │ REST / Live Stream
                                        ▼
┌─────────────────────────────────────────────────────────────────────────────────┐
│                     Spring Boot 3 Security Assessment Engine                    │
│                                                                                 │
│   ┌─────────────────────┐  ┌─────────────────────┐  ┌────────────────────────┐  │
│   │     SAST Engine     │  │     DAST Engine     │  │    Edge API Suite      │  │
│   │  Semgrep + AST Rule │  │   HTTP Probing &    │  │ Specific Edge Routes:  │  │
│   │     Analyzers       │  │   Header Audits     │  │ /api/version, /health  │  │
│   └──────────┬──────────┘  └──────────┬──────────┘  └───────────┬────────────┘  │
│              │                        │                         │               │
│              └────────────────────────┼─────────────────────────┘               │
│                                       ▼                                         │
│                   ┌──────────────────────────────────────┐                      │
│                   │  Vulnerability Engine & CVSS v3.1    │                      │
│                   │   Deduplication & Health Scoring     │                      │
│                   └───────────────────┬──────────────────┘                      │
│                                       ▼                                         │
│                   ┌──────────────────────────────────────┐                      │
│                   │   OpenPDF Report Generation Engine   │                      │
│                   └───────────────────┬──────────────────┘                      │
└───────────────────────────────────────┼─────────────────────────────────────────┘
                                        ▼
                  ┌──────────────────────────────────────────┐
                  │    PostgreSQL (Default)  /  H2 (Fallback)│
                  └──────────────────────────────────────────┘
```

---

## 🎯 Key Features

### 1. Multi-Stage Scanning (SAST + DAST + Edge Probes)
- **SAST**: Scans TypeScript/JavaScript source code for hardcoded credentials, improper DOM insertions (`innerHTML`), dynamic `eval()`, and insecure `localStorage` caching.
- **DAST**: Evaluates running targets for missing defensive headers (CSP, HSTS, X-Frame-Options), CORS misconfigurations, and clickjacking risks.
- **Edge API Suite**: Tailored specifically for World Monitor edge endpoints (`/api/version`, `/api/health`, `/api/seed-contract-probe`, `/api/relay`), identifying header spoofing and debug leaks.

### 2. Intelligent Scoring & Risk Engine
- Calculates standard **CVSS v3.1** base scores and associates exact **CWE** numbers.
- Computes an aggregate **Platform Health Score (0–100)** so teams can understand their security posture at a glance.
- Provides plain-English impact summaries and concrete remediation code snippets.

### 3. Interactive Live API Probe Tool
- Test individual endpoints with custom HTTP headers, methods, and payloads directly from the web interface.
- Automatically analyzes response headers, security grades, and warns about leaky metadata.

### 4. Architecture & Data Flow Auditing
- Visual breakdown of the entire World Monitor attack surface: client SPA, Vercel edge runtime, Upstash Redis, Convex database, and external RSS/news ingestion pipelines.

### 5. Automated PDF Report Generation
- One-click export of executive security audit reports formatted with executive summaries, vulnerability breakdown tables, threat vectors, and recommended fixes.

---

## 🔍 Vulnerability Findings Catalog

Here are key vulnerabilities evaluated and cataloged by the platform:

| Finding Title | Severity | CVSS v3.1 | CWE | Target Location | Threat & Impact |
|---|---|---|---|---|---|
| **Hardcoded Relay Shared Secret** | `CRITICAL` | 9.1 | CWE-798 | `api/relay.ts:28` | Fallback developer token allows unauthorized communication with internal bridge. |
| **Origin-Based API Key Exemption** | `HIGH` | 7.8 | CWE-290 | `api/_api-key.js:44` | Client-supplied `Origin` header is trusted blindly, allowing rate-limit bypass. |
| **Permissive Wildcard CORS on Previews** | `HIGH` | 7.2 | CWE-942 | `api/_cors.js:19` | RegEx matches any arbitrary `*.vercel.app` domain, allowing cross-origin data theft. |
| **Webhook SSRF DNS Rebinding** | `HIGH` | 8.2 | CWE-918 | `api/_notification-webhook-ssrf.ts` | Time-of-check to time-of-use DNS resolution gap allows internal VPC probing. |
| **Unsanitized DOM Feed Rendering** | `HIGH` | 7.5 | CWE-79 | `src/components/NewsFeed.ts` | External RSS content directly inserted into DOM via `innerHTML` without DOMPurify. |
| **Regex Bot Gate Bypass** | `MEDIUM` | 5.3 | CWE-863 | `middleware.ts:16` | Naive User-Agent string check can be easily circumvented by automated scrapers. |
| **Unauthenticated Seed Probe Exposed** | `MEDIUM` | 5.8 | CWE-200 | `/api/seed-contract-probe` | Debug probe endpoint left accessible in production environment. |
| **Sensitive Session in LocalStorage** | `MEDIUM` | 5.9 | CWE-922 | `src/utils/urlState.ts` | Unencrypted browser storage used for session state and auth tokens. |
| **Missing Content Security Policy (CSP)** | `LOW` | 4.5 | CWE-1021 | `https://worldmonitor.app` | Root domain lacks strict CSP headers, leaving window for script injection. |
| **Missing Anti-Clickjacking Headers** | `LOW` | 4.1 | CWE-1021 | `https://worldmonitor.app` | Missing `X-Frame-Options` allows embedding in malicious iframes. |

---

## 🚀 Getting Started

### Requirements
- **Java 21 or higher**
- **Node.js 18+** & **npm**
- **Maven 3.9+**
- **PostgreSQL 14+** *(optional if using the H2 fallback)*

---

### Method 1: The Quickest Way (Windows 1-Click Script)

From the project root directory, run:
```cmd
scripts\start-all.bat
```
This opens two dedicated terminal windows:
1. Spring Boot backend on **http://localhost:8080**
2. Vite React UI on **http://localhost:5173**

---

### Method 2: Manual Step-by-Step

#### 1. Setup the Database
If using PostgreSQL (recommended):
```sql
CREATE DATABASE wm_security;
```
*(If your Postgres password is not `postgres`, set the environment variable: `set SPRING_DATASOURCE_PASSWORD=your_password`)*

#### 2. Start the Backend
```bash
cd backend
mvn spring-boot:run
```
*(To run with zero-setup H2 instead, add `-Dspring-boot.run.profiles=h2`)*

You can verify the backend is ready when you see:
```
Started SecurityPlatformApplication in ... seconds (process running on port 8080)
```

#### 3. Start the Frontend
In a separate terminal:
```bash
cd frontend
npm install
npm run dev
```

Open your browser at **http://localhost:5173**.

---

## 🧪 Tour of the Web Interface

1. **Dashboard (`/`)**:
   - Live Security Health Score gauge with dynamic grading (A through F).
   - Severity breakdown cards (Critical, High, Medium, Low).
   - Quick launcher for scanning and recent scan history.

2. **Launch New Scan (`/new-scan`)**:
   - Choose scan profile: **Complete Audit**, **SAST Source Review**, or **Edge API Probe**.
   - Watch the scan orchestrator step through phases with real-time status updates.

3. **Vulnerabilities Catalog (`/findings`)**:
   - Filter by severity, category (Authentication, CORS, SSRF, Injection), or search by keyword.
   - Click any card to inspect code evidence, CWE tags, and copy-paste ready mitigation steps.

4. **Live API Probe (`/api-tester`)**:
   - Send custom HTTP requests against World Monitor endpoints.
   - Test how the target responds to spoofed origins, malformed payloads, or probe headers.

5. **Architecture Review (`/architecture`)**:
   - Interactive security architecture diagram mapping trust boundaries between client, edge workers, caches, and upstream news providers.

6. **Executive PDF Reports (`/reports`)**:
   - Preview generated reports and download publication-ready PDFs for stakeholders.

---

## 📂 Project Structure

```
SIH World monitor/
├── backend/                              # Spring Boot 3 Java backend
│   ├── pom.xml                           # Dependencies (PostgreSQL, H2, JPA, OpenPDF)
│   ├── src/main/java/com/sih/securityplatform/
│   │   ├── controller/                   # REST API controllers
│   │   ├── model/                        # JPA Entities (Scan, Finding, Report)
│   │   ├── repository/                   # Spring Data JPA repositories
│   │   └── service/                      # SAST, DAST, API, & PDF Generation services
│   └── src/main/resources/
│       ├── application.yml               # Default PostgreSQL configuration
│       └── application-h2.yml            # Standalone H2 fallback configuration
│
├── frontend/                             # React 18 + TypeScript + Vite
│   ├── src/
│   │   ├── components/                   # Navigation, cards, score meters
│   │   ├── pages/                        # Dashboard, Scans, Findings, API Probe, Reports
│   │   └── services/                     # API client layer
│   └── package.json
│
├── scanner/                              # Analysis rules and definitions
│   ├── api/                              # Edge route test specifications
│   ├── semgrep/                          # Custom Semgrep SAST rule YAMLs
│   └── zap/                              # DAST scanner configuration
│
└── scripts/                              # Convenient automation scripts
    ├── setup-postgres.sql                # SQL script to create wm_security DB
    ├── start-all.bat                     # 1-click startup for both services
    ├── start-backend.bat                 # Backend runner
    └── start-frontend.bat                # Frontend runner
```

---

## 📄 License & Attribution

Developed for the **Smart India Hackathon 2026** under Problem Statement **SIH26163**.  
Target application reference: [World Monitor](https://github.com/koala73/worldmonitor).
