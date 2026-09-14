# SIH26163 — Security Assessment Platform for World Monitor

**Smart India Hackathon 2026** | **Problem Statement SIH26163**

A dedicated vulnerability scanning and security posture evaluation platform engineered specifically for the **World Monitor** geopolitical intelligence application.

---

## 1. Executive Summary

World Monitor is a high-performance TypeScript single-page application (SPA) deployed across Vercel Edge Functions, integrating Upstash Redis, Convex Cloud, and over 500+ upstream intelligence providers. 

This platform delivers an automated, multi-tiered security assessment covering:
1. **Static Application Security Testing (SAST)**: TypeScript AST inspection & Semgrep rule integration detecting hardcoded secrets, dangerous DOM sinks (`innerHTML`), unvalidated `postMessage` wildcards, and dynamic code evaluation (`eval`).
2. **Dynamic Application Security Testing (DAST)**: Active web crawler & OWASP ZAP API integration probing for reflected state injection, parameter manipulation, and missing defense-in-depth headers.
3. **Edge API Security Scanner**: Specialized probes tailored to World Monitor edge function routes (`/api/version`, `/api/health`, `/api/seed-contract-probe`, `/api/feed`), identifying origin-based authentication trust bypasses, wildcard CORS rules for preview deployments, and rate limit spoofing.
4. **Vulnerability Correlation & Risk Engine**: Automated CVSS v3.1 calculation, CWE taxonomy tagging, and deduplication into an aggregate **Security Health Score (0–100)**.
5. **Human-Readable Explanations & Action Plans**: Technical descriptions, threat vectors, reproducible evidence, and remediation steps.
6. **Exportable Security Reports**: Downloadable PDF and JSON reports.

---

## 2. System Architecture

```
                                  ┌────────────────────────┐
                                  │   React 18 Dashboard   │
                                  │  (Vite + Dark UI + SSE) │
                                  └───────────┬────────────┘
                                              │ REST / SSE
                                              ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                        Spring Boot 3 Security Assessment Engine                        │
│                                                                                        │
│  ┌───────────────────────┐  ┌───────────────────────┐  ┌────────────────────────────┐  │
│  │   SAST Runner (Java)  │  │   DAST Scanner Engine │  │    Edge API Security Suite │  │
│  │  Semgrep + AST Rules  │  │   OWASP ZAP / Crawler │  │   World Monitor Gateway    │  │
│  └───────────┬───────────┘  └───────────┬───────────┘  └─────────────┬──────────────┘  │
│              │                          │                            │                 │
│              └──────────────────────────┼────────────────────────────┘                 │
│                                         ▼                                              │
│                     ┌──────────────────────────────────────┐                           │
│                     │ Vulnerability Correlation & Scoring  │                           │
│                     │     (CVSS v3.1 / CWE / Formulas)     │                           │
│                     └───────────────────┬──────────────────┘                           │
│                                         ▼                                              │
│                     ┌──────────────────────────────────────┐                           │
│                     │  PDF & JSON Assessment Report Engine │                           │
│                     └──────────────────────────────────────┘                           │
└─────────────────────────────────────────┬──────────────────────────────────────────────┘
                                          │
                                          ▼
                               ┌─────────────────────┐
                               │  H2 Database / JPA  │
                               └─────────────────────┘
```

---

## 3. World Monitor Security Vulnerability Matrix

| Vulnerability Title | Category | Severity | CVSS | File / Endpoint | Threat Vector |
|---|---|---|---|---|---|
| **Hardcoded Relay Shared Secret** | Authentication | **CRITICAL** | 9.1 | `api/relay.ts:28` | Source includes fallback token allowing unauthorized bridge commands. |
| **Origin-Based API Key Exemption** | Authentication | **HIGH** | 7.8 | `api/_api-key.js:44` | Trusts client `Origin` header blindly, allowing quota exhaustion via spoofing. |
| **Permissive Wildcard CORS on Preview URLs** | CORS Policy | **HIGH** | 7.2 | `api/_cors.js:19` | Regex matches any `*.vercel.app` domain, allowing cross-origin data extraction. |
| **Webhook SSRF DNS Rebinding Window** | SSRF | **HIGH** | 8.2 | `api/_notification-webhook-ssrf.ts` | TOCTOU race condition in DNS verification permits internal VPC probing. |
| **Unsanitized innerHTML Feed Rendering** | Injection (XSS) | **HIGH** | 7.5 | `src/components/NewsFeed.ts` | News feeds interpolated directly into DOM without sanitization. |
| **Regex Bot Gate Bypass** | Security Control | **MEDIUM** | 5.3 | `middleware.ts:16` | Static User-Agent regex check easily bypassed by automated scrapers. |
| **Unauthenticated Seed Contract Probe** | Configuration | **MEDIUM** | 5.8 | `/api/seed-contract-probe` | Debug probe exposed publicly in production environment. |
| **Sensitive State in Insecure LocalStorage** | Data Exposure | **MEDIUM** | 5.9 | `src/utils/urlState.ts` | Session telemetry and tokens stored in unencrypted browser storage. |
| **Rate Limit Header Spoofing (X-Forwarded-For)**| Rate Limiting | **MEDIUM** | 6.2 | `api/_rate-limit.js` | Untrusted IP header parsed before sliding-window rate evaluation. |
| **Missing Content-Security-Policy (CSP)** | Headers | **LOW** | 4.5 | `https://worldmonitor.app` | No strict script restrictions on root domain. |
| **Anti-Clickjacking Frame Headers Missing** | Headers | **LOW** | 4.1 | `https://worldmonitor.app` | Missing X-Frame-Options or frame-ancestors. |

---

## 4. Quick Start & Execution

### Prerequisites
- **Java 21+** (Configured via JetBrains JBR 25 or OpenJDK)
- **Node.js 18+** & **npm**

### Option A: Launch Everything with One Script
```bash
scripts\start-all.bat
```

### Option B: Run Manually

**1. Start the Spring Boot Backend:**
```bash
cd backend
mvn spring-boot:run
```
*Backend runs on `http://localhost:8080`*

**2. Start the React Frontend:**
```bash
cd frontend
npm install
npm run dev
```
*Frontend runs on `http://localhost:5173`*

---

## 5. Key Verification Steps

1. **Dashboard Overview**: Open `http://localhost:5173`. View the animated Security Score Gauge, severity distribution cards, category progress bars, and recent scans.
2. **Launch a Live Scan**: Navigate to **Launch New Scan**, choose **Complete Scan**, enter `https://worldmonitor.app`, and click **Execute**. Watch the real-time progress bar stream through SAST, DAST, and API stages.
3. **Interactive API Tester**: Navigate to **Live API Probe**, select presets such as `/api/version` or `/api/health`, customize headers (e.g. `Origin: https://attacker.com`), and send the probe to see automated header analysis and security grading.
4. **Vulnerability Inspection**: Click any finding from the catalog to see technical evidence, reproduction steps, CWE mappings, and mitigation advice.
5. **Export PDF Report**: Navigate to **Security Reports** or open any completed scan to download the complete PDF security assessment report.
