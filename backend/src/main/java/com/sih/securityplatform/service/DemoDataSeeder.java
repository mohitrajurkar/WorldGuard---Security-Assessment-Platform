package com.sih.securityplatform.service;

import com.sih.securityplatform.model.*;
import com.sih.securityplatform.repository.ScanRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;

@Component
public class DemoDataSeeder implements CommandLineRunner {

    private final ScanRepository scanRepository;
    private final VulnerabilityEngine vulnerabilityEngine;

    public DemoDataSeeder(ScanRepository scanRepository, VulnerabilityEngine vulnerabilityEngine) {
        this.scanRepository = scanRepository;
        this.vulnerabilityEngine = vulnerabilityEngine;
    }

    @Override
    public void run(String... args) {
        if (scanRepository.count() > 0) {
            return;
        }

        Scan seedScan = new Scan();
        seedScan.setScanType(ScanType.COMPLETE);
        seedScan.setStatus(ScanStatus.COMPLETED);
        seedScan.setTargetUrl("https://worldmonitor.app");
        seedScan.setSourcePath("github.com/koala73/worldmonitor");
        seedScan.setStartedAt(LocalDateTime.now().minusHours(2));
        seedScan.setCompletedAt(LocalDateTime.now().minusHours(2).plusMinutes(6));
        seedScan.setProgressPercent(100);
        seedScan.setCurrentStep("Audit Complete (Demonstration Baseline)");
        seedScan.setDemo(true);

        // 1. Critical Finding
        Finding f1 = new Finding();
        f1.setTitle("Hardcoded Relay Shared Secret Token in Client-Reachable Build");
        f1.setSeverity(Severity.CRITICAL);
        f1.setCategory(FindingCategory.AUTHENTICATION);
        f1.setSource("SAST / Source Review");
        f1.setFilePath("api/relay.ts");
        f1.setLineNumber(28);
        f1.setDescription("Static analysis detected a fallback hardcoded authorization token used to validate communication with the Railway relay bridge when RELAY_SHARED_SECRET is unset.");
        f1.setImpact("Attackers can forge relay control packets, manipulate upstream intelligence streams, or flood the external data ingestion pipeline.");
        f1.setEvidence("const secret = process.env.RELAY_SHARED_SECRET || 'wm_bridge_dev_sec_9941a8e2';");
        f1.setRecommendation("Enforce a hard failure if RELAY_SHARED_SECRET is absent at runtime; never bundle fallback cryptographic secrets in application source files.");
        f1.setCwe("CWE-798: Use of Hard-coded Credentials");
        f1.setCvssScore(9.1);
        f1.setRemediationTimeMinutes(45);
        seedScan.addFinding(f1);

        // 2. High Finding
        Finding f2 = new Finding();
        f2.setTitle("Origin-Based API Key Exemption in Edge Auth Gateway");
        f2.setSeverity(Severity.HIGH);
        f2.setCategory(FindingCategory.AUTHENTICATION);
        f2.setSource("SAST / Source Review");
        f2.setFilePath("api/_api-key.js");
        f2.setLineNumber(44);
        f2.setDescription("In `api/_api-key.js`, requests with an HTTP Origin header matching 'worldmonitor.app' or containing 'localhost' bypass API key authentication without cryptographic session validation.");
        f2.setImpact("Attackers running automated scripts or reverse proxies can forge the Origin header (`Origin: https://worldmonitor.app`) to drain paid tier external API quotas (Finnhub, OpenSky, ACLED).");
        f2.setEvidence("if (origin === 'https://worldmonitor.app' || origin.includes('localhost')) { return { authorized: true, user: 'browser-anonymous' }; }");
        f2.setRecommendation("Use signed cryptographically verifiable session tokens or JWTs stored in HttpOnly cookies rather than trusting raw client Origin headers.");
        f2.setCwe("CWE-290: Authentication Bypass by Spoofing");
        f2.setCvssScore(7.8);
        f2.setRemediationTimeMinutes(60);
        seedScan.addFinding(f2);

        // 3. High Finding
        Finding f3 = new Finding();
        f3.setTitle("Permissive Wildcard Pattern for Vercel Preview Deployments in CORS Allowlist");
        f3.setSeverity(Severity.HIGH);
        f3.setCategory(FindingCategory.CORS);
        f3.setSource("DAST / Security Engine");
        f3.setFilePath("api/_cors.js");
        f3.setLineNumber(19);
        f3.setDescription("The CORS validation regular expression matches any URL ending in `.vercel.app`. Because any user can register arbitrary subdomains on Vercel, this policy is overly permissive.");
        f3.setImpact("An adversary can deploy a malicious webpage on a free Vercel account, induce users to visit it, and read sensitive telemetry or cached intelligence payloads.");
        f3.setEvidence("Origin regex: /^https:\\/\\/.*\\.vercel\\.app$/ matches attacker-hosted 'https://evil-harvest-wm.vercel.app'");
        f3.setRecommendation("Lock CORS origins strictly to exact verified domain names: 'https://worldmonitor.app' and specific, authenticated preview branches.");
        f3.setCwe("CWE-942: Permissive Cross-Domain Policy with Untrusted Domains");
        f3.setCvssScore(7.2);
        f3.setRemediationTimeMinutes(30);
        seedScan.addFinding(f3);

        // 4. High Finding
        Finding f4 = new Finding();
        f4.setTitle("Webhook Notification Target SSRF Vulnerability Window");
        f4.setSeverity(Severity.HIGH);
        f4.setCategory(FindingCategory.SSRF);
        f4.setSource("DAST / Web Scanner");
        f4.setFilePath("api/_notification-webhook-ssrf.ts");
        f4.setLineNumber(35);
        f4.setDescription("Webhook notification dispatch performs DNS resolution prior to HTTP dispatch, but fails to pin the connection socket, leaving a Time-of-Check to Time-of-Use (TOCTOU) DNS rebinding window.");
        f4.setImpact("Permits internal network probing against cloud metadata services (169.254.169.254) or Upstash Redis database instances.");
        f4.setEvidence("Synchronous DNS lookup occurs in Node.js runtime, followed by standard fetch() which performs a second independent DNS resolution.");
        f4.setRecommendation("Use an egress HTTP proxy with kernel-enforced IP filtering or configure custom Agent socket IP pinning.");
        f4.setCwe("CWE-918: Server-Side Request Forgery (SSRF)");
        f4.setCvssScore(8.2);
        f4.setRemediationTimeMinutes(90);
        seedScan.addFinding(f4);

        // 5. High Finding
        Finding f5 = new Finding();
        f5.setTitle("Unsanitized innerHTML in Geopolitical News Feed Renderers");
        f5.setSeverity(Severity.HIGH);
        f5.setCategory(FindingCategory.INJECTION);
        f5.setSource("SAST / Security Engine");
        f5.setFilePath("src/components/NewsFeed.ts");
        f5.setLineNumber(88);
        f5.setDescription("News article titles and GDELT RSS summaries are interpolated directly into DOM elements via innerHTML without passing through DOMPurify sanitization.");
        f5.setImpact("Hostile RSS feeds or poisoned intelligence stream items can inject persistent client-side JavaScript payloads executing in user browser sessions.");
        f5.setEvidence("cardElement.innerHTML = `<h3>${item.title}</h3><p>${item.summary}</p>`;");
        f5.setRecommendation("Utilize DOMPurify.sanitize() or standard DOM text node creation (`textContent`) for rendering untrusted third-party feed strings.");
        f5.setCwe("CWE-79: Cross-site Scripting (XSS)");
        f5.setCvssScore(7.5);
        f5.setRemediationTimeMinutes(30);
        seedScan.addFinding(f5);

        // 6. Medium Finding
        Finding f6 = new Finding();
        f6.setTitle("User-Agent Regular Expression Bot Filtering Bypass");
        f6.setSeverity(Severity.MEDIUM);
        f6.setCategory(FindingCategory.CONFIGURATION);
        f6.setSource("SAST / Source Review");
        f6.setFilePath("middleware.ts");
        f6.setLineNumber(16);
        f6.setDescription("Edge middleware employs a static User-Agent regex check to block web scrapers. Any automated scraper supplying a standard Chrome or Safari User-Agent string bypasses the filter.");
        f6.setImpact("Allows automated scraping bots to exhaust Vercel Edge invocation quotas and flood upstream intelligence APIs.");
        f6.setEvidence("const isBot = /bot|crawl|spider|slurp|curl/i.test(userAgent);");
        f6.setRecommendation("Integrate Cloudflare Turnstile, CAPTCHA challenge-response, or rate-based token bucket anomaly detection.");
        f6.setCwe("CWE-290: Authentication Bypass by Spoofing");
        f6.setCvssScore(5.3);
        f6.setRemediationTimeMinutes(30);
        seedScan.addFinding(f6);

        // 7. Medium Finding
        Finding f7 = new Finding();
        f7.setTitle("Unauthenticated Seed Contract Probe Endpoint in Production");
        f7.setSeverity(Severity.MEDIUM);
        f7.setCategory(FindingCategory.CONFIGURATION);
        f7.setSource("DAST / Web Scanner");
        f7.setEndpoint("/api/seed-contract-probe");
        f7.setDescription("Diagnostic endpoint `/api/seed-contract-probe` is accessible over public Internet without requiring authentication credentials.");
        f7.setImpact("Exposes internal state synchronization schemas and triggers unnecessary internal probe queries.");
        f7.setEvidence("HTTP GET /api/seed-contract-probe returned HTTP 200 with schema state payload.");
        f7.setRecommendation("Gate diagnostic endpoints with NODE_ENV checks or require an admin API key.");
        f7.setCwe("CWE-489: Active Debug Code in Production");
        f7.setCvssScore(5.8);
        f7.setRemediationTimeMinutes(20);
        seedScan.addFinding(f7);

        // 8. Medium Finding
        Finding f8 = new Finding();
        f8.setTitle("Client-Side Intelligence Cache and Preferences in Insecure LocalStorage");
        f8.setSeverity(Severity.MEDIUM);
        f8.setCategory(FindingCategory.INFORMATION_DISCLOSURE);
        f8.setSource("SAST / Source Review");
        f8.setFilePath("src/utils/urlState.ts");
        f8.setLineNumber(112);
        f8.setDescription("User custom feeds, pinned coordinates, and session metadata are saved to unencrypted localStorage.");
        f8.setImpact("Any script running in the application origin can extract user telemetry, saved geopolitical feeds, and auth tokens.");
        f8.setEvidence("window.localStorage.setItem('wm_preferences', JSON.stringify(config));");
        f8.setRecommendation("Store authentication tokens in HttpOnly cookies; encrypt stored sensitive preferences if persisting to browser storage.");
        f8.setCwe("CWE-922: Insecure Storage of Sensitive Information");
        f8.setCvssScore(5.9);
        f8.setRemediationTimeMinutes(30);
        seedScan.addFinding(f8);

        // 9. Medium Finding
        Finding f9 = new Finding();
        f9.setTitle("Rate Limiting IP Extraction Vulnerable to Header Spoofing");
        f9.setSeverity(Severity.MEDIUM);
        f9.setCategory(FindingCategory.RATE_LIMITING);
        f9.setSource("SAST / Source Review");
        f9.setFilePath("api/_rate-limit.js");
        f9.setLineNumber(30);
        f9.setDescription("Client IP extraction for Upstash Redis rate limiting parses client-controlled headers (`x-forwarded-for`) without checking trusted proxy signatures.");
        f9.setImpact("Attackers can cycle fake IP values in HTTP headers to completely bypass rate limit quotas.");
        f9.setEvidence("const ip = req.headers['x-forwarded-for']?.split(',')[0] || req.socket.remoteAddress;");
        f9.setRecommendation("Rely exclusively on Vercel's trusted platform edge header `x-vercel-ip`.");
        f9.setCwe("CWE-345: Insufficient Verification of Data Authenticity");
        f9.setCvssScore(6.2);
        f9.setRemediationTimeMinutes(25);
        seedScan.addFinding(f9);

        // 10. Low Finding
        Finding f10 = new Finding();
        f10.setTitle("Missing Strict Content-Security-Policy (CSP) Header on Root Domain");
        f10.setSeverity(Severity.LOW);
        f10.setCategory(FindingCategory.SECURITY_HEADERS);
        f10.setSource("API Security Engine");
        f10.setEndpoint("https://worldmonitor.app");
        f10.setDescription("The web server does not return a Content-Security-Policy response header on root web assets.");
        f10.setImpact("Reduces defence-in-depth against client-side injection and malicious iframe framing.");
        f10.setEvidence("Inspected HTTP headers; no 'Content-Security-Policy' found.");
        f10.setRecommendation("Add Content-Security-Policy in `vercel.json` with strict script-src and object-src directives.");
        f10.setCwe("CWE-693: Protection Mechanism Failure");
        f10.setCvssScore(4.5);
        f10.setRemediationTimeMinutes(15);
        seedScan.addFinding(f10);

        // 11. Low Finding
        Finding f11 = new Finding();
        f11.setTitle("Anti-Clickjacking Frame Restrictions (X-Frame-Options) Not Configured");
        f11.setSeverity(Severity.LOW);
        f11.setCategory(FindingCategory.SECURITY_HEADERS);
        f11.setSource("API Security Engine");
        f11.setEndpoint("https://worldmonitor.app");
        f11.setDescription("The application does not specify X-Frame-Options or CSP frame-ancestors.");
        f11.setImpact("Allows third-party websites to embed World Monitor inside hidden iframes for clickjacking attacks.");
        f11.setEvidence("Header 'X-Frame-Options' was missing from server response.");
        f11.setRecommendation("Configure `X-Frame-Options: SAMEORIGIN` in Vercel configuration.");
        f11.setCwe("CWE-1021: Improper Restriction of Rendered UI Layers or Frames");
        f11.setCvssScore(4.1);
        f11.setRemediationTimeMinutes(10);
        seedScan.addFinding(f11);

        // 12. Info Finding
        Finding f12 = new Finding();
        f12.setTitle("Verbose API Build Metadata & Git Commit Hash Exposure");
        f12.setSeverity(Severity.INFO);
        f12.setCategory(FindingCategory.INFORMATION_DISCLOSURE);
        f12.setSource("API Security Engine");
        f12.setEndpoint("/api/version");
        f12.setDescription("Public `/api/version` endpoint returns exact software revision hash, deployment timestamp, and edge runtime version.");
        f12.setImpact("Provides reconnaissance intelligence for adversaries mapping specific package versions.");
        f12.setEvidence("Response: {\"version\": \"1.4.2\", \"commit\": \"a8f3b9c\", \"runtime\": \"nodejs20.x\"}");
        f12.setRecommendation("Consider returning a generic version string or requiring authenticated operator access.");
        f12.setCwe("CWE-200: Exposure of Sensitive Information");
        f12.setCvssScore(2.8);
        f12.setRemediationTimeMinutes(10);
        seedScan.addFinding(f12);

        vulnerabilityEngine.recalculateScanStats(seedScan, seedScan.getFindings());
        scanRepository.save(seedScan);
    }
}
