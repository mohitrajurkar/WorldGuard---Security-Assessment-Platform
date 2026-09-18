package com.sih.securityplatform.service;

import com.sih.securityplatform.dto.ApiProbeRequest;
import com.sih.securityplatform.dto.ApiProbeResult;
import com.sih.securityplatform.model.Finding;
import com.sih.securityplatform.model.FindingCategory;
import com.sih.securityplatform.model.FindingStatus;
import com.sih.securityplatform.model.Severity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Service
public class ApiScannerService {

    private static final Logger log = LoggerFactory.getLogger(ApiScannerService.class);
    private final HttpClient httpClient = HttpClient.newBuilder()
            .version(HttpClient.Version.HTTP_1_1)
            .connectTimeout(Duration.ofSeconds(4))
            .followRedirects(HttpClient.Redirect.NORMAL)
            .build();

    public boolean isReady() {
        return true;
    }

    public List<Finding> scanTarget(String targetBaseUrl) {
        List<Finding> findings = new ArrayList<>();
        if (targetBaseUrl == null || targetBaseUrl.isBlank()) {
            return findings;
        }

        String base = targetBaseUrl.replaceAll("/+$", "");
        log.info("API Security Scanner started: Probing authorized target at {}", base);

        // 1. Check Root Defensive Headers
        checkSecurityHeaders(base, findings);

        // 2. Check CORS Policy Behavior with safe test origin
        checkCorsConfiguration(base, findings);

        // 3. Safe Information Disclosure Check on standard endpoints
        checkEndpointInfoDisclosure(base + "/api/version", findings);
        checkEndpointInfoDisclosure(base + "/api/health", findings);

        // 4. Test HTTP Method Handling (TRACE method)
        checkTraceMethod(base, findings);

        log.info("API Security Scanner completed: Found {} evidence-backed observations.", findings.size());
        return findings;
    }

    private void checkSecurityHeaders(String baseUrl, List<Finding> findings) {
        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(baseUrl))
                    .timeout(Duration.ofSeconds(4))
                    .header("User-Agent", "WorldGuard-Security-Auditor/1.0")
                    .GET()
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            Map<String, List<String>> headers = response.headers().map();

            boolean hasCsp = headers.keySet().stream().anyMatch(h -> h.equalsIgnoreCase("Content-Security-Policy"));
            boolean hasXfo = headers.keySet().stream().anyMatch(h -> h.equalsIgnoreCase("X-Frame-Options"));
            boolean hasHsts = headers.keySet().stream().anyMatch(h -> h.equalsIgnoreCase("Strict-Transport-Security"));
            boolean hasNoSniff = headers.keySet().stream().anyMatch(h -> h.equalsIgnoreCase("X-Content-Type-Options"));

            if (!hasCsp) {
                Finding f = new Finding();
                f.setTitle("Missing Content-Security-Policy (CSP) Header");
                f.setSeverity(Severity.MEDIUM);
                f.setCategory(FindingCategory.SECURITY_HEADERS);
                f.setSource("API Scanner");
                f.setStatus(FindingStatus.VERIFIED);
                f.setEndpoint(baseUrl);
                f.setCwe("CWE-693: Protection Mechanism Failure");
                f.setCvssScore(5.4);

                f.setWhatIsTheIssue("The server does not include a Content-Security-Policy header in HTTP responses.");
                f.setWhyDoesItMatter("Without a Content-Security-Policy, the browser will not restrict where scripts, styles, or iframes can be loaded from, increasing the impact of XSS vulnerabilities.");
                f.setDescription("Response from " + baseUrl + " lacked a Content-Security-Policy header.");
                f.setEvidence("Request: GET " + baseUrl + " -> Response Status: " + response.statusCode() + " -> Headers: " + headers.keySet());
                f.setImpact("Attackers who find an injection point can execute scripts from arbitrary external domains.");
                f.setRecommendation("Configure a Content-Security-Policy header restricting script-src and connect-src to trusted domains.");
                f.setReproductionSteps("Send a GET request to " + baseUrl + " and inspect the response headers for 'Content-Security-Policy'.");
                f.setRawTechnicalDetails("HTTP " + response.statusCode() + "\nHeaders inspected: " + headers.keySet());
                findings.add(f);
            }

            if (!hasXfo) {
                Finding f = new Finding();
                f.setTitle("Missing Anti-Clickjacking Header (X-Frame-Options)");
                f.setSeverity(Severity.LOW);
                f.setCategory(FindingCategory.SECURITY_HEADERS);
                f.setSource("API Scanner");
                f.setStatus(FindingStatus.VERIFIED);
                f.setEndpoint(baseUrl);
                f.setCwe("CWE-1021: Improper Restriction of Rendered UI Layers");
                f.setCvssScore(4.3);

                f.setWhatIsTheIssue("The server does not include an X-Frame-Options or frame-ancestors header.");
                f.setWhyDoesItMatter("Malicious websites can embed your application inside a hidden <iframe> and trick users into clicking buttons they did not intend to click (Clickjacking).");
                f.setDescription("The web page does not declare whether it can be embedded in third-party iframes.");
                f.setEvidence("Request: GET " + baseUrl + " -> X-Frame-Options header not returned.");
                f.setImpact("Allows malicious framing of the application interface.");
                f.setRecommendation("Add 'X-Frame-Options: SAMEORIGIN' or 'X-Frame-Options: DENY' to HTTP response headers.");
                f.setReproductionSteps("Embed " + baseUrl + " inside an HTML <iframe> on an external test page.");
                f.setRawTechnicalDetails("Missing X-Frame-Options in HTTP " + response.statusCode() + " response.");
                findings.add(f);
            }

            if (!hasNoSniff) {
                Finding f = new Finding();
                f.setTitle("Missing MIME-Sniffing Protection (X-Content-Type-Options)");
                f.setSeverity(Severity.LOW);
                f.setCategory(FindingCategory.SECURITY_HEADERS);
                f.setSource("API Scanner");
                f.setStatus(FindingStatus.VERIFIED);
                f.setEndpoint(baseUrl);
                f.setCwe("CWE-79: Cross-site Scripting (MIME Confusion)");
                f.setCvssScore(3.4);

                f.setWhatIsTheIssue("The server does not send 'X-Content-Type-Options: nosniff'.");
                f.setWhyDoesItMatter("Browsers may attempt to detect (sniff) content types and execute uploaded text or images as JavaScript if content types are misinterpreted.");
                f.setDescription("HTTP response lacks X-Content-Type-Options: nosniff directive.");
                f.setEvidence("Request: GET " + baseUrl + " -> X-Content-Type-Options missing.");
                f.setImpact("Enables MIME-type confusion attacks in certain browsers.");
                f.setRecommendation("Add 'X-Content-Type-Options: nosniff' header to all server responses.");
                f.setReproductionSteps("Send a GET request to " + baseUrl + " and verify absence of X-Content-Type-Options.");
                f.setRawTechnicalDetails("Headers inspected: " + headers.keySet());
                findings.add(f);
            }
        } catch (Exception e) {
            log.info("API Scanner: Target {} was not reachable for header check ({}).", baseUrl, e.getMessage());
        }
    }

    private void checkCorsConfiguration(String baseUrl, List<Finding> findings) {
        try {
            String testOrigin = "https://untrusted-preview.example.com";
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(baseUrl + "/api/version"))
                    .timeout(Duration.ofSeconds(4))
                    .header("Origin", testOrigin)
                    .header("User-Agent", "WorldGuard-Security-Auditor/1.0")
                    .method("OPTIONS", HttpRequest.BodyPublishers.noBody())
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            String acao = response.headers().firstValue("access-control-allow-origin").orElse("");

            if ("*".equals(acao) || acao.contains("untrusted-preview") || acao.contains("example.com")) {
                Finding f = new Finding();
                f.setTitle("Permissive Cross-Origin Resource Sharing (CORS) Configuration");
                f.setSeverity(Severity.HIGH);
                f.setCategory(FindingCategory.CORS);
                f.setSource("API Scanner");
                f.setStatus(FindingStatus.VERIFIED);
                f.setEndpoint(baseUrl + "/api/version");
                f.setCwe("CWE-942: Permissive Cross-Domain Policy with Untrusted Domains");
                f.setCvssScore(7.1);

                f.setWhatIsTheIssue("The server allows requests from unauthorized or arbitrary origins via CORS.");
                f.setWhyDoesItMatter("A malicious website can make asynchronous requests to this endpoint from a user's browser and read sensitive data returned by the API.");
                f.setDescription("CORS preflight request with Origin '" + testOrigin + "' was reflected in Access-Control-Allow-Origin: " + acao);
                f.setEvidence("Request Origin: " + testOrigin + " -> Response Header: Access-Control-Allow-Origin: " + acao);
                f.setImpact("Cross-origin reading of API responses by untrusted websites.");
                f.setRecommendation("Restrict Access-Control-Allow-Origin strictly to verified application domains, and do not reflect untrusted origins.");
                f.setReproductionSteps("Send HTTP OPTIONS to " + baseUrl + "/api/version with header 'Origin: " + testOrigin + "' and observe response header 'Access-Control-Allow-Origin'.");
                f.setRawTechnicalDetails("Method: OPTIONS\nStatus: " + response.statusCode() + "\nACAO: " + acao);
                findings.add(f);
            }
        } catch (Exception ignored) {
        }
    }

    private void checkEndpointInfoDisclosure(String url, List<Finding> findings) {
        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .timeout(Duration.ofSeconds(4))
                    .header("User-Agent", "WorldGuard-Security-Auditor/1.0")
                    .GET()
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() == 200 && response.body() != null && response.body().length() > 5) {
                String body = response.body();
                boolean leaksDetails = body.contains("version") || body.contains("commit") || body.contains("build") || body.contains("uptime");
                if (leaksDetails) {
                    Finding f = new Finding();
                    f.setTitle("System Information Disclosure via Unauthenticated Endpoint");
                    f.setSeverity(Severity.LOW);
                    f.setCategory(FindingCategory.INFORMATION_DISCLOSURE);
                    f.setSource("API Scanner");
                    f.setStatus(FindingStatus.NEEDS_REVIEW);
                    f.setEndpoint(url);
                    f.setCwe("CWE-200: Exposure of Sensitive Information");
                    f.setCvssScore(3.8);

                    f.setWhatIsTheIssue("The server reveals internal build, version, or operational metadata without authentication.");
                    f.setWhyDoesItMatter("Attackers use exposed version numbers to find known unpatched vulnerabilities specific to that exact build.");
                    f.setDescription("Endpoint " + url + " responded with system details.");
                    String snippet = body.length() > 150 ? body.substring(0, 150) + "..." : body;
                    f.setEvidence("GET " + url + " returned HTTP 200 with payload: " + snippet);
                    f.setImpact("Aids external reconnaissance and vulnerability mapping.");
                    f.setRecommendation("Restrict internal health and version endpoints to authenticated administrators or internal networks.");
                    f.setReproductionSteps("Send a GET request to " + url + " and view the JSON response.");
                    f.setRawTechnicalDetails("URL: " + url + "\nStatus: 200\nBody Preview: " + snippet);
                    findings.add(f);
                }
            }
        } catch (Exception ignored) {
        }
    }

    private void checkTraceMethod(String baseUrl, List<Finding> findings) {
        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(baseUrl))
                    .timeout(Duration.ofSeconds(4))
                    .method("TRACE", HttpRequest.BodyPublishers.noBody())
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() == 200) {
                Finding f = new Finding();
                f.setTitle("HTTP TRACE Method Enabled");
                f.setSeverity(Severity.LOW);
                f.setCategory(FindingCategory.CONFIGURATION);
                f.setSource("API Scanner");
                f.setStatus(FindingStatus.NEEDS_REVIEW);
                f.setEndpoint(baseUrl);
                f.setCwe("CWE-693: Protection Mechanism Failure");
                f.setCvssScore(3.5);

                f.setWhatIsTheIssue("The server responded successfully to an HTTP TRACE request.");
                f.setWhyDoesItMatter("HTTP TRACE can be used by attackers in Cross-Site Tracing (XST) attacks to reflect HTTP headers containing session cookies.");
                f.setDescription("The web server accepted an HTTP TRACE request with status code 200.");
                f.setEvidence("Request: TRACE " + baseUrl + " -> Response Status: 200 OK");
                f.setImpact("Allows reflection of request headers, potentially facilitating session token theft.");
                f.setRecommendation("Disable the HTTP TRACE method in your web server or edge proxy configuration.");
                f.setReproductionSteps("Send a TRACE request to " + baseUrl + " and observe 200 OK response.");
                f.setRawTechnicalDetails("Method: TRACE\nStatus: " + response.statusCode());
                findings.add(f);
            }
        } catch (Exception ignored) {
        }
    }

    public ApiProbeResult probeEndpoint(ApiProbeRequest req) {
        ApiProbeResult result = new ApiProbeResult();
        long start = System.currentTimeMillis();
        int score = 100;

        try {
            HttpRequest.Builder builder = HttpRequest.newBuilder()
                    .uri(URI.create(req.getUrl()))
                    .timeout(Duration.ofSeconds(6));

            if (req.getHeaders() != null) {
                req.getHeaders().forEach(builder::header);
            }

            if ("POST".equalsIgnoreCase(req.getMethod())) {
                String body = req.getBody() != null ? req.getBody() : "";
                builder.POST(HttpRequest.BodyPublishers.ofString(body));
            } else if ("PUT".equalsIgnoreCase(req.getMethod())) {
                String body = req.getBody() != null ? req.getBody() : "";
                builder.PUT(HttpRequest.BodyPublishers.ofString(body));
            } else if ("DELETE".equalsIgnoreCase(req.getMethod())) {
                builder.DELETE();
            } else {
                builder.GET();
            }

            HttpResponse<String> response = httpClient.send(builder.build(), HttpResponse.BodyHandlers.ofString());
            result.setStatusCode(response.statusCode());
            result.setStatusText(response.statusCode() >= 200 && response.statusCode() < 300 ? "OK" : "Status " + response.statusCode());
            result.setResponseTimeMs(System.currentTimeMillis() - start);

            response.headers().map().forEach((k, v) -> {
                if (!v.isEmpty()) result.getResponseHeaders().put(k, v.get(0));
            });

            String body = response.body();
            if (body != null && body.length() > 4000) {
                result.setResponseBody(body.substring(0, 4000) + "\n...[truncated]");
            } else {
                result.setResponseBody(body);
            }

            // Analyze Security Attributes
            if (!result.getResponseHeaders().containsKey("content-security-policy")) {
                result.getSecurityAlerts().add("Missing Content-Security-Policy (CSP)");
                score -= 20;
            } else {
                result.getPositiveControls().add("Content-Security-Policy header present");
            }

            if (!result.getResponseHeaders().containsKey("x-content-type-options")) {
                result.getSecurityAlerts().add("Missing X-Content-Type-Options: nosniff");
                score -= 10;
            } else {
                result.getPositiveControls().add("MIME Sniffing protection enabled (nosniff)");
            }

            if (!result.getResponseHeaders().containsKey("x-frame-options")) {
                result.getSecurityAlerts().add("Missing X-Frame-Options anti-clickjacking header");
                score -= 10;
            } else {
                result.getPositiveControls().add("Clickjacking protection active");
            }

            if (result.getResponseHeaders().containsKey("access-control-allow-origin")) {
                String acao = result.getResponseHeaders().get("access-control-allow-origin");
                if ("*".equals(acao)) {
                    result.getSecurityAlerts().add("Wildcard CORS (Access-Control-Allow-Origin: *)");
                    score -= 25;
                } else {
                    result.getPositiveControls().add("CORS restricted to: " + acao);
                }
            }

            if (response.statusCode() == 500 && body != null && (body.contains("stack") || body.contains("Exception") || body.contains("Error:"))) {
                result.getSecurityAlerts().add("Sensitive stack trace leakage in HTTP 500 response");
                score -= 30;
            }

        } catch (Exception e) {
            result.setStatusCode(0);
            result.setStatusText("Connection Failed: " + e.getMessage());
            result.setResponseTimeMs(System.currentTimeMillis() - start);
            result.getSecurityAlerts().add("Target could not be reached: " + e.getMessage());
            score = 50;
        }

        result.setSecurityGradeScore(Math.max(0, score));
        return result;
    }
}
