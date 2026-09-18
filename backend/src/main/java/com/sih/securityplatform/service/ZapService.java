package com.sih.securityplatform.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
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

@Service
public class ZapService {

    private static final Logger log = LoggerFactory.getLogger(ZapService.class);
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final HttpClient httpClient = HttpClient.newBuilder()
            .version(HttpClient.Version.HTTP_1_1)
            .connectTimeout(Duration.ofSeconds(3))
            .build();

    private final String zapBaseUrl = "http://localhost:8090";

    public boolean isAvailable() {
        try {
            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(zapBaseUrl + "/JSON/core/view/version/"))
                    .timeout(Duration.ofSeconds(2))
                    .GET()
                    .build();
            HttpResponse<String> resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
            return resp.statusCode() == 200;
        } catch (Exception e) {
            return false;
        }
    }

    public List<Finding> scanTarget(String targetUrl) {
        List<Finding> findings = new ArrayList<>();

        if (!isAvailable()) {
            log.info("ZAP: Dynamic scanner is not reachable on {}. Dynamic scan could not be completed.", zapBaseUrl);
            return findings;
        }

        log.info("ZAP started: Querying active alerts for target {}", targetUrl);
        try {
            String zapAlertsUrl = zapBaseUrl + "/JSON/core/view/alerts/?baseurl=" + targetUrl;
            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(zapAlertsUrl))
                    .timeout(Duration.ofSeconds(15))
                    .GET()
                    .build();

            HttpResponse<String> resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() == 200) {
                JsonNode root = objectMapper.readTree(resp.body());
                JsonNode alerts = root.path("alerts");
                if (alerts.isArray()) {
                    for (JsonNode alert : alerts) {
                        Finding f = parseZapAlert(alert, targetUrl);
                        if (f != null) {
                            findings.add(f);
                        }
                    }
                }
            }
            log.info("ZAP completed: Discovered {} actual alerts from ZAP API.", findings.size());
        } catch (Exception e) {
            log.error("ZAP dynamic analysis error: {}", e.getMessage());
        }

        return findings;
    }

    private Finding parseZapAlert(JsonNode alert, String targetUrl) {
        try {
            String rawTitle = alert.path("alert").asText("Dynamic Security Alert");
            String risk = alert.path("risk").asText("Medium").toUpperCase();
            String confidence = alert.path("confidence").asText("Medium");
            String url = alert.path("url").asText(targetUrl);
            String param = alert.path("param").asText("");
            String evidence = alert.path("evidence").asText("");
            String description = alert.path("description").asText("");
            String solution = alert.path("solution").asText("");
            String cweId = alert.path("cweid").asText("693");

            Finding f = new Finding();
            f.setTitle(rawTitle);
            f.setSource("OWASP ZAP");
            f.setStatus(FindingStatus.NEEDS_REVIEW);
            f.setEndpoint(url);
            f.setSeverity(mapRisk(risk));
            f.setCwe("CWE-" + cweId);
            f.setCategory(mapCategory(rawTitle, description));

            f.setWhatIsTheIssue("Dynamic testing detected: " + rawTitle + (param.isBlank() ? "" : " on parameter '" + param + "'"));
            f.setWhyDoesItMatter("Dynamic behavior indicates missing defensive mechanisms or unvalidated responses while the application is running.");
            f.setDescription(description);
            f.setEvidence(evidence.isBlank() ? "Observed URL: " + url + " (Confidence: " + confidence + ")" : evidence);
            f.setImpact("May allow attackers to exploit runtime behavior against connected clients.");
            f.setRecommendation(solution.isBlank() ? "Apply standard OWASP defense guidelines for " + rawTitle : solution);
            f.setReproductionSteps("Send HTTP request to " + url + (param.isBlank() ? "" : " with parameter " + param) + " and inspect server response.");
            f.setRawTechnicalDetails("Alert: " + rawTitle + "\nRisk: " + risk + "\nConfidence: " + confidence + "\nParam: " + param);
            f.setCvssScore(estimateCvss(f.getSeverity()));

            return f;
        } catch (Exception e) {
            return null;
        }
    }

    private Severity mapRisk(String risk) {
        if (risk.contains("HIGH")) return Severity.HIGH;
        if (risk.contains("MED")) return Severity.MEDIUM;
        if (risk.contains("LOW")) return Severity.LOW;
        return Severity.INFO;
    }

    private FindingCategory mapCategory(String title, String desc) {
        String combined = (title + " " + desc).toLowerCase();
        if (combined.contains("header")) return FindingCategory.SECURITY_HEADERS;
        if (combined.contains("xss") || combined.contains("inject")) return FindingCategory.INJECTION;
        if (combined.contains("cors")) return FindingCategory.CORS;
        if (combined.contains("cookie") || combined.contains("session")) return FindingCategory.AUTHENTICATION;
        return FindingCategory.CONFIGURATION;
    }

    private double estimateCvss(Severity severity) {
        return switch (severity) {
            case CRITICAL -> 8.2;
            case HIGH -> 7.2;
            case MEDIUM -> 5.2;
            case LOW -> 3.2;
            case INFO -> 1.0;
        };
    }
}
