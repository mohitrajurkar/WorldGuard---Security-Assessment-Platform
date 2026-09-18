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
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

@Service
public class LeakIXService {

    private static final Logger log = LoggerFactory.getLogger(LeakIXService.class);
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final HttpClient httpClient = HttpClient.newBuilder()
            .version(HttpClient.Version.HTTP_1_1)
            .connectTimeout(Duration.ofSeconds(6))
            .build();

    public boolean isConfigured() {
        String key = System.getenv("LEAKIX_API_KEY");
        return key != null && !key.isBlank();
    }

    public boolean isAvailable() {
        // Can reach LeakIX public health or search endpoint
        if (!isConfigured()) return false;
        try {
            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create("https://leakix.net/search?page=0&q=example.com"))
                    .timeout(Duration.ofSeconds(4))
                    .header("api-key", System.getenv("LEAKIX_API_KEY"))
                    .GET()
                    .build();
            HttpResponse<Void> resp = httpClient.send(req, HttpResponse.BodyHandlers.discarding());
            return resp.statusCode() == 200 || resp.statusCode() == 429;
        } catch (Exception e) {
            return false;
        }
    }

    public List<Finding> queryIntelligence(String domain) {
        List<Finding> findings = new ArrayList<>();

        if (!isConfigured()) {
            log.info("LeakIX: LEAKIX_API_KEY not set in environment. External intelligence skipped.");
            return findings;
        }

        if (domain == null || domain.isBlank() || domain.contains("localhost") || domain.contains("127.0.0.1")) {
            log.info("LeakIX: Local target '{}' is not applicable for external OSINT intelligence.", domain);
            return findings;
        }

        String apiKey = System.getenv("LEAKIX_API_KEY");
        log.info("LeakIX started: Querying external threat intelligence for domain {}", domain);

        try {
            String encodedQuery = URLEncoder.encode("host:" + domain + " +scope:leak", StandardCharsets.UTF_8);
            String url = "https://leakix.net/search?page=0&q=" + encodedQuery;

            HttpRequest req = HttpRequest.newBuilder()
                    .uri(URI.create(url))
                    .timeout(Duration.ofSeconds(10))
                    .header("api-key", apiKey)
                    .header("Accept", "application/json")
                    .GET()
                    .build();

            HttpResponse<String> resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());

            if (resp.statusCode() == 200 && resp.body() != null && !resp.body().isBlank()) {
                JsonNode root = objectMapper.readTree(resp.body());
                if (root.isArray()) {
                    for (JsonNode item : root) {
                        Finding f = parseLeakResult(item, domain);
                        if (f != null) {
                            findings.add(f);
                        }
                    }
                }
            } else {
                log.info("LeakIX response: HTTP {}. No external leaks reported.", resp.statusCode());
            }

            log.info("LeakIX completed: Found {} external intelligence records.", findings.size());
        } catch (Exception e) {
            log.error("LeakIX query failed: {}", e.getMessage());
        }

        return findings;
    }

    private Finding parseLeakResult(JsonNode item, String domain) {
        try {
            String eventType = item.path("event_type").asText("External Exposure");
            String ip = item.path("ip").asText(domain);
            int port = item.path("port").asInt(80);
            String summary = item.path("summary").asText("Publicly indexed exposure detected on external network.");
            String time = item.path("time").asText("");

            Finding f = new Finding();
            f.setTitle("External Intelligence: " + eventType);
            f.setSource("LeakIX");
            f.setStatus(FindingStatus.EXTERNAL_INTELLIGENCE);
            f.setEndpoint(ip + ":" + port);
            f.setSeverity(Severity.MEDIUM);
            f.setCwe("CWE-200: Exposure of Sensitive Information");
            f.setCategory(FindingCategory.INFORMATION_DISCLOSURE);

            f.setWhatIsTheIssue("External threat intelligence indexer detected an exposed service: " + eventType);
            f.setWhyDoesItMatter("Publicly accessible services or leaked metadata on external infrastructure can be discovered by internet-wide scanners.");
            f.setDescription(summary);
            f.setEvidence("Indexed by LeakIX on " + time + " at " + ip + ":" + port);
            f.setImpact("May reveal infrastructure details, software versions, or unauthenticated services to external actors.");
            f.setRecommendation("Verify if " + ip + ":" + port + " is intended to be publicly accessible, and apply IP allowlisting or authentication.");
            f.setReproductionSteps("Review external network perimeter and firewall rules for IP " + ip);
            f.setRawTechnicalDetails("LeakIX Event: " + item.toString());
            f.setCvssScore(5.0);

            return f;
        } catch (Exception e) {
            return null;
        }
    }
}
