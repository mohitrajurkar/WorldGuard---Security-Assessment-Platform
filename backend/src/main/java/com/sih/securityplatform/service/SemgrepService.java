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

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

@Service
public class SemgrepService {

    private static final Logger log = LoggerFactory.getLogger(SemgrepService.class);
    private final ObjectMapper objectMapper = new ObjectMapper();

    private String cachedVersion = null;

    public boolean isAvailable() {
        String v = getVersion();
        return v != null && !v.equals("Unavailable");
    }

    public synchronized String getVersion() {
        if (cachedVersion != null) {
            return cachedVersion;
        }
        try {
            ProcessBuilder pb = new ProcessBuilder("semgrep", "--version");
            pb.redirectErrorStream(true);
            Process process = pb.start();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line = reader.readLine();
                process.waitFor(10, java.util.concurrent.TimeUnit.SECONDS);
                cachedVersion = (line != null && !line.isBlank()) ? line.trim() : "Available";
                return cachedVersion;
            }
        } catch (Exception e) {
            cachedVersion = "Unavailable";
            return cachedVersion;
        }
    }

    public List<Finding> scanSource(String sourcePath) {
        List<Finding> findings = new ArrayList<>();

        if (sourcePath == null || sourcePath.isBlank()) {
            log.info("Semgrep: No source directory provided. Skipping static analysis.");
            return findings;
        }

        File dir = new File(sourcePath);
        if (!dir.exists() || !dir.isDirectory()) {
            log.warn("Semgrep: Specified source directory does not exist: {}", sourcePath);
            return findings;
        }

        if (!isAvailable()) {
            log.warn("Semgrep: CLI is not available in system PATH. Static code analysis could not run.");
            return findings;
        }

        log.info("Semgrep started: Scanning source repository at {}", sourcePath);
        try {
            ProcessBuilder pb = new ProcessBuilder(
                    "semgrep",
                    "scan",
                    "--config", "auto",
                    "--json",
                    sourcePath
            );
            pb.redirectErrorStream(false);
            Process process = pb.start();

            StringBuilder jsonOutput = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    jsonOutput.append(line);
                }
            }

            process.waitFor(120, java.util.concurrent.TimeUnit.SECONDS);

            if (jsonOutput.length() > 0) {
                JsonNode root = objectMapper.readTree(jsonOutput.toString());
                JsonNode results = root.path("results");
                if (results.isArray()) {
                    for (JsonNode item : results) {
                        Finding f = parseSemgrepResult(item);
                        if (f != null) {
                            findings.add(f);
                        }
                    }
                }
            }
            log.info("Semgrep completed: Found {} real static analysis results.", findings.size());
        } catch (Exception e) {
            log.error("Semgrep execution failed: {}", e.getMessage());
        }

        return findings;
    }

    private Finding parseSemgrepResult(JsonNode item) {
        try {
            String checkId = item.path("check_id").asText("semgrep.rule");
            String filePath = item.path("path").asText("");
            int startLine = item.path("start").path("line").asInt(1);
            String rawMessage = item.path("extra").path("message").asText("");
            String rawLines = item.path("extra").path("lines").asText("").trim();
            String rawSeverity = item.path("extra").path("severity").asText("INFO").toUpperCase();
            JsonNode metadata = item.path("extra").path("metadata");
            String cwe = metadata.path("cwe").isArray() && metadata.path("cwe").size() > 0
                    ? metadata.path("cwe").get(0).asText("CWE-707")
                    : metadata.path("cwe").asText("CWE-707");

            Finding f = new Finding();
            f.setTitle(formatHumanTitle(checkId, rawMessage));
            f.setSource("Semgrep");
            f.setStatus(FindingStatus.POTENTIAL);
            f.setFilePath(filePath);
            f.setLineNumber(startLine);
            f.setCwe(cwe);
            f.setSeverity(mapSeverity(rawSeverity));
            f.setCategory(mapCategory(checkId, rawMessage));

            f.setWhatIsTheIssue("Semgrep detected a potential code pattern: " + simplifyMessage(rawMessage));
            f.setWhyDoesItMatter("Unvalidated or insecure patterns in source code can introduce vulnerabilities if user input reaches this execution flow.");
            f.setDescription(rawMessage);
            f.setEvidence(rawLines.isBlank() ? "File: " + filePath + ", Line: " + startLine : rawLines);
            f.setImpact("May allow unauthorized manipulation or bypass of intended application logic depending on surrounding execution context.");
            f.setRecommendation("Review code according to security best practices and ensure all inputs are strictly validated.");
            f.setReproductionSteps("Inspect source code at " + filePath + ":" + startLine + " and trace callers.");
            f.setRawTechnicalDetails("Rule: " + checkId + "\nMetadata: " + metadata.toString());
            f.setCvssScore(estimateCvss(f.getSeverity()));

            return f;
        } catch (Exception e) {
            log.warn("Error parsing individual Semgrep result item: {}", e.getMessage());
            return null;
        }
    }

    private String formatHumanTitle(String checkId, String message) {
        if (checkId.contains("regex") || checkId.contains("redos")) {
            return "Potential Unsafe Regular Expression Pattern";
        }
        if (checkId.contains("secret") || checkId.contains("token") || checkId.contains("key")) {
            return "Potential Hardcoded Credential Pattern";
        }
        if (checkId.contains("injection") || checkId.contains("xss") || checkId.contains("innerhtml")) {
            return "Potential Client-Side Input Injection Pattern";
        }
        if (checkId.contains("cors")) {
            return "Potential Overly Permissive Cross-Origin Policy";
        }
        if (checkId.contains("ssrf")) {
            return "Potential Unvalidated Outbound Request Pattern";
        }

        // Clean up rule ID to make readable title
        String[] parts = checkId.split("\\.");
        if (parts.length > 0) {
            String last = parts[parts.length - 1].replace('-', ' ').replace('_', ' ');
            return "Potential " + capitalize(last);
        }
        return "Potential Static Analysis Finding";
    }

    private String simplifyMessage(String msg) {
        if (msg == null || msg.isBlank()) return "Code pattern identified by static analyzer.";
        // Truncate and clean technical jargon
        String clean = msg.replaceAll("\\s+", " ").trim();
        return clean.length() > 180 ? clean.substring(0, 180) + "..." : clean;
    }

    private String capitalize(String text) {
        if (text == null || text.isBlank()) return text;
        String[] words = text.split(" ");
        StringBuilder sb = new StringBuilder();
        for (String w : words) {
            if (!w.isBlank()) {
                sb.append(Character.toUpperCase(w.charAt(0))).append(w.substring(1).toLowerCase()).append(" ");
            }
        }
        return sb.toString().trim();
    }

    private Severity mapSeverity(String sev) {
        if (sev.contains("ERROR") || sev.contains("CRIT")) return Severity.HIGH;
        if (sev.contains("WARN") || sev.contains("MED")) return Severity.MEDIUM;
        if (sev.contains("LOW")) return Severity.LOW;
        return Severity.INFO;
    }

    private FindingCategory mapCategory(String checkId, String msg) {
        String combined = (checkId + " " + msg).toLowerCase();
        if (combined.contains("auth") || combined.contains("secret") || combined.contains("token")) return FindingCategory.AUTHENTICATION;
        if (combined.contains("cors") || combined.contains("origin")) return FindingCategory.CORS;
        if (combined.contains("xss") || combined.contains("inject") || combined.contains("html")) return FindingCategory.INJECTION;
        if (combined.contains("ssrf")) return FindingCategory.SSRF;
        if (combined.contains("rate")) return FindingCategory.RATE_LIMITING;
        if (combined.contains("header")) return FindingCategory.SECURITY_HEADERS;
        return FindingCategory.CODE_QUALITY;
    }

    private double estimateCvss(Severity severity) {
        return switch (severity) {
            case CRITICAL -> 8.5;
            case HIGH -> 7.0;
            case MEDIUM -> 5.0;
            case LOW -> 3.5;
            case INFO -> 1.0;
        };
    }
}
