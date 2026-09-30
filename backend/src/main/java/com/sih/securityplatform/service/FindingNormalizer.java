package com.sih.securityplatform.service;

import com.sih.securityplatform.dto.NormalizedFinding;
import com.sih.securityplatform.model.Finding;
import com.sih.securityplatform.model.FindingStatus;
import com.sih.securityplatform.model.Severity;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;

@Service
public class FindingNormalizer {

    public List<Finding> normalizeFromPentest(List<NormalizedFinding> normalizedFindings) {
        List<Finding> result = new ArrayList<>();
        if (normalizedFindings == null) return result;

        for (NormalizedFinding nf : normalizedFindings) {
            Finding f = new Finding();
            f.setTitle(nf.getTitle());
            f.setDescription(nf.getDescription());
            f.setSeverity(nf.getSeverity() != null ? nf.getSeverity() : Severity.UNKNOWN);
            f.setCategory(nf.getCategory());
            f.setStatus(nf.getStatus() != null ? nf.getStatus() : FindingStatus.NEEDS_REVIEW);

            f.setSource("PENTEST_SUITE");
            f.setScanner("PENTEST_SUITE");
            f.setExternalFindingId(nf.getScannerFindingId());

            f.setTarget(nf.getTarget());
            f.setEndpoint(nf.getEndpoint());
            f.setMethod(nf.getMethod());
            f.setParameter(nf.getParameter());

            f.setEvidence(nf.getEvidence());
            f.setPoc(nf.getPoc());
            f.setHttpRequest(nf.getRequest());
            f.setHttpResponse(nf.getResponse());
            f.setRecommendation(nf.getRecommendation());
            f.setImpact(nf.getImpact());
            f.setReproductionSteps(nf.getReproductionSteps());
            f.setRawFinding(nf.getRawFinding());
            f.setRawTechnicalDetails(nf.getRawFinding());

            f.setCwe(nf.getCwe());
            f.setOwaspCategory(nf.getOwaspCategory());
            f.setCvssScore(nf.getCvssScore());
            f.setCvssVector(nf.getCvssVector());

            f.setWhatIsTheIssue(nf.getDescription() != null && !nf.getDescription().isBlank() ? nf.getDescription() : nf.getTitle());
            f.setWhyDoesItMatter(nf.getImpact() != null ? nf.getImpact() : "This vulnerability exposes the application to security risks.");

            // Calculate stable SHA-256 fingerprint
            String fp = generateFingerprint(
                    nf.getCategory() != null ? nf.getCategory().name() : "GENERAL",
                    nf.getTarget(),
                    nf.getEndpoint(),
                    nf.getParameter(),
                    nf.getCwe(),
                    nf.getSource()
            );
            f.setFingerprint(fp);

            // Assign standard remediation estimate
            f.setRemediationTimeMinutes(calculateRemediationTime(f.getSeverity()));

            result.add(f);
        }
        return result;
    }

    public void normalize(List<Finding> findings) {
        if (findings == null) return;
        for (Finding f : findings) {
            if (f.getFingerprint() == null || f.getFingerprint().isBlank()) {
                f.setFingerprint(generateFingerprint(
                        f.getCategory() != null ? f.getCategory().name() : "GENERAL",
                        f.getTarget(),
                        f.getEndpoint() != null ? f.getEndpoint() : f.getFilePath(),
                        f.getParameter(),
                        f.getCwe(),
                        f.getSource()
                ));
            }
            if (f.getWhatIsTheIssue() == null || f.getWhatIsTheIssue().isBlank()) {
                f.setWhatIsTheIssue(f.getDescription() != null ? f.getDescription() : f.getTitle());
            }
            if (f.getWhyDoesItMatter() == null || f.getWhyDoesItMatter().isBlank()) {
                f.setWhyDoesItMatter(f.getImpact() != null ? f.getImpact() : "This issue may weaken application security.");
            }
            if (f.getStatus() == null) {
                f.setStatus(FindingStatus.NEEDS_REVIEW);
            }
            if (f.getRemediationTimeMinutes() == null || f.getRemediationTimeMinutes() <= 0) {
                f.setRemediationTimeMinutes(calculateRemediationTime(f.getSeverity()));
            }
        }
    }

    public String generateFingerprint(String category, String target, String endpoint, String parameter, String cwe, String source) {
        try {
            String normCategory = category != null ? category.trim().toUpperCase() : "";
            String normTarget = target != null ? target.trim().toLowerCase() : "";
            String normEndpoint = endpoint != null ? endpoint.trim().toLowerCase() : "/";
            String normParam = parameter != null ? parameter.trim().toLowerCase() : "";
            String normCwe = cwe != null ? cwe.trim().toUpperCase() : "";

            String raw = normCategory + "|" + normTarget + "|" + normEndpoint + "|" + normParam + "|" + normCwe;

            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(raw.getBytes(StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (Exception e) {
            return String.valueOf(((target != null ? target : "") + (endpoint != null ? endpoint : "") + (cwe != null ? cwe : "")).hashCode());
        }
    }

    private int calculateRemediationTime(Severity severity) {
        if (severity == null) return 30;
        return switch (severity) {
            case CRITICAL -> 120;
            case HIGH -> 90;
            case MEDIUM -> 45;
            case LOW -> 20;
            case INFO -> 10;
            case UNKNOWN -> 30;
        };
    }
}
