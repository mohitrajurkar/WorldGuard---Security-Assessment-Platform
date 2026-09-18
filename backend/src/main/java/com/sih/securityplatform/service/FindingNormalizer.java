package com.sih.securityplatform.service;

import com.sih.securityplatform.model.Finding;
import com.sih.securityplatform.model.FindingStatus;
import com.sih.securityplatform.model.Severity;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.List;

@Service
public class FindingNormalizer {

    public void normalize(List<Finding> findings) {
        if (findings == null) return;

        for (Finding f : findings) {
            // Generate deterministic fingerprint
            if (f.getFingerprint() == null || f.getFingerprint().isBlank()) {
                f.setFingerprint(generateFingerprint(
                        f.getTitle(),
                        f.getEndpoint() != null ? f.getEndpoint() : f.getFilePath(),
                        f.getSource()
                ));
            }

            // Ensure human-readable explanations exist
            if (f.getWhatIsTheIssue() == null || f.getWhatIsTheIssue().isBlank()) {
                f.setWhatIsTheIssue(f.getDescription() != null ? f.getDescription() : f.getTitle());
            }

            if (f.getWhyDoesItMatter() == null || f.getWhyDoesItMatter().isBlank()) {
                f.setWhyDoesItMatter(f.getImpact() != null ? f.getImpact() : "This issue may weaken application security.");
            }

            // Ensure status is initialized
            if (f.getStatus() == null) {
                f.setStatus(FindingStatus.POTENTIAL);
            }

            // Standardize remediation time
            if (f.getRemediationTimeMinutes() == null || f.getRemediationTimeMinutes() <= 0) {
                switch (f.getSeverity()) {
                    case CRITICAL -> f.setRemediationTimeMinutes(120);
                    case HIGH -> f.setRemediationTimeMinutes(90);
                    case MEDIUM -> f.setRemediationTimeMinutes(45);
                    case LOW -> f.setRemediationTimeMinutes(20);
                    default -> f.setRemediationTimeMinutes(10);
                }
            }
        }
    }

    private String generateFingerprint(String title, String location, String source) {
        try {
            String raw = (title != null ? title.toLowerCase().trim() : "") + ":" +
                         (location != null ? location.toLowerCase().trim() : "") + ":" +
                         (source != null ? source.toLowerCase().trim() : "");
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(raw.getBytes(StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }
            return hexString.toString().substring(0, 16);
        } catch (Exception e) {
            return String.valueOf(((title != null ? title : "") + (location != null ? location : "")).hashCode());
        }
    }
}
