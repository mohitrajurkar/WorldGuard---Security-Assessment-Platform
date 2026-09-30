package com.sih.securityplatform.service;

import com.sih.securityplatform.model.Finding;
import com.sih.securityplatform.model.FindingStatus;
import com.sih.securityplatform.model.Severity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * Evidence-driven Verification Engine.
 * Evaluates findings against proof-of-concept criteria to classify them as
 * VERIFIED, NEEDS_REVIEW, or POTENTIAL.
 */
@Service
public class VerificationEngine {

    private static final Logger log = LoggerFactory.getLogger(VerificationEngine.class);

    public void verifyFindings(List<Finding> findings) {
        if (findings == null || findings.isEmpty()) return;

        for (Finding f : findings) {
            FindingStatus status = evaluateVerification(f);
            f.setStatus(status);
        }
        log.info("Verification engine classified {} findings", findings.size());
    }

    private FindingStatus evaluateVerification(Finding f) {
        String evidence = f.getEvidence() != null ? f.getEvidence().toLowerCase() : "";
        String title = f.getTitle() != null ? f.getTitle().toLowerCase() : "";
        String response = f.getHttpResponse() != null ? f.getHttpResponse().toLowerCase() : "";

        // Criteria for VERIFIED status: concrete proof observed in HTTP response
        boolean hasDirectProof = false;

        // 1. Confirmed security headers misconfiguration (CSP, X-Frame, HSTS, CORS)
        if (evidence.contains("csp:") || evidence.contains("missing security header")
                || evidence.contains("unsafe-inline") || evidence.contains("access-control-allow-origin: *")
                || evidence.contains("x-frame-options missing") || evidence.contains("strict-transport-security")) {
            hasDirectProof = true;
        }

        // 2. Sensitive path / robots.txt / file disclosure with verified response content
        if ((title.contains("robots.txt") || title.contains("sensitive") || title.contains("file"))
                && (evidence.contains("found") || evidence.contains("disclosed") || evidence.contains("200"))) {
            hasDirectProof = true;
        }

        // 3. Injection with reflected payload or confirmed SQL syntax error
        if (title.contains("sql") && (evidence.contains("syntax error") || response.contains("sql syntax")
                || response.contains("database error"))) {
            hasDirectProof = true;
        }

        if (title.contains("xss") && (evidence.contains("reflected") || response.contains("<script")
                || evidence.contains("sink detected"))) {
            hasDirectProof = true;
        }

        // 4. Clickjacking with confirmed missing framing controls
        if (title.contains("clickjacking") && (evidence.contains("no frame protection") || evidence.contains("missing"))) {
            hasDirectProof = true;
        }

        if (hasDirectProof && f.getSeverity() != null && f.getSeverity() != Severity.INFO) {
            return FindingStatus.VERIFIED;
        }

        // Static analysis matches a source pattern; nothing here proves the code is reachable or
        // exploited. They stay POTENTIAL so the score is not inflated by unconfirmed matches.
        if (isStatic(f)) {
            return f.getSeverity() == Severity.INFO ? FindingStatus.INFORMATIONAL : FindingStatus.POTENTIAL;
        }

        // Heuristic reconnaissance or informational disclosure -> POTENTIAL
        if (f.getSeverity() == Severity.INFO || title.contains("detect") || title.contains("fingerprint")
                || title.contains("stack")) {
            return FindingStatus.POTENTIAL;
        }

        // Timing anomaly, generic error code, or potential injections without response proof
        return FindingStatus.NEEDS_REVIEW;
    }

    /** True for findings that came from analysing source code rather than probing a live target. */
    private boolean isStatic(Finding f) {
        return f.getFilePath() != null && !f.getFilePath().isBlank();
    }
}
