package com.sih.securityplatform.service;

import com.sih.securityplatform.model.Finding;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Collapses findings that describe the same problem.
 *
 * <p>The same weak pattern is frequently reported by more than one engine, or several times
 * within one engine (for example the same secret pattern on a re-scanned file). Deduplication is
 * keyed on the SHA-256 fingerprint assigned during normalisation, and duplicate hits are merged
 * rather than dropped so no evidence is lost.
 */
@Service
public class FindingDeduplicator {

    private static final Logger log = LoggerFactory.getLogger(FindingDeduplicator.class);

    public List<Finding> deduplicate(List<Finding> rawFindings) {
        if (rawFindings == null || rawFindings.isEmpty()) {
            return Collections.emptyList();
        }

        Map<String, Finding> uniqueMap = new LinkedHashMap<>();
        int duplicates = 0;

        for (Finding current : rawFindings) {
            if (current == null) {
                continue;
            }
            String fp = current.getFingerprint();

            if (fp == null || fp.isBlank()) {
                // No fingerprint yet — keep it, but make sure it cannot collide with a real one.
                uniqueMap.put("nofp:" + UUID.randomUUID(), current);
                continue;
            }

            Finding existing = uniqueMap.get(fp);
            if (existing == null) {
                uniqueMap.put(fp, current);
            } else {
                duplicates++;
                merge(existing, current);
            }
        }

        if (duplicates > 0) {
            log.info("Deduplication merged {} duplicate finding(s) by fingerprint", duplicates);
        }
        return new ArrayList<>(uniqueMap.values());
    }

    /** Fills gaps in the kept finding from the duplicate, without overwriting existing detail. */
    private void merge(Finding target, Finding duplicate) {
        if (isBlank(target.getEvidence()) && !isBlank(duplicate.getEvidence())) {
            target.setEvidence(duplicate.getEvidence());
        }
        if (isBlank(target.getPoc()) && !isBlank(duplicate.getPoc())) {
            target.setPoc(duplicate.getPoc());
        }
        if (isBlank(target.getHttpRequest()) && !isBlank(duplicate.getHttpRequest())) {
            target.setHttpRequest(duplicate.getHttpRequest());
        }
        if (isBlank(target.getHttpResponse()) && !isBlank(duplicate.getHttpResponse())) {
            target.setHttpResponse(duplicate.getHttpResponse());
        }
        if (isBlank(target.getRecommendation()) && !isBlank(duplicate.getRecommendation())) {
            target.setRecommendation(duplicate.getRecommendation());
        }
        if (target.getCvssScore() == null && duplicate.getCvssScore() != null) {
            target.setCvssScore(duplicate.getCvssScore());
        }
    }

    private boolean isBlank(String s) {
        return s == null || s.isBlank();
    }
}
