package com.sih.securityplatform.service;

import com.sih.securityplatform.model.Finding;
import com.sih.securityplatform.model.FindingStatus;
import org.springframework.stereotype.Service;

import java.util.*;

@Service
public class FindingDeduplicator {

    public List<Finding> deduplicateAndCorrelate(List<Finding> rawFindings) {
        if (rawFindings == null || rawFindings.isEmpty()) {
            return Collections.emptyList();
        }

        Map<String, Finding> uniqueMap = new LinkedHashMap<>();

        for (Finding current : rawFindings) {
            String fp = current.getFingerprint();
            if (fp == null || fp.isBlank()) {
                uniqueMap.put(UUID.randomUUID().toString(), current);
                continue;
            }

            if (!uniqueMap.containsKey(fp)) {
                uniqueMap.put(fp, current);
            } else {
                // If existing finding has less evidence, merge info
                Finding existing = uniqueMap.get(fp);
                if ((existing.getEvidence() == null || existing.getEvidence().isBlank()) && current.getEvidence() != null) {
                    existing.setEvidence(current.getEvidence());
                }
            }
        }

        List<Finding> list = new ArrayList<>(uniqueMap.values());

        // Perform cross-layer correlation between Static (Semgrep) and Dynamic (API/ZAP)
        correlateStaticAndDynamic(list);

        return list;
    }

    private void correlateStaticAndDynamic(List<Finding> findings) {
        for (int i = 0; i < findings.size(); i++) {
            Finding f1 = findings.get(i);
            for (int j = i + 1; j < findings.size(); j++) {
                Finding f2 = findings.get(j);

                boolean oneIsStatic = "Semgrep".equalsIgnoreCase(f1.getSource());
                boolean twoIsStatic = "Semgrep".equalsIgnoreCase(f2.getSource());

                if (oneIsStatic != twoIsStatic) {
                    // One is static, one is dynamic
                    boolean sameCategory = f1.getCategory() == f2.getCategory();
                    boolean corsMatch = f1.getTitle().toLowerCase().contains("cors") && f2.getTitle().toLowerCase().contains("cors");
                    boolean headerMatch = f1.getTitle().toLowerCase().contains("header") && f2.getTitle().toLowerCase().contains("header");

                    if (sameCategory && (corsMatch || headerMatch)) {
                        Finding base = oneIsStatic ? f2 : f1;
                        Finding counterpart = oneIsStatic ? f1 : f2;

                        base.setSource("Semgrep + " + base.getSource());
                        base.setStatus(FindingStatus.VERIFIED);
                        base.setWhyDoesItMatter(base.getWhyDoesItMatter() + " (Correlated: Source inspection and running behavior both confirm this issue).");

                        findings.remove(j);
                        j--;
                    }
                }
            }
        }
    }
}
