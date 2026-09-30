package com.sih.securityplatform.service;

import com.sih.securityplatform.model.Finding;
import com.sih.securityplatform.model.FindingCategory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Correlation Engine.
 * Correlates findings by endpoint, attack surface vector, and multi-vulnerability exposure chains.
 * Architected to support future scanner adapters (Semgrep, ZAP, threat feeds) without architectural redesign.
 */
@Service
public class CorrelationEngine {

    private static final Logger log = LoggerFactory.getLogger(CorrelationEngine.class);

    public void correlateFindings(List<Finding> findings) {
        if (findings == null || findings.size() < 2) return;

        // 1. Group findings by endpoint to discover compound attack surfaces
        Map<String, List<Finding>> endpointGroups = findings.stream()
                .filter(f -> f.getEndpoint() != null && !f.getEndpoint().isBlank())
                .collect(Collectors.groupingBy(Finding::getEndpoint));

        for (Map.Entry<String, List<Finding>> entry : endpointGroups.entrySet()) {
            String endpoint = entry.getKey();
            List<Finding> group = entry.getValue();

            if (group.size() > 1) {
                boolean hasInjection = group.stream().anyMatch(f -> f.getCategory() == FindingCategory.INJECTION);
                boolean hasHeaderFlaw = group.stream().anyMatch(f -> f.getCategory() == FindingCategory.CONFIGURATION);

                if (hasInjection && hasHeaderFlaw) {
                    for (Finding f : group) {
                        if (f.getCategory() == FindingCategory.INJECTION) {
                            f.setImpact(f.getImpact() + " [Correlated Vector: Weak browser security headers on endpoint "
                                    + endpoint + " amplify the exploitability of this vulnerability.]");
                        }
                    }
                }
            }
        }

        // 2. Identify compound authentication / authorization flaws
        List<Finding> authFindings = findings.stream()
                .filter(f -> f.getCategory() == FindingCategory.AUTHENTICATION || f.getCategory() == FindingCategory.AUTHORIZATION)
                .toList();

        if (authFindings.size() > 1) {
            log.info("Correlated multiple authentication/authorization issues on target: {} findings", authFindings.size());
        }
    }
}
