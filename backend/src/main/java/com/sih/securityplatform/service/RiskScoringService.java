package com.sih.securityplatform.service;

import com.sih.securityplatform.model.Finding;
import com.sih.securityplatform.model.FindingStatus;
import com.sih.securityplatform.model.Scan;
import com.sih.securityplatform.model.Severity;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class RiskScoringService {

    public void calculateAndApplyStats(Scan scan, List<Finding> findings) {
        int crit = 0, high = 0, med = 0, low = 0, info = 0;
        int verified = 0, needsReview = 0, potential = 0, informational = 0;

        int penalty = 0;

        for (Finding f : findings) {
            // Count severity
            if (f.getSeverity() == Severity.CRITICAL) crit++;
            else if (f.getSeverity() == Severity.HIGH) high++;
            else if (f.getSeverity() == Severity.MEDIUM) med++;
            else if (f.getSeverity() == Severity.LOW) low++;
            else if (f.getSeverity() == Severity.INFO) info++;

            // Count verification status
            FindingStatus st = f.getStatus() != null ? f.getStatus() : FindingStatus.POTENTIAL;
            switch (st) {
                case VERIFIED -> {
                    verified++;
                    // Verified issues deduct heavily
                    if (f.getSeverity() == Severity.CRITICAL) penalty += 25;
                    else if (f.getSeverity() == Severity.HIGH) penalty += 15;
                    else if (f.getSeverity() == Severity.MEDIUM) penalty += 8;
                    else if (f.getSeverity() == Severity.LOW) penalty += 3;
                }
                case NEEDS_REVIEW, EXTERNAL_INTELLIGENCE -> {
                    needsReview++;
                    // Needs review deducts moderately
                    if (f.getSeverity() == Severity.CRITICAL) penalty += 10;
                    else if (f.getSeverity() == Severity.HIGH) penalty += 5;
                    else if (f.getSeverity() == Severity.MEDIUM) penalty += 2;
                    else if (f.getSeverity() == Severity.LOW) penalty += 1;
                }
                case POTENTIAL -> {
                    potential++;
                    // Potential deducts very little so unverified static alerts don't destroy score
                    if (f.getSeverity() == Severity.CRITICAL) penalty += 3;
                    else if (f.getSeverity() == Severity.HIGH) penalty += 2;
                    else if (f.getSeverity() == Severity.MEDIUM) penalty += 1;
                }
                case INFORMATIONAL, FALSE_POSITIVE -> {
                    informational++;
                }
            }
        }

        int score = 100 - penalty;
        scan.setSecurityScore(Math.max(0, Math.min(100, score)));

        scan.setCriticalCount(crit);
        scan.setHighCount(high);
        scan.setMediumCount(med);
        scan.setLowCount(low);
        scan.setInfoCount(info);

        scan.setVerifiedCount(verified);
        scan.setNeedsReviewCount(needsReview);
        scan.setPotentialCount(potential);
        scan.setInformationalCount(informational);
    }
}
