package com.sih.securityplatform.service;

import com.sih.securityplatform.model.Finding;
import com.sih.securityplatform.model.FindingStatus;
import com.sih.securityplatform.model.Scan;
import com.sih.securityplatform.model.Severity;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The score is the headline number of the whole product, so its behaviour is pinned down here.
 */
class RiskScoringServiceTest {

    private final RiskScoringService service = new RiskScoringService();

    private Finding finding(Severity severity, FindingStatus status) {
        Finding f = new Finding();
        f.setSeverity(severity);
        f.setStatus(status);
        f.setTitle("t");
        return f;
    }

    private int scoreOf(Severity severity, FindingStatus status, int count) {
        Scan scan = new Scan();
        List<Finding> findings = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            findings.add(finding(severity, status));
        }
        service.calculateAndApplyStats(scan, findings);
        return scan.getSecurityScore();
    }

    @Test
    @DisplayName("a clean target scores 100")
    void cleanTargetScoresPerfect() {
        Scan scan = new Scan();
        service.calculateAndApplyStats(scan, new ArrayList<>());
        assertEquals(100, scan.getSecurityScore());
    }

    @Test
    @DisplayName("confirmed issues weigh far more than speculative ones of the same severity")
    void confidenceDominatesSeverity() {
        int verified = scoreOf(Severity.CRITICAL, FindingStatus.VERIFIED, 1);
        int potential = scoreOf(Severity.CRITICAL, FindingStatus.POTENTIAL, 1);
        assertTrue(verified < potential,
                "one confirmed critical (" + verified + ") must cost more than one speculative one (" + potential + ")");
    }

    @Test
    @DisplayName("a pile of unconfirmed static matches stays well above a confirmed breach")
    void unconfirmedNoiseDoesNotOutweighConfirmedRisk() {
        int noisy = scoreOf(Severity.CRITICAL, FindingStatus.POTENTIAL, 40);
        int confirmed = scoreOf(Severity.CRITICAL, FindingStatus.VERIFIED, 2);
        assertTrue(noisy > confirmed,
                "40 speculative criticals (" + noisy + ") should not read worse than 2 confirmed ones (" + confirmed + ")");
    }

    @Test
    @DisplayName("the score degrades gradually rather than dropping off a cliff")
    void scoreDegradesSmoothly() {
        int one = scoreOf(Severity.CRITICAL, FindingStatus.VERIFIED, 1);
        int two = scoreOf(Severity.CRITICAL, FindingStatus.VERIFIED, 2);
        int four = scoreOf(Severity.CRITICAL, FindingStatus.VERIFIED, 4);
        assertTrue(one > two && two > four, "more confirmed criticals must always score lower");
        // Diminishing returns: the second issue hurts less than half as much as the first.
        int firstDrop = 100 - one;
        int secondDrop = one - two;
        assertTrue(secondDrop < firstDrop,
                "expected diminishing returns, got drops of " + firstDrop + " then " + secondDrop);
    }

    @Test
    @DisplayName("severity ordering holds at equal confidence")
    void severityOrderingHolds() {
        int critical = scoreOf(Severity.CRITICAL, FindingStatus.NEEDS_REVIEW, 5);
        int high = scoreOf(Severity.HIGH, FindingStatus.NEEDS_REVIEW, 5);
        int medium = scoreOf(Severity.MEDIUM, FindingStatus.NEEDS_REVIEW, 5);
        int low = scoreOf(Severity.LOW, FindingStatus.NEEDS_REVIEW, 5);
        assertTrue(critical < high && high < medium && medium < low,
                "expected critical<high<medium<low, got " + critical + "," + high + "," + medium + "," + low);
    }

    @Test
    @DisplayName("severity counters always sum to the number of findings")
    void countersAlwaysSumToTotal() {
        Scan scan = new Scan();
        List<Finding> findings = List.of(
                finding(Severity.CRITICAL, FindingStatus.VERIFIED),
                finding(Severity.HIGH, FindingStatus.NEEDS_REVIEW),
                finding(Severity.MEDIUM, FindingStatus.POTENTIAL),
                finding(Severity.LOW, FindingStatus.POTENTIAL),
                finding(Severity.INFO, FindingStatus.POTENTIAL),
                finding(Severity.UNKNOWN, FindingStatus.POTENTIAL));

        service.calculateAndApplyStats(scan, findings);

        int total = scan.getCriticalCount() + scan.getHighCount() + scan.getMediumCount()
                + scan.getLowCount() + scan.getInfoCount();
        assertEquals(findings.size(), total, "every finding must land in exactly one severity bucket");

        int statusTotal = scan.getVerifiedCount() + scan.getNeedsReviewCount()
                + scan.getPotentialCount() + scan.getInformationalCount();
        assertEquals(findings.size(), statusTotal, "every finding must land in exactly one status bucket");
    }

    @Test
    @DisplayName("findings with a null severity or status are still counted")
    void nullsAreHandled() {
        Scan scan = new Scan();
        Finding bare = new Finding();
        bare.setTitle("no severity, no status");
        // The entity has defaults, so the null path has to be exercised explicitly.
        bare.setSeverity(null);
        bare.setStatus(null);

        service.calculateAndApplyStats(scan, List.of(bare));

        assertEquals(1, scan.getInfoCount());
        assertEquals(1, scan.getPotentialCount());
    }

    @Test
    @DisplayName("triaged-away findings cost nothing")
    void triageDowngradesRemoveThePenalty() {
        Scan scan = new Scan();
        service.calculateAndApplyStats(scan, List.of(
                finding(Severity.CRITICAL, FindingStatus.FALSE_POSITIVE),
                finding(Severity.HIGH, FindingStatus.INFORMATIONAL)));

        assertEquals(100, scan.getSecurityScore());
        assertEquals(2, scan.getInformationalCount());
    }

    @Test
    @DisplayName("the score is always clamped to 0-100")
    void scoreIsClamped() {
        Scan scan = new Scan();
        List<Finding> many = new ArrayList<>();
        for (int i = 0; i < 500; i++) {
            many.add(finding(Severity.CRITICAL, FindingStatus.VERIFIED));
        }
        service.calculateAndApplyStats(scan, many);
        assertTrue(scan.getSecurityScore() >= 0 && scan.getSecurityScore() <= 100);
    }

    @Test
    @DisplayName("individual risk points are ordered sensibly")
    void riskPointsAreOrdered() {
        double criticalVerified = RiskScoringService.riskPoints(Severity.CRITICAL, FindingStatus.VERIFIED);
        double criticalPotential = RiskScoringService.riskPoints(Severity.CRITICAL, FindingStatus.POTENTIAL);
        double lowVerified = RiskScoringService.riskPoints(Severity.LOW, FindingStatus.VERIFIED);
        double falsePositive = RiskScoringService.riskPoints(Severity.CRITICAL, FindingStatus.FALSE_POSITIVE);

        assertTrue(criticalVerified > criticalPotential);
        assertTrue(criticalPotential > lowVerified);
        assertEquals(0.0, falsePositive);
    }
}
