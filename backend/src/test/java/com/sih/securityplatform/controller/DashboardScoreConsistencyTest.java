package com.sih.securityplatform.controller;

import com.sih.securityplatform.model.Finding;
import com.sih.securityplatform.model.FindingCategory;
import com.sih.securityplatform.model.FindingStatus;
import com.sih.securityplatform.model.Scan;
import com.sih.securityplatform.model.ScanStatus;
import com.sih.securityplatform.model.ScanType;
import com.sih.securityplatform.model.Severity;
import com.sih.securityplatform.repository.FindingRepository;
import com.sih.securityplatform.repository.ScanRepository;
import com.sih.securityplatform.service.RiskScoringService;
import com.sih.securityplatform.service.ScanDurationService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The dashboard score and the dashboard counters must describe the same set of findings.
 *
 * <p>They previously did not: the score came from the newest scan while the counters summed
 * every finding, so a clean single-endpoint scan could present "92/100 — strong" directly above
 * 21 high-severity issues from an earlier scan.
 */
@SpringBootTest
@TestPropertySource(properties = {
        "spring.datasource.url=jdbc:h2:mem:dashscore;DB_CLOSE_DELAY=-1",
        "spring.datasource.driver-class-name=org.h2.Driver",
        "spring.datasource.username=sa",
        "spring.datasource.password=",
        "spring.jpa.hibernate.ddl-auto=create-drop"
})
class DashboardScoreConsistencyTest {

    @Autowired
    private DashboardController controller;

    @Autowired
    private ScanRepository scanRepository;

    @Autowired
    private FindingRepository findingRepository;

    @Autowired
    private RiskScoringService riskScoringService;

    private Scan scan(ScanType type, int id, int minutesAgo) {
        Scan s = new Scan();
        s.setScanType(type);
        s.setStatus(ScanStatus.COMPLETED);
        s.setTargetUrl("https://example.test/" + id);
        s.setProfile("STANDARD");
        s.setStartedAt(LocalDateTime.now().minusMinutes(minutesAgo));
        s.setCompletedAt(LocalDateTime.now().minusMinutes(minutesAgo - 1));
        return scanRepository.save(s);
    }

    private Finding finding(Scan s, Severity sev, FindingStatus status, FindingCategory cat) {
        Finding f = new Finding();
        f.setTitle(sev + "/" + status);
        f.setSeverity(sev);
        f.setStatus(status);
        f.setCategory(cat);
        f.setSource("TEST");
        f.setDescription("test");
        f.setImpact("test");
        f.setEvidence("test");
        f.setRecommendation("test");
        s.addFinding(f);
        return f;
    }

    @Test
    @Transactional
    @DisplayName("score reflects all open findings, not just the newest scan")
    void scoreCoversEveryFinding() {
        // An old, badly affected scan.
        Scan old = scan(ScanType.DAST, 1, 60);
        finding(old, Severity.HIGH, FindingStatus.VERIFIED, FindingCategory.CORS);
        finding(old, Severity.HIGH, FindingStatus.VERIFIED, FindingCategory.CORS);
        finding(old, Severity.CRITICAL, FindingStatus.VERIFIED, FindingCategory.INJECTION);
        scanRepository.save(old);

        // A newer, near-clean scan of a single endpoint.
        Scan recent = scan(ScanType.DAST, 2, 5);
        finding(recent, Severity.INFO, FindingStatus.INFORMATIONAL, FindingCategory.CONFIGURATION);
        scanRepository.save(recent);

        // The newest scan alone would score very well.
        Scan alone = new Scan();
        riskScoringService.calculateAndApplyStats(alone, List.of(recent.getFindings().get(0)));
        assertTrue(alone.getSecurityScore() >= 99, "single informational finding should not dent the score");

        var summary = controller.getDashboardSummary();

        assertEquals(4, summary.getTotalFindings());
        assertEquals(1, summary.getCriticalCount());
        assertEquals(2, summary.getHighCount());
        assertEquals(3, summary.getVerifiedCount());

        // The dashboard must not report the clean newest scan's score while listing the rest.
        assertNotEquals(alone.getSecurityScore(), summary.getOverallSecurityScore(),
                "dashboard score must not come from a single scan when other findings exist");
        assertTrue(summary.getOverallSecurityScore() < 90,
                "confirmed high/critical issues should drag the dashboard score down, got "
                        + summary.getOverallSecurityScore());
    }

    @Test
    @Transactional
    @DisplayName("a clean workspace scores 100")
    void cleanWorkspaceScoresPerfect() {
        assertEquals(100, controller.getDashboardSummary().getOverallSecurityScore());
    }
}
