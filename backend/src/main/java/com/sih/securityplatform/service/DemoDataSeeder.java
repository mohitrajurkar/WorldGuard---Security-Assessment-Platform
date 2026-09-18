package com.sih.securityplatform.service;

import com.sih.securityplatform.model.*;
import com.sih.securityplatform.repository.ScanRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;

@Component
public class DemoDataSeeder implements CommandLineRunner {

    private static final Logger log = LoggerFactory.getLogger(DemoDataSeeder.class);

    private final ScanRepository scanRepository;
    private final RiskScoringService riskScoringService;

    public DemoDataSeeder(ScanRepository scanRepository, RiskScoringService riskScoringService) {
        this.scanRepository = scanRepository;
        this.riskScoringService = riskScoringService;
    }

    @Override
    public void run(String... args) {
        // DO NOT automatically seed fake findings in production/standard run.
        // The dashboard must only reflect authentic scan results.
        log.info("WorldGuard initialized in authentic assessment mode. No mock findings auto-seeded.");
    }

    public Scan seedDemoData() {
        Scan seedScan = new Scan();
        seedScan.setScanType(ScanType.COMPLETE);
        seedScan.setStatus(ScanStatus.COMPLETED);
        seedScan.setTargetUrl("http://localhost:3000 (Demo Baseline)");
        seedScan.setSourcePath("demo/worldmonitor");
        seedScan.setStartedAt(LocalDateTime.now().minusHours(1));
        seedScan.setCompletedAt(LocalDateTime.now().minusHours(1).plusMinutes(3));
        seedScan.setProgressPercent(100);
        seedScan.setCurrentStep("DEMO MODE — Sample Baseline");
        seedScan.setDemo(true);

        Finding f1 = new Finding();
        f1.setTitle("DEMO: Hardcoded Secret Reference Pattern");
        f1.setSeverity(Severity.HIGH);
        f1.setCategory(FindingCategory.AUTHENTICATION);
        f1.setSource("Semgrep");
        f1.setStatus(FindingStatus.POTENTIAL);
        f1.setFilePath("api/relay.ts");
        f1.setLineNumber(28);
        f1.setWhatIsTheIssue("DEMO DATA — NOT A VERIFIED VULNERABILITY: Reference fallback token in source code.");
        f1.setWhyDoesItMatter("Hardcoded credentials should be replaced with runtime environment variables.");
        f1.setDescription("DEMO DATA — NOT A VERIFIED VULNERABILITY: Sample finding for UI layout testing.");
        f1.setImpact("Illustrative demonstration finding.");
        f1.setEvidence("const secret = process.env.RELAY_SECRET || 'dev_secret_demo';");
        f1.setRecommendation("Store secrets strictly in secure cloud environment variables.");
        f1.setCwe("CWE-798: Use of Hard-coded Credentials");
        f1.setCvssScore(7.5);
        f1.setRemediationTimeMinutes(45);
        seedScan.addFinding(f1);

        Finding f2 = new Finding();
        f2.setTitle("DEMO: Missing Defensive Header");
        f2.setSeverity(Severity.MEDIUM);
        f2.setCategory(FindingCategory.SECURITY_HEADERS);
        f2.setSource("API Scanner");
        f2.setStatus(FindingStatus.POTENTIAL);
        f2.setEndpoint("http://localhost:3000");
        f2.setWhatIsTheIssue("DEMO DATA — NOT A VERIFIED VULNERABILITY: Content-Security-Policy header demonstration.");
        f2.setWhyDoesItMatter("Missing headers increase exposure to cross-site scripting.");
        f2.setDescription("DEMO DATA — NOT A VERIFIED VULNERABILITY: Sample header finding.");
        f2.setEvidence("GET / -> CSP header absent");
        f2.setRecommendation("Add Content-Security-Policy header.");
        f2.setCwe("CWE-693: Protection Mechanism Failure");
        f2.setCvssScore(5.4);
        f2.setRemediationTimeMinutes(30);
        seedScan.addFinding(f2);

        riskScoringService.calculateAndApplyStats(seedScan, seedScan.getFindings());
        return scanRepository.save(seedScan);
    }
}
