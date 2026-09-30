package com.sih.securityplatform.controller;

import com.sih.securityplatform.dto.DashboardSummaryDto;
import com.sih.securityplatform.model.Finding;
import com.sih.securityplatform.model.FindingStatus;
import com.sih.securityplatform.model.Scan;
import com.sih.securityplatform.model.ScanStatus;
import com.sih.securityplatform.model.Severity;
import com.sih.securityplatform.repository.FindingRepository;
import com.sih.securityplatform.repository.ScanRepository;
import com.sih.securityplatform.service.RiskScoringService;
import com.sih.securityplatform.service.ScanDurationService;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Aggregated view of every assessment on the platform.
 */
@RestController
@RequestMapping("/api/dashboard")
@CrossOrigin(origins = "*")
public class DashboardController {

    private final ScanRepository scanRepository;
    private final FindingRepository findingRepository;
    private final ScanDurationService durationService;
    private final RiskScoringService riskScoringService;

    public DashboardController(ScanRepository scanRepository, FindingRepository findingRepository,
                               ScanDurationService durationService, RiskScoringService riskScoringService) {
        this.scanRepository = scanRepository;
        this.findingRepository = findingRepository;
        this.durationService = durationService;
        this.riskScoringService = riskScoringService;
    }

    @GetMapping
    public DashboardSummaryDto getDashboardSummary() {
        DashboardSummaryDto summary = new DashboardSummaryDto();

        List<Scan> scans = scanRepository.findAllByOrderByStartedAtDesc();
        List<Scan> recent = scans.stream().limit(8).toList();
        summary.setTotalScans(scans.size());
        summary.setRecentScans(recent);

        // The target label comes from the newest completed assessment. It is only a label —
        // the score below is computed over the current open-issue set so that it always agrees
        // with the severity counters shown beside it.
        Optional<Scan> latestScored = scans.stream()
                .filter(s -> s.getStatus() == ScanStatus.COMPLETED && s.getSecurityScore() != null)
                .findFirst();
        summary.setTargetApp(latestScored.map(Scan::getTargetUrl).orElse("No completed assessment yet"));

        List<Finding> allFindings = findingRepository.findAll();
        summary.setTotalFindings(allFindings.size());

        // The headline score must describe the same set of findings as the counters below.
        // Taking it from the newest scan alone made the dashboard read "92/100 — strong"
        // while listing 21 high-severity issues from an older scan, which is misleading.
        // Recomputing over the current open-issue set keeps the two consistent.
        if (allFindings.isEmpty()) {
            summary.setOverallSecurityScore(100);
        } else {
            Scan scratch = new Scan();
            riskScoringService.calculateAndApplyStats(scratch, allFindings);
            summary.setOverallSecurityScore(scratch.getSecurityScore());
        }

        long crit = 0, high = 0, med = 0, low = 0, info = 0;
        long verified = 0, needsReview = 0, potential = 0, informational = 0;
        Map<String, Long> catDist = new LinkedHashMap<>();

        for (Finding f : allFindings) {
            if (f.getSeverity() == null) {
                info++;
            } else {
                switch (f.getSeverity()) {
                    case CRITICAL -> crit++;
                    case HIGH -> high++;
                    case MEDIUM -> med++;
                    case LOW -> low++;
                    // UNKNOWN is counted as informational so the buckets always sum to the total.
                    default -> info++;
                }
            }

            FindingStatus st = f.getStatus() == null ? FindingStatus.POTENTIAL : f.getStatus();
            switch (st) {
                case VERIFIED -> verified++;
                case NEEDS_REVIEW, EXTERNAL_INTELLIGENCE -> needsReview++;
                case POTENTIAL -> potential++;
                case INFORMATIONAL, FALSE_POSITIVE -> informational++;
            }

            String cat = f.getCategory() == null ? "OTHER" : f.getCategory().name();
            catDist.merge(cat, 1L, Long::sum);
        }

        summary.setCriticalCount(crit);
        summary.setHighCount(high);
        summary.setMediumCount(med);
        summary.setLowCount(low);
        summary.setInfoCount(info);

        summary.setVerifiedCount(verified);
        summary.setNeedsReviewCount(needsReview);
        summary.setPotentialCount(potential);
        summary.setInformationalCount(informational);
        summary.setCategoryDistribution(catDist);

        // Highest-impact, most-confirmed issues first — this is the developer's work queue.
        summary.setTopRiskFindings(
                allFindings.stream()
                        .filter(f -> f.getSeverity() == Severity.CRITICAL
                                || f.getSeverity() == Severity.HIGH
                                || f.getStatus() == FindingStatus.VERIFIED)
                        .sorted(Comparator
                                .comparingInt((Finding f) -> f.getSeverity() == null ? 9
                                        : severityRank(f.getSeverity()))
                                .thenComparingInt(f -> -(f.getCvssScore() == null ? 0 : f.getCvssScore().intValue())))
                        .limit(6)
                        .toList());

        return summary;
    }

    private int severityRank(Severity s) {
        return switch (s) {
            case CRITICAL -> 0;
            case HIGH -> 1;
            case MEDIUM -> 2;
            case LOW -> 3;
            case INFO -> 4;
            default -> 5;
        };
    }

    /** Wipes assessment history. Findings cascade from their scan. */
    @DeleteMapping("/data")
    public Map<String, Object> clearAllData() {
        findingRepository.deleteAll();
        scanRepository.deleteAll();
        return Map.of("status", "SUCCESS", "message", "All assessment history and findings cleared.");
    }

    /** Kept for backwards compatibility with the existing client. */
    @PostMapping("/reset")
    public Map<String, Object> resetAllData() {
        return clearAllData();
    }
}
