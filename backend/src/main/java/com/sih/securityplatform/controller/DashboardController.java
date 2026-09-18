package com.sih.securityplatform.controller;

import com.sih.securityplatform.dto.DashboardSummaryDto;
import com.sih.securityplatform.model.*;
import com.sih.securityplatform.repository.FindingRepository;
import com.sih.securityplatform.repository.ScanRepository;
import com.sih.securityplatform.service.DemoDataSeeder;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/dashboard")
@CrossOrigin(origins = "*")
public class DashboardController {

    private final ScanRepository scanRepository;
    private final FindingRepository findingRepository;
    private final DemoDataSeeder demoDataSeeder;

    public DashboardController(ScanRepository scanRepository, FindingRepository findingRepository, DemoDataSeeder demoDataSeeder) {
        this.scanRepository = scanRepository;
        this.findingRepository = findingRepository;
        this.demoDataSeeder = demoDataSeeder;
    }

    @GetMapping
    public DashboardSummaryDto getDashboardSummary() {
        DashboardSummaryDto summary = new DashboardSummaryDto();

        List<Scan> scans = scanRepository.findAllByOrderByStartedAtDesc();
        summary.setTotalScans(scans.size());
        summary.setRecentScans(scans.stream().limit(5).toList());

        if (!scans.isEmpty()) {
            summary.setOverallSecurityScore(scans.get(0).getSecurityScore());
            summary.setTargetApp(scans.get(0).getTargetUrl());
        } else {
            summary.setOverallSecurityScore(100);
            summary.setTargetApp("World Monitor — Local (http://localhost:3000)");
        }

        List<Finding> allFindings = findingRepository.findAll();
        summary.setTotalFindings(allFindings.size());

        long crit = 0, high = 0, med = 0, low = 0, info = 0;
        long verified = 0, needsReview = 0, potential = 0, informational = 0;
        Map<String, Long> catDist = new HashMap<>();

        for (Finding f : allFindings) {
            if (f.getSeverity() == Severity.CRITICAL) crit++;
            else if (f.getSeverity() == Severity.HIGH) high++;
            else if (f.getSeverity() == Severity.MEDIUM) med++;
            else if (f.getSeverity() == Severity.LOW) low++;
            else if (f.getSeverity() == Severity.INFO) info++;

            FindingStatus st = f.getStatus() != null ? f.getStatus() : FindingStatus.POTENTIAL;
            switch (st) {
                case VERIFIED -> verified++;
                case NEEDS_REVIEW, EXTERNAL_INTELLIGENCE -> needsReview++;
                case POTENTIAL -> potential++;
                case INFORMATIONAL, FALSE_POSITIVE -> informational++;
            }

            String catName = f.getCategory() != null ? f.getCategory().name() : "OTHER";
            catDist.put(catName, catDist.getOrDefault(catName, 0L) + 1);
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

        summary.setTopRiskFindings(
                allFindings.stream()
                        .filter(f -> f.getSeverity() == Severity.CRITICAL || f.getSeverity() == Severity.HIGH || f.getStatus() == FindingStatus.VERIFIED)
                        .limit(6)
                        .toList()
        );

        return summary;
    }

    @PostMapping("/reset")
    public Map<String, Object> resetAllData() {
        findingRepository.deleteAll();
        scanRepository.deleteAll();
        Map<String, Object> res = new HashMap<>();
        res.put("status", "SUCCESS");
        res.put("message", "All scan assessment history and findings cleared.");
        return res;
    }

    @PostMapping("/seed-demo")
    public Map<String, Object> seedDemoData() {
        Scan s = demoDataSeeder.seedDemoData();
        Map<String, Object> res = new HashMap<>();
        res.put("status", "SUCCESS");
        res.put("message", "Demo baseline scan initialized.");
        res.put("scanId", s.getId());
        return res;
    }
}
