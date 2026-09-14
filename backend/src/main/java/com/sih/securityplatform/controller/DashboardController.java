package com.sih.securityplatform.controller;

import com.sih.securityplatform.dto.DashboardSummaryDto;
import com.sih.securityplatform.model.Finding;
import com.sih.securityplatform.model.FindingCategory;
import com.sih.securityplatform.model.Scan;
import com.sih.securityplatform.model.Severity;
import com.sih.securityplatform.repository.FindingRepository;
import com.sih.securityplatform.repository.ScanRepository;
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

    public DashboardController(ScanRepository scanRepository, FindingRepository findingRepository) {
        this.scanRepository = scanRepository;
        this.findingRepository = findingRepository;
    }

    @GetMapping
    public DashboardSummaryDto getDashboardSummary() {
        DashboardSummaryDto summary = new DashboardSummaryDto();

        List<Scan> scans = scanRepository.findAllByOrderByStartedAtDesc();
        summary.setTotalScans(scans.size());
        summary.setRecentScans(scans.stream().limit(5).toList());

        if (!scans.isEmpty()) {
            summary.setOverallSecurityScore(scans.get(0).getSecurityScore());
        } else {
            summary.setOverallSecurityScore(100);
        }

        List<Finding> allFindings = findingRepository.findAll();
        summary.setTotalFindings(allFindings.size());

        long crit = 0, high = 0, med = 0, low = 0, info = 0;
        Map<String, Long> catDist = new HashMap<>();

        for (Finding f : allFindings) {
            if (f.getSeverity() == Severity.CRITICAL) crit++;
            else if (f.getSeverity() == Severity.HIGH) high++;
            else if (f.getSeverity() == Severity.MEDIUM) med++;
            else if (f.getSeverity() == Severity.LOW) low++;
            else if (f.getSeverity() == Severity.INFO) info++;

            String catName = f.getCategory() != null ? f.getCategory().name() : "OTHER";
            catDist.put(catName, catDist.getOrDefault(catName, 0L) + 1);
        }

        summary.setCriticalCount(crit);
        summary.setHighCount(high);
        summary.setMediumCount(med);
        summary.setLowCount(low);
        summary.setInfoCount(info);
        summary.setCategoryDistribution(catDist);

        summary.setTopRiskFindings(
                allFindings.stream()
                        .filter(f -> f.getSeverity() == Severity.CRITICAL || f.getSeverity() == Severity.HIGH)
                        .limit(6)
                        .toList()
        );

        return summary;
    }
}
