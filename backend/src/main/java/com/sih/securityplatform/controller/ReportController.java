package com.sih.securityplatform.controller;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import com.sih.securityplatform.model.Scan;
import com.sih.securityplatform.model.ScanStatus;
import com.sih.securityplatform.repository.ScanRepository;
import com.sih.securityplatform.service.ReportGeneratorService;
import com.sih.securityplatform.service.ScanDurationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Serves the generated PDF report for a scan.
 */
@RestController
@RequestMapping("/api/reports")
@CrossOrigin(origins = "*")
public class ReportController {

    private static final Logger log = LoggerFactory.getLogger(ReportController.class);

    private final ScanRepository scanRepository;
    private final ReportGeneratorService reportGeneratorService;
    private final ScanDurationService durationService;

    public ReportController(ScanRepository scanRepository,
                            ReportGeneratorService reportGeneratorService,
                            ScanDurationService durationService) {
        this.scanRepository = scanRepository;
        this.reportGeneratorService = reportGeneratorService;
        this.durationService = durationService;
    }

    /** Scans that have a report available to download. */
    @GetMapping("/available")
    public List<Map<String, Object>> listAvailableReports() {
        return scanRepository.findAllByOrderByStartedAtDesc().stream()
                .filter(s -> s.getStatus() == ScanStatus.COMPLETED)
                .map(s -> {
                    Map<String, Object> m = new LinkedHashMap<>();
                    m.put("scanId", s.getId());
                    m.put("scanType", s.getScanType());
                    m.put("targetUrl", s.getTargetUrl());
                    m.put("profile", s.getProfile());
                    m.put("securityScore", s.getSecurityScore());
                    m.put("verifiedCount", s.getVerifiedCount());
                    m.put("criticalCount", s.getCriticalCount());
                    m.put("highCount", s.getHighCount());
                    m.put("completedAt", s.getCompletedAt());
                    m.put("downloadUrl", "/api/reports/scan/" + s.getId() + "/download");
                    return m;
                })
                .toList();
    }

    /** Real measured/estimated durations, so the UI never advertises a fictional time. */
    @GetMapping("/estimates")
    public Map<String, Object> estimates() {
        return durationService.allEstimates();
    }

    @GetMapping("/scan/{scanId}/download")
    public ResponseEntity<byte[]> downloadReport(@PathVariable Long scanId) {
        Scan scan = scanRepository.findById(scanId).orElse(null);
        if (scan == null) {
            return ResponseEntity.notFound().build();
        }
        if (scan.getStatus() != ScanStatus.COMPLETED) {
            return ResponseEntity.badRequest().build();
        }
        try {
            byte[] pdf = reportGeneratorService.generatePdfReport(scan);
            return ResponseEntity.ok()
                    .header(HttpHeaders.CONTENT_DISPOSITION,
                            "attachment; filename=\"WorldGuard_Report_Scan_" + scanId + ".pdf\"")
                    .contentType(MediaType.APPLICATION_PDF)
                    .body(pdf);
        } catch (Exception e) {
            log.error("Report generation failed for scan {}", scanId, e);
            return ResponseEntity.internalServerError().build();
        }
    }
}
