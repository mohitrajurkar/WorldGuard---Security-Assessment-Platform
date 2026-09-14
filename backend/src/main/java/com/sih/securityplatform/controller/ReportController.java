package com.sih.securityplatform.controller;

import com.sih.securityplatform.model.Report;
import com.sih.securityplatform.model.Scan;
import com.sih.securityplatform.repository.ReportRepository;
import com.sih.securityplatform.repository.ScanRepository;
import com.sih.securityplatform.service.ReportGeneratorService;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/reports")
@CrossOrigin(origins = "*")
public class ReportController {

    private final ReportRepository reportRepository;
    private final ScanRepository scanRepository;
    private final ReportGeneratorService reportGeneratorService;

    public ReportController(
            ReportRepository reportRepository,
            ScanRepository scanRepository,
            ReportGeneratorService reportGeneratorService) {
        this.reportRepository = reportRepository;
        this.scanRepository = scanRepository;
        this.reportGeneratorService = reportGeneratorService;
    }

    @GetMapping
    public List<Report> listReports() {
        return reportRepository.findAllByOrderByGeneratedAtDesc();
    }

    @PostMapping("/generate/{scanId}")
    public ResponseEntity<byte[]> generateReport(@PathVariable Long scanId) {
        return scanRepository.findById(scanId).map(scan -> {
            try {
                byte[] pdfData = reportGeneratorService.generatePdfReport(scan);
                return ResponseEntity.ok()
                        .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"World_Monitor_Security_Report_Scan_" + scanId + ".pdf\"")
                        .contentType(MediaType.APPLICATION_PDF)
                        .body(pdfData);
            } catch (Exception e) {
                return ResponseEntity.internalServerError().<byte[]>build();
            }
        }).orElse(ResponseEntity.notFound().build());
    }

    @GetMapping("/scan/{scanId}/download")
    public ResponseEntity<byte[]> downloadReport(@PathVariable Long scanId) {
        return generateReport(scanId);
    }
}
