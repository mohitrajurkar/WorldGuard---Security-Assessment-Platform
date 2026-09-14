package com.sih.securityplatform.service;

import com.sih.securityplatform.dto.ScanProgressDto;
import com.sih.securityplatform.dto.ScanRequest;
import com.sih.securityplatform.model.*;
import com.sih.securityplatform.repository.FindingRepository;
import com.sih.securityplatform.repository.ScanRepository;
import org.springframework.stereotype.Service;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.*;

@Service
public class ScanOrchestratorService {

    private final ScanRepository scanRepository;
    private final FindingRepository findingRepository;
    private final StaticAnalysisService staticAnalysisService;
    private final DastScannerService dastScannerService;
    private final ApiScannerService apiScannerService;
    private final VulnerabilityEngine vulnerabilityEngine;

    private final Map<Long, List<SseEmitter>> emitters = new ConcurrentHashMap<>();
    private final ExecutorService executorService = Executors.newFixedThreadPool(4);

    public ScanOrchestratorService(
            ScanRepository scanRepository,
            FindingRepository findingRepository,
            StaticAnalysisService staticAnalysisService,
            DastScannerService dastScannerService,
            ApiScannerService apiScannerService,
            VulnerabilityEngine vulnerabilityEngine) {
        this.scanRepository = scanRepository;
        this.findingRepository = findingRepository;
        this.staticAnalysisService = staticAnalysisService;
        this.dastScannerService = dastScannerService;
        this.apiScannerService = apiScannerService;
        this.vulnerabilityEngine = vulnerabilityEngine;
    }

    public Scan initiateScan(ScanRequest request) {
        Scan scan = new Scan();
        scan.setScanType(request.getScanType() != null ? request.getScanType() : ScanType.COMPLETE);
        scan.setStatus(ScanStatus.RUNNING);
        scan.setTargetUrl(request.getTargetUrl() != null && !request.getTargetUrl().isBlank() ? request.getTargetUrl() : "https://worldmonitor.app");
        scan.setSourcePath(request.getSourcePath());
        scan.setStartedAt(LocalDateTime.now());
        scan.setProgressPercent(5);
        scan.setCurrentStep("Initializing assessment orchestrator...");
        scan.setDemo(request.isDemo());

        Scan saved = scanRepository.save(scan);

        // Execute asynchronously
        executorService.submit(() -> executeScanAsync(saved.getId(), request));

        return saved;
    }

    public SseEmitter subscribeToScan(Long scanId) {
        SseEmitter emitter = new SseEmitter(180_000L); // 3 minutes timeout
        emitters.computeIfAbsent(scanId, k -> new CopyOnWriteArrayList<>()).add(emitter);

        emitter.onCompletion(() -> removeEmitter(scanId, emitter));
        emitter.onTimeout(() -> removeEmitter(scanId, emitter));
        emitter.onError(e -> removeEmitter(scanId, emitter));

        // Send immediate current state
        scanRepository.findById(scanId).ifPresent(scan -> {
            try {
                emitter.send(SseEmitter.event()
                        .name("progress")
                        .data(new ScanProgressDto(
                                scan.getId(),
                                scan.getStatus(),
                                scan.getProgressPercent(),
                                scan.getCurrentStep(),
                                scan.getFindings().size(),
                                scan.getSecurityScore())));
            } catch (IOException ignored) {}
        });

        return emitter;
    }

    private void removeEmitter(Long scanId, SseEmitter emitter) {
        List<SseEmitter> list = emitters.get(scanId);
        if (list != null) {
            list.remove(emitter);
        }
    }

    private void broadcastProgress(Long scanId, int percent, String step, int findingsCount, Integer score, ScanStatus status) {
        ScanProgressDto dto = new ScanProgressDto(scanId, status, percent, step, findingsCount, score);
        List<SseEmitter> list = emitters.get(scanId);
        if (list != null) {
            for (SseEmitter emitter : list) {
                try {
                    emitter.send(SseEmitter.event().name("progress").data(dto));
                } catch (Exception e) {
                    emitter.complete();
                }
            }
        }
    }

    private void executeScanAsync(Long scanId, ScanRequest request) {
        Optional<Scan> opt = scanRepository.findById(scanId);
        if (opt.isEmpty()) return;
        Scan scan = opt.get();

        List<Finding> allFindings = new ArrayList<>();

        try {
            // Step 1: Pre-flight & Handshake
            updateScanStep(scan, 15, "Connecting to target & inspecting architecture...");
            Thread.sleep(800);

            // Step 2: SAST Static Analysis
            if (scan.getScanType() == ScanType.COMPLETE || scan.getScanType() == ScanType.SAST) {
                updateScanStep(scan, 35, "Running Static Code Analysis (Semgrep & AST rules)...");
                List<Finding> sastFindings = staticAnalysisService.scanRepository(scan.getSourcePath());
                for (Finding f : sastFindings) {
                    scan.addFinding(f);
                }
                allFindings.addAll(sastFindings);
                Thread.sleep(1000);
            }

            // Step 3: DAST Dynamic Web Scan
            if (scan.getScanType() == ScanType.COMPLETE || scan.getScanType() == ScanType.DAST) {
                updateScanStep(scan, 60, "Running Dynamic Web Security Testing (DAST & Crawling)...");
                List<Finding> dastFindings = dastScannerService.scanTarget(scan.getTargetUrl());
                for (Finding f : dastFindings) {
                    scan.addFinding(f);
                }
                allFindings.addAll(dastFindings);
                Thread.sleep(1000);
            }

            // Step 4: API Security Scanner
            if (scan.getScanType() == ScanType.COMPLETE || scan.getScanType() == ScanType.API_SECURITY) {
                updateScanStep(scan, 80, "Probing World Monitor API Gateway & Headers...");
                List<Finding> apiFindings = apiScannerService.scanTarget(scan.getTargetUrl());
                for (Finding f : apiFindings) {
                    scan.addFinding(f);
                }
                allFindings.addAll(apiFindings);
                Thread.sleep(800);
            }

            // Step 5: Vulnerability Correlation & Risk Scoring
            updateScanStep(scan, 95, "Correlating findings, scoring CVSS & calculating risk index...");
            vulnerabilityEngine.recalculateScanStats(scan, allFindings);
            scan.setStatus(ScanStatus.COMPLETED);
            scan.setCompletedAt(LocalDateTime.now());
            scan.setProgressPercent(100);
            scan.setCurrentStep("Assessment Completed Successfully");

            scanRepository.save(scan);
            broadcastProgress(scan.getId(), 100, "Assessment Completed Successfully",
                    allFindings.size(), scan.getSecurityScore(), ScanStatus.COMPLETED);

        } catch (Exception e) {
            scan.setStatus(ScanStatus.FAILED);
            scan.setCurrentStep("Assessment Error: " + e.getMessage());
            scanRepository.save(scan);
            broadcastProgress(scan.getId(), scan.getProgressPercent(), "Error: " + e.getMessage(),
                    allFindings.size(), scan.getSecurityScore(), ScanStatus.FAILED);
        }
    }

    private void updateScanStep(Scan scan, int percent, String step) {
        scan.setProgressPercent(percent);
        scan.setCurrentStep(step);
        scanRepository.save(scan);
        int fCount = scan.getFindings() != null ? scan.getFindings().size() : 0;
        broadcastProgress(scan.getId(), percent, step, fCount, scan.getSecurityScore(), scan.getStatus());
    }
}
