package com.sih.securityplatform.service;

import com.sih.securityplatform.dto.ScanProgressDto;
import com.sih.securityplatform.dto.ScanRequest;
import com.sih.securityplatform.model.*;
import com.sih.securityplatform.repository.FindingRepository;
import com.sih.securityplatform.repository.ScanRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.*;

@Service
public class ScanOrchestratorService {

    private static final Logger log = LoggerFactory.getLogger(ScanOrchestratorService.class);

    private final ScanRepository scanRepository;
    private final FindingRepository findingRepository;
    private final SemgrepService semgrepService;
    private final ZapService zapService;
    private final ApiScannerService apiScannerService;
    private final LeakIXService leakIXService;
    private final FindingNormalizer findingNormalizer;
    private final FindingDeduplicator findingDeduplicator;
    private final RiskScoringService riskScoringService;

    private final Map<Long, List<SseEmitter>> emitters = new ConcurrentHashMap<>();
    private final ExecutorService executorService = Executors.newFixedThreadPool(4);

    public ScanOrchestratorService(
            ScanRepository scanRepository,
            FindingRepository findingRepository,
            SemgrepService semgrepService,
            ZapService zapService,
            ApiScannerService apiScannerService,
            LeakIXService leakIXService,
            FindingNormalizer findingNormalizer,
            FindingDeduplicator findingDeduplicator,
            RiskScoringService riskScoringService) {
        this.scanRepository = scanRepository;
        this.findingRepository = findingRepository;
        this.semgrepService = semgrepService;
        this.zapService = zapService;
        this.apiScannerService = apiScannerService;
        this.leakIXService = leakIXService;
        this.findingNormalizer = findingNormalizer;
        this.findingDeduplicator = findingDeduplicator;
        this.riskScoringService = riskScoringService;
    }

    public Scan initiateScan(ScanRequest request) {
        Scan scan = new Scan();
        scan.setScanType(request.getScanType() != null ? request.getScanType() : ScanType.COMPLETE);
        scan.setStatus(ScanStatus.RUNNING);

        String target = request.getTargetUrl() != null && !request.getTargetUrl().isBlank()
                ? request.getTargetUrl()
                : "http://localhost:3000";
        scan.setTargetUrl(target);
        scan.setSourcePath(request.getSourcePath());
        scan.setStartedAt(LocalDateTime.now());
        scan.setProgressPercent(5);
        scan.setCurrentStep("Target Validation");
        scan.setDemo(request.isDemo());

        Scan saved = scanRepository.save(scan);
        log.info("Scan started [ID: {}] for target {}", saved.getId(), target);

        executorService.submit(() -> executeScanAsync(saved.getId(), request));
        return saved;
    }

    public SseEmitter subscribeToScan(Long scanId) {
        SseEmitter emitter = new SseEmitter(180_000L);
        emitters.computeIfAbsent(scanId, k -> new CopyOnWriteArrayList<>()).add(emitter);

        emitter.onCompletion(() -> removeEmitter(scanId, emitter));
        emitter.onTimeout(() -> removeEmitter(scanId, emitter));
        emitter.onError(e -> removeEmitter(scanId, emitter));

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

        List<Finding> collectedFindings = new ArrayList<>();

        try {
            // 1. Target Validation
            log.info("Target validated: {}", scan.getTargetUrl());
            updateScanStep(scan, 10, "Target Validation");
            Thread.sleep(400);

            // 2. Source Analysis (Semgrep)
            boolean shouldRunSemgrep = request.isEnableSemgrep() &&
                    (scan.getScanType() == ScanType.COMPLETE || scan.getScanType() == ScanType.SAST);

            if (shouldRunSemgrep) {
                log.info("Semgrep started");
                updateScanStep(scan, 25, "Source Analysis (Semgrep)");

                String sourcePath = scan.getSourcePath();
                if (sourcePath != null && !sourcePath.isBlank()) {
                    List<Finding> sast = semgrepService.scanSource(sourcePath);
                    collectedFindings.addAll(sast);
                } else {
                    log.info("No source directory specified; skipping static code scan.");
                }
                log.info("Semgrep completed");
                Thread.sleep(500);
            }

            // 3. API Security Testing
            boolean shouldRunApi = request.isEnableApiSecurity() &&
                    (scan.getScanType() == ScanType.COMPLETE || scan.getScanType() == ScanType.API_SECURITY);

            if (shouldRunApi) {
                log.info("API scan started");
                updateScanStep(scan, 45, "API Security Testing");

                List<Finding> apiFindings = apiScannerService.scanTarget(scan.getTargetUrl());
                collectedFindings.addAll(apiFindings);
                log.info("API scan completed");
                Thread.sleep(400);
            }

            // 4. Dynamic Web Testing (ZAP)
            boolean shouldRunZap = request.isEnableZap() &&
                    (scan.getScanType() == ScanType.COMPLETE || scan.getScanType() == ScanType.DAST);

            if (shouldRunZap) {
                log.info("ZAP started");
                updateScanStep(scan, 65, "Dynamic Web Testing (ZAP)");

                if (zapService.isAvailable()) {
                    List<Finding> zapFindings = zapService.scanTarget(scan.getTargetUrl());
                    collectedFindings.addAll(zapFindings);
                } else {
                    log.info("ZAP unavailable — dynamic scan could not be completed.");
                }
                log.info("ZAP completed");
                Thread.sleep(400);
            }

            // 5. External Intelligence (LeakIX)
            boolean shouldRunLeakIX = request.isEnableLeakix();
            if (shouldRunLeakIX) {
                log.info("LeakIX lookup started");
                updateScanStep(scan, 80, "External Intelligence (LeakIX)");

                String domainToQuery = request.getAuthorizedDomain() != null && !request.getAuthorizedDomain().isBlank()
                        ? request.getAuthorizedDomain()
                        : extractDomain(scan.getTargetUrl());

                if (leakIXService.isConfigured()) {
                    List<Finding> leakFindings = leakIXService.queryIntelligence(domainToQuery);
                    collectedFindings.addAll(leakFindings);
                } else {
                    log.info("External intelligence unavailable.");
                }
                log.info("LeakIX completed");
                Thread.sleep(400);
            }

            // 6. Finding Analysis, Normalization & Deduplication
            log.info("Findings normalized");
            findingNormalizer.normalize(collectedFindings);
            List<Finding> deduplicated = findingDeduplicator.deduplicateAndCorrelate(collectedFindings);

            // 7. Risk Calculation
            log.info("Risk calculated");
            riskScoringService.calculateAndApplyStats(scan, deduplicated);

            // 8. Assign findings and complete
            log.info("Report generated");
            scan.setProgressPercent(100);
            scan.setCurrentStep("Assessment Completed Successfully");
            scan.setStatus(ScanStatus.COMPLETED);
            scan.setCompletedAt(LocalDateTime.now());

            scan.getFindings().clear();
            for (Finding f : deduplicated) {
                scan.addFinding(f);
            }

            scanRepository.save(scan);
            broadcastProgress(scan.getId(), 100, "Assessment Completed Successfully",
                    deduplicated.size(), scan.getSecurityScore(), ScanStatus.COMPLETED);

        } catch (Exception e) {
            log.error("Assessment failed: {}", e.getMessage(), e);
            scan.setStatus(ScanStatus.FAILED);
            scan.setCurrentStep("Assessment Error: " + e.getMessage());
            scanRepository.save(scan);
            broadcastProgress(scan.getId(), scan.getProgressPercent(), "Error: " + e.getMessage(),
                    collectedFindings.size(), scan.getSecurityScore(), ScanStatus.FAILED);
        }
    }

    private String extractDomain(String url) {
        try {
            java.net.URI uri = java.net.URI.create(url);
            String host = uri.getHost();
            return host != null ? host : url;
        } catch (Exception e) {
            return url;
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
