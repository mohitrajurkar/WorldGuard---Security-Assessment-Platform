package com.sih.securityplatform.service;

import com.sih.securityplatform.dto.ScanRequest;
import com.sih.securityplatform.model.Finding;
import com.sih.securityplatform.model.Scan;
import com.sih.securityplatform.model.ScanStatus;
import com.sih.securityplatform.model.ScanType;
import com.sih.securityplatform.repository.FindingRepository;
import com.sih.securityplatform.repository.ScanRepository;
import com.sih.securityplatform.service.pentest.PentestSuiteService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.io.IOException;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Runs an assessment to completion.
 *
 * <p>Every scan type is a composition of the same three phases — static analysis, dynamic
 * probing and an API probe — so a COMPLETE scan and a single-phase scan share one code path.
 *
 * <p>Two guarantees this class is responsible for:
 * <ul>
 *   <li><b>Nothing is left half-done.</b> Every scan reaches COMPLETED or FAILED. Phase failures
 *       are captured and reported, and if a phase overruns its budget the scan is still
 *       finalised with whatever was collected rather than being abandoned mid-flight.</li>
 *   <li><b>Progress is persisted and streamed.</b> The UI can always show real state, including
 *       after a reconnect, because state lives in the database rather than in memory.</li>
 * </ul>
 */
@Service
public class ScanOrchestratorService {

    private static final Logger log = LoggerFactory.getLogger(ScanOrchestratorService.class);

    private static final String DEFAULT_TARGET = "https://worldmonitor.app";

    private final ScanRepository scanRepository;
    private final FindingRepository findingRepository;
    private final PentestSuiteService pentestSuiteService;
    private final StaticAnalysisService staticAnalysisService;
    private final ApiScannerService apiScannerService;
    private final FindingNormalizer findingNormalizer;
    private final FindingDeduplicator findingDeduplicator;
    private final CorrelationEngine correlationEngine;
    private final VerificationEngine verificationEngine;
    private final RiskScoringService riskScoringService;
    private final ScanDurationService durationService;
    private final ReportGeneratorService reportGeneratorService;
    private final String defaultTarget;

    private final Map<Long, List<SseEmitter>> emitters = new ConcurrentHashMap<>();
    private final ExecutorService executorService = Executors.newFixedThreadPool(4);

    public ScanOrchestratorService(
            ScanRepository scanRepository,
            FindingRepository findingRepository,
            PentestSuiteService pentestSuiteService,
            StaticAnalysisService staticAnalysisService,
            ApiScannerService apiScannerService,
            FindingNormalizer findingNormalizer,
            FindingDeduplicator findingDeduplicator,
            CorrelationEngine correlationEngine,
            VerificationEngine verificationEngine,
            RiskScoringService riskScoringService,
            ScanDurationService durationService,
            ReportGeneratorService reportGeneratorService,
            @Value("${security.platform.default-target:" + DEFAULT_TARGET + "}") String defaultTarget) {
        this.scanRepository = scanRepository;
        this.findingRepository = findingRepository;
        this.pentestSuiteService = pentestSuiteService;
        this.staticAnalysisService = staticAnalysisService;
        this.apiScannerService = apiScannerService;
        this.findingNormalizer = findingNormalizer;
        this.findingDeduplicator = findingDeduplicator;
        this.correlationEngine = correlationEngine;
        this.verificationEngine = verificationEngine;
        this.riskScoringService = riskScoringService;
        this.durationService = durationService;
        this.reportGeneratorService = reportGeneratorService;
        this.defaultTarget = defaultTarget;
    }

    // ── Entry point ────────────────────────────────────────────────────────────

    /**
     * Validates the request, creates the scan record and starts execution.
     *
     * @throws SecurityException        if the target or authorization is rejected
     * @throws IllegalArgumentException if the request is malformed
     */
    public Scan initiateScan(ScanRequest request) {
        ScanType type = request.getScanType() != null ? request.getScanType() : ScanType.DAST;
        String profile = normalizeProfile(request.getScanProfile());
        String target = resolveTarget(request.getTargetUrl(), type);

        // Authorization + SSRF policy is checked before anything is persisted or dispatched.
        if (type.includesDynamic() || type.includesApiProbe()) {
            pentestSuiteService.validateTarget(target, request.isAuthorizedConfirmation());
        }

        Scan scan = new Scan();
        scan.setScanType(type);
        scan.setStatus(ScanStatus.RUNNING);
        scan.setTargetUrl(target);
        scan.setProfile(profile);
        scan.setAuthorizedAssessment(request.isAuthorizedConfirmation());
        scan.setSourcePath(type.includesStatic() ? StaticAnalysisService.GITHUB_REPO : null);
        scan.setExternalScanner(describeEngines(type));
        scan.setStartedAt(LocalDateTime.now());
        scan.setProgressPercent(1);
        scan.setCurrentStep("Queued — estimated " + durationService.estimateLabel(type, profile));
        scan.setDemo(request.isDemo());

        Scan saved = scanRepository.save(scan);
        log.info("Queued {} scan [ID: {}] for {} (profile {}, estimated {})",
                type, saved.getId(), target, profile, durationService.estimateLabel(type, profile));

        final String finalTarget = target;
        executorService.submit(() -> execute(saved.getId(), type, profile, finalTarget));

        return saved;
    }

    // ── Execution ──────────────────────────────────────────────────────────────

    private void execute(Long scanId, ScanType type, String profile, String target) {
        long deadlineSeconds = durationService.deadlineSeconds(type, profile);
        long start = System.currentTimeMillis();
        long hardDeadlineNanos = System.nanoTime() + deadlineSeconds * 1_000_000_000L;

        List<Finding> collected = new ArrayList<>();
        List<String> phaseErrors = new ArrayList<>();
        List<String> completedPhases = new ArrayList<>();

        try {
            // The total budget is split between phases so one slow phase cannot starve the
            // others. A single-phase scan gets the whole budget.
            long staticBudget = (long) (deadlineSeconds * shareFor(type, true));
            long apiBudget = (long) (deadlineSeconds * shareFor(type, false));
            long dynamicBudget = (long) (deadlineSeconds * shareFor(type, null));

            if (type.includesStatic()) {
                collected.addAll(runStaticPhase(scanId, profile, staticBudget, hardDeadlineNanos,
                        completedPhases, phaseErrors));
            }
            // Skip any remaining phase if the scan has already used its whole budget. The scan
            // still finalises, so it is never left running.
            if (type.includesApiProbe() && withinBudget(hardDeadlineNanos)) {
                collected.addAll(runApiPhase(scanId, target, apiBudget, collected.size(),
                        completedPhases, phaseErrors));
            } else if (type.includesApiProbe()) {
                phaseErrors.add("API probe skipped — the scan had already used its time budget");
            }
            if (type.includesDynamic() && withinBudget(hardDeadlineNanos)) {
                collected.addAll(runDynamicPhase(scanId, target, profile, dynamicBudget, collected.size(),
                        completedPhases, phaseErrors));
            } else if (type.includesDynamic()) {
                phaseErrors.add("Dynamic testing skipped — the scan had already used its time budget");
            }

            finalizeScan(scanId, collected, completedPhases, phaseErrors, start, type, profile, false);
        } catch (Exception e) {
            // A failure here is unexpected but must still produce a terminal scan record.
            log.error("Unexpected failure running scan {}", scanId, e);
            phaseErrors.add("Unexpected error: " + e.getMessage());
            finalizeScan(scanId, collected, completedPhases, phaseErrors, start, type, profile, true);
        }
    }

    private boolean withinBudget(long deadlineNanos) {
        return System.nanoTime() < deadlineNanos;
    }

    /**
     * Fraction of the total budget for one phase.
     *
     * @param phase true = static, false = API probe, null = dynamic
     */
    private double shareFor(ScanType type, Boolean phase) {
        boolean multi = type == ScanType.COMPLETE;
        if (!multi) {
            return 1.0;
        }
        if (phase != null && phase) {
            return 0.45;   // static dominates COMPLETE — the repo clone plus Semgrep
        }
        if (phase != null) {
            return 0.10;   // a single endpoint probe is quick
        }
        return 0.45;       // dynamic
    }

    private List<Finding> runStaticPhase(Long scanId, String profile, long deadlineSeconds,
                                        long hardDeadlineNanos, List<String> completedPhases,
                                        List<String> phaseErrors) {
        ScanProgressListener listener = listener(scanId, "Static", 4, 58);
        try {
            List<Finding> findings = staticAnalysisService.runStaticPhase(deadlineSeconds, listener);
            completedPhases.add("Static analysis");
            return findings;
        } catch (Exception e) {
            log.warn("Static phase failed for scan {}: {}", scanId, e.getMessage());
            phaseErrors.add("Static analysis failed: " + e.getMessage());
            return List.of();
        }
    }

    private List<Finding> runApiPhase(Long scanId, String target, long deadlineSeconds,
                                       int alreadyFound, List<String> completedPhases, List<String> phaseErrors) {
        ScanProgressListener listener = listener(scanId, "API Probe", 60, 74);
        try {
            listener.onProgress("API Probe", 60, "Probing " + target, alreadyFound);
            List<Finding> findings = apiScannerService.scanTarget(target);
            completedPhases.add("API probe");
            return findings;
        } catch (Exception e) {
            log.warn("API probe phase failed for scan {}: {}", scanId, e.getMessage());
            phaseErrors.add("API probe failed: " + e.getMessage());
            return List.of();
        }
    }

    private List<Finding> runDynamicPhase(Long scanId, String target, String profile, long deadlineSeconds,
                                          int alreadyFound, List<String> completedPhases, List<String> phaseErrors) {
        Scan scan = scanRepository.findById(scanId).orElse(null);
        if (scan == null) {
            return List.of();
        }
        ScanProgressListener listener = new ScanProgressListener() {
            @Override
            public void onProgress(String phase, int percent, String step, int findingsSoFar) {
                // The dynamic phase owns 76%-98% of the overall bar, leaving room to finalise.
                publish(scanId, 76 + (int) ((percent / 100.0) * 22), step, alreadyFound + findingsSoFar);
            }
        };
        try {
            List<Finding> findings = pentestSuiteService.runDynamicPhase(scan, target, profile, deadlineSeconds, listener);
            completedPhases.add("Dynamic testing");
            return findings;
        } catch (Exception e) {
            log.warn("Dynamic phase failed for scan {}: {}", scanId, e.getMessage());
            phaseErrors.add("Dynamic testing failed: " + e.getMessage());
            return List.of();
        }
    }

    // ── Finalisation ───────────────────────────────────────────────────────────

    private void finalizeScan(Long scanId, List<Finding> raw, List<String> completedPhases,
                              List<String> phaseErrors, long startMillis, ScanType type,
                              String profile, boolean fatal) {
        Scan scan = scanRepository.findById(scanId).orElse(null);
        if (scan == null) {
            log.warn("Scan {} vanished before it could be finalised.", scanId);
            return;
        }

        try {
            // Normalise -> dedupe -> correlate -> verify -> score.
            findingNormalizer.normalize(raw);
            List<Finding> unique = findingDeduplicator.deduplicate(raw);
            correlationEngine.correlateFindings(unique);
            verificationEngine.verifyFindings(unique);
            riskScoringService.calculateAndApplyStats(scan, unique);

            scan.getFindings().clear();
            for (Finding f : unique) {
                scan.addFinding(f);
            }

            boolean anyPhaseFailed = !phaseErrors.isEmpty();
            // A scan is only FAILED when nothing usable came out of it. Partial results with a
            // clear note are far more useful than discarding real findings because one phase broke.
            scan.setStatus(fatal && unique.isEmpty() ? ScanStatus.FAILED : ScanStatus.COMPLETED);
            scan.setCompletedAt(LocalDateTime.now());
            scan.setProgressPercent(100);
            scan.setCurrentStep(summarise(completedPhases, phaseErrors, unique.size()));

            StringBuilder error = new StringBuilder();
            if (!completedPhases.isEmpty()) {
                error.append("Completed: ").append(String.join(", ", completedPhases)).append(". ");
            }
            if (anyPhaseFailed) {
                error.append("Phase issues: ").append(String.join(" | ", phaseErrors));
            }
            scan.setErrorMessage(error.length() > 0 ? error.toString() : null);
            scan.setErrorCode(anyPhaseFailed ? "PARTIAL_RESULT" : null);

            scanRepository.save(scan);

            Duration actual = Duration.ofMillis(System.currentTimeMillis() - startMillis);
            durationService.record(type, profile, actual);

            // Produce the PDF as part of finishing, so the report link always resolves.
            try {
                reportGeneratorService.ensureReport(scan);
            } catch (Exception e) {
                log.warn("Report could not be pre-generated for scan {}: {}", scanId, e.getMessage());
            }

            log.info("Scan {} finished in {}s: {} finding(s), score {}/100, phases completed: {}",
                    scanId, actual.getSeconds(), unique.size(), scan.getSecurityScore(),
                    completedPhases.isEmpty() ? "none" : String.join(", ", completedPhases));

            broadcast(scanId, 100, scan.getCurrentStep(), unique.size(), scan.getSecurityScore(), scan.getStatus());
            completeEmitters(scanId);

        } catch (Exception e) {
            // Last-resort: still close the scan so it is never left RUNNING.
            log.error("Could not finalise scan {}", scanId, e);
            try {
                scan.setStatus(ScanStatus.FAILED);
                scan.setCompletedAt(LocalDateTime.now());
                scan.setProgressPercent(100);
                scan.setCurrentStep("Scan finalisation failed: " + e.getMessage());
                scan.setErrorMessage("Could not finalise results: " + e.getMessage());
                scanRepository.save(scan);
                broadcast(scanId, 100, scan.getCurrentStep(), 0, scan.getSecurityScore(), ScanStatus.FAILED);
                completeEmitters(scanId);
            } catch (Exception ignored) {
                log.error("Scan {} could not be closed.", scanId);
            }
        }
    }

    private String summarise(List<String> completed, List<String> errors, int findingCount) {
        if (completed.isEmpty() && errors.isEmpty()) {
            return "Completed — no findings identified";
        }
        String base = completed.isEmpty()
                ? "Partial result"
                : "Completed — " + String.join(" + ", completed);
        base += " — " + findingCount + " finding" + (findingCount == 1 ? "" : "s");
        if (!errors.isEmpty()) {
            base += " (" + errors.size() + " phase issue" + (errors.size() == 1 ? "" : "s") + ")";
        }
        return base;
    }

    private String describeEngines(ScanType type) {
        List<String> engines = new ArrayList<>();
        if (type.includesStatic()) {
            engines.add(staticAnalysisService.isSemgrepAvailable() ? "SEMGREP" : "WORLDGUARD_SAST");
        }
        if (type.includesApiProbe()) {
            engines.add("API_PROBE");
        }
        if (type.includesDynamic()) {
            engines.add("PENTEST_SUITE");
        }
        return String.join(" + ", engines);
    }

    // ── Progress plumbing ──────────────────────────────────────────────────────

    private ScanProgressListener listener(Long scanId, String phase, int from, int to) {
        return (ph, percent, step, count) -> {
            int scaled = from + (int) ((percent / 100.0) * (to - from));
            publish(scanId, scaled, phase + ": " + step, count);
        };
    }

    private void publish(Long scanId, int percent, String step, int findingCount) {
        try {
            Scan scan = scanRepository.findById(scanId).orElse(null);
            if (scan == null) {
                return;
            }
            int bounded = Math.max(0, Math.min(99, percent));
            scan.setProgressPercent(bounded);
            scan.setCurrentStep(step);
            scanRepository.save(scan);
            broadcast(scanId, bounded, step, findingCount, scan.getSecurityScore(), scan.getStatus());
        } catch (Exception e) {
            log.debug("Could not publish progress for scan {}: {}", scanId, e.getMessage());
        }
    }

    // ── SSE ────────────────────────────────────────────────────────────────────

    public SseEmitter subscribeToScan(Long scanId) {
        SseEmitter emitter = new SseEmitter(300_000L);
        emitters.computeIfAbsent(scanId, k -> new CopyOnWriteArrayList<>()).add(emitter);

        emitter.onCompletion(() -> removeEmitter(scanId, emitter));
        emitter.onTimeout(() -> removeEmitter(scanId, emitter));
        emitter.onError(e -> removeEmitter(scanId, emitter));

        scanRepository.findById(scanId).ifPresent(scan -> {
            try {
                emitter.send(SseEmitter.event().name("progress").data(progressDto(scan)));
            } catch (IOException ignored) {
                // Client already gone; the completion callback will clean up.
            }
            if (scan.getStatus() == ScanStatus.COMPLETED || scan.getStatus() == ScanStatus.FAILED) {
                try {
                    emitter.complete();
                } catch (Exception ignored) {
                    // Nothing to do.
                }
            }
        });

        return emitter;
    }

    private com.sih.securityplatform.dto.ScanProgressDto progressDto(Scan scan) {
        return new com.sih.securityplatform.dto.ScanProgressDto(
                scan.getId(),
                scan.getStatus(),
                scan.getProgressPercent(),
                scan.getCurrentStep(),
                scan.getFindings() != null ? scan.getFindings().size() : 0,
                scan.getSecurityScore());
    }

    private void removeEmitter(Long scanId, SseEmitter emitter) {
        List<SseEmitter> list = emitters.get(scanId);
        if (list != null) {
            list.remove(emitter);
            if (list.isEmpty()) {
                emitters.remove(scanId);
            }
        }
    }

    private void completeEmitters(Long scanId) {
        List<SseEmitter> list = emitters.remove(scanId);
        if (list != null) {
            for (SseEmitter emitter : list) {
                try {
                    emitter.complete();
                } catch (Exception ignored) {
                    // Already closed.
                }
            }
        }
    }

    private void broadcast(Long scanId, int percent, String step, int findingsCount, Integer score, ScanStatus status) {
        List<SseEmitter> list = emitters.get(scanId);
        if (list == null || list.isEmpty()) {
            return;
        }
        var dto = new com.sih.securityplatform.dto.ScanProgressDto(scanId, status, percent, step, findingsCount, score);
        for (SseEmitter emitter : list) {
            try {
                emitter.send(SseEmitter.event().name("progress").data(dto));
            } catch (Exception e) {
                try {
                    emitter.complete();
                } catch (Exception ignored) {
                    // Already closed.
                }
            }
        }
    }

    // ── Helpers ────────────────────────────────────────────────────────────────

    private String normalizeProfile(String profile) {
        if (profile == null || profile.isBlank()) {
            return "STANDARD";
        }
        String p = profile.trim().toUpperCase();
        return switch (p) {
            case "QUICK", "STANDARD", "DEEP", "FULL" -> p;
            default -> "STANDARD";
        };
    }

    private String resolveTarget(String requested, ScanType type) {
        if (type == ScanType.SAST) {
            return StaticAnalysisService.GITHUB_REPO;
        }
        if (requested == null || requested.isBlank()) {
            return defaultTarget;
        }
        return requested.trim();
    }

    /** Ensures a PDF exists on disk for the scan, so the report link always works. */
    public boolean ensureReportGenerated(Long scanId) {
        try {
            Scan scan = scanRepository.findById(scanId).orElse(null);
            if (scan == null || scan.getStatus() != ScanStatus.COMPLETED) {
                return false;
            }
            reportGeneratorService.ensureReport(scan);
            return true;
        } catch (Exception e) {
            log.warn("Could not pre-generate report for scan {}: {}", scanId, e.getMessage());
            return false;
        }
    }
}
