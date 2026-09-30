package com.sih.securityplatform.service;

import com.sih.securityplatform.model.Scan;
import com.sih.securityplatform.model.ScanStatus;
import com.sih.securityplatform.repository.ScanRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.List;

/**
 * Closes out scans that were still marked RUNNING/PENDING when the application last stopped.
 *
 * <p>Scans execute on background executors owned by this JVM. If the process is killed mid-scan
 * (Ctrl+C, crash, redeploy) nothing ever marks the record terminal, so it stays RUNNING forever
 * and the UI shows a progress bar that will never move. On the next boot those rows are
 * unrecoverable, so they are closed as FAILED while keeping whatever findings were already
 * collected.
 */
@Component
@Order(1)
public class InterruptedScanRecovery implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(InterruptedScanRecovery.class);

    private static final String INTERRUPTED_MESSAGE =
            "Assessment was interrupted before completion (application stopped while the scan was running). "
                    + "Re-run the assessment to obtain a complete result.";

    private final ScanRepository scanRepository;

    public InterruptedScanRecovery(ScanRepository scanRepository) {
        this.scanRepository = scanRepository;
    }

    @Override
    public void run(ApplicationArguments args) {
        try {
            List<Scan> interrupted = scanRepository.findByStatus(ScanStatus.RUNNING);
            interrupted.addAll(scanRepository.findByStatus(ScanStatus.PENDING));

            for (Scan scan : interrupted) {
                log.warn("Closing interrupted scan [ID: {}] left in {} state from a previous run ({}% complete).",
                        scan.getId(), scan.getStatus(), scan.getProgressPercent());
                scan.setStatus(ScanStatus.FAILED);
                scan.setErrorCode("SCAN_INTERRUPTED");
                scan.setErrorMessage(INTERRUPTED_MESSAGE);
                scan.setErrorTimestamp(LocalDateTime.now());
                if (scan.getCompletedAt() == null) {
                    scan.setCompletedAt(LocalDateTime.now());
                }
                if (scan.getCurrentStep() == null || scan.getCurrentStep().isBlank()) {
                    scan.setCurrentStep("Interrupted — application restarted during assessment");
                }
            }

            if (!interrupted.isEmpty()) {
                scanRepository.saveAll(interrupted);
                log.warn("Marked {} interrupted scan(s) as FAILED.", interrupted.size());
            } else {
                log.info("No interrupted scans to recover.");
            }
        } catch (Exception e) {
            log.error("Interrupted scan recovery failed: {}", e.getMessage(), e);
        }
    }
}
