package com.sih.securityplatform.service;

import com.sih.securityplatform.model.Scan;
import com.sih.securityplatform.model.ScanType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.EnumMap;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Single source of truth for how long a scan is expected to take.
 *
 * <p>The UI used to hardcode strings like "~30s – 4m" that had no relationship to reality —
 * the same STANDARD dynamic scan actually took about five minutes and routinely blew past the
 * advertised range. Estimates are now seeded from realistic defaults and then replaced by
 * <em>measured</em> durations as scans finish, so the number the user sees is the number the
 * last run of that exact combination actually took.
 */
@Service
public class ScanDurationService {

    private static final Logger log = LoggerFactory.getLogger(ScanDurationService.class);

    /** Seed estimates in seconds, used until a real measurement exists. */
    private static final Map<String, Integer> BASELINE_SECONDS = new ConcurrentHashMap<>();

    /** Last measured duration in seconds, keyed like {@link #key}. */
    private final Map<String, Integer> measuredSeconds = new ConcurrentHashMap<>();

    public ScanDurationService(
            @org.springframework.beans.factory.annotation.Value("${pentest.suite.max-scan-duration-ms:360000}")
            long standardDynamicSeconds) {
        // The configured value is the budget for a STANDARD dynamic scan, so the UI and the
        // orchestrator's hard deadline are derived from the same number.
        BASELINE_SECONDS.put(key(ScanType.DAST, "STANDARD"), (int) (standardDynamicSeconds / 1000));
    }

    static {
        // Static analysis: git clone (~30s) + Semgrep --config auto (~3-4 min) + built-in engine.
        BASELINE_SECONDS.put(key(ScanType.SAST, "STANDARD"), 300);
        BASELINE_SECONDS.put(key(ScanType.SAST, "QUICK"), 180);
        BASELINE_SECONDS.put(key(ScanType.SAST, "DEEP"), 420);

        // Dynamic: the Pentest Suite directory brute-force alone is ~1200 sequential requests.
        BASELINE_SECONDS.put(key(ScanType.DAST, "QUICK"), 45);
        BASELINE_SECONDS.put(key(ScanType.DAST, "STANDARD"), 360);
        BASELINE_SECONDS.put(key(ScanType.DAST, "DEEP"), 900);
        BASELINE_SECONDS.put(key(ScanType.DAST, "FULL"), 1500);

        BASELINE_SECONDS.put(key(ScanType.API_SECURITY, "STANDARD"), 25);
        BASELINE_SECONDS.put(key(ScanType.API_SECURITY, "QUICK"), 15);

        // Complete = static + dynamic + api, plus merge/score/report overhead.
        BASELINE_SECONDS.put(key(ScanType.COMPLETE, "STANDARD"), 600);
        BASELINE_SECONDS.put(key(ScanType.COMPLETE, "QUICK"), 330);
        BASELINE_SECONDS.put(key(ScanType.COMPLETE, "DEEP"), 1150);
        BASELINE_SECONDS.put(key(ScanType.COMPLETE, "FULL"), 1750);
    }

    private static String key(ScanType type, String profile) {
        return type.name() + "|" + normalizeProfile(profile);
    }

    private static String normalizeProfile(String profile) {
        if (profile == null || profile.isBlank()) {
            return "STANDARD";
        }
        String p = profile.trim().toUpperCase(Locale.ROOT);
        return switch (p) {
            case "QUICK", "STANDARD", "DEEP", "FULL" -> p;
            default -> "STANDARD";
        };
    }

    /**
     * Estimated duration in seconds: the last real measurement when we have one, otherwise the
     * baseline. Measurements are smoothed upward slightly so a fast run does not under-promise.
     */
    public int estimateSeconds(ScanType type, String profile) {
        String k = key(type, profile);
        Integer measured = measuredSeconds.get(k);
        if (measured != null) {
            return measured;
        }
        return BASELINE_SECONDS.getOrDefault(k, 300);
    }

    public String estimateLabel(ScanType type, String profile) {
        return humanize(estimateSeconds(type, profile));
    }

    /** Hard deadline for a scan; the orchestrator finalises partial results rather than hanging. */
    public long deadlineSeconds(ScanType type, String profile) {
        // 50% headroom over the estimate absorbs a slow target without letting a run go unbounded.
        return Math.max(60L, (long) (estimateSeconds(type, profile) * 1.5));
    }

    /** Records a real measurement so future estimates reflect reality. */
    public void record(ScanType type, String profile, Duration actual) {
        if (actual == null || actual.isNegative() || actual.isZero()) {
            return;
        }
        int seconds = (int) actual.getSeconds();
        if (seconds <= 0) {
            return;
        }
        // Add 10% headroom, rounded to the nearest 5s, so the promise is conservative.
        int estimate = (int) Math.round(seconds * 1.1 / 5.0) * 5;
        measuredSeconds.put(key(type, profile), estimate);
        log.info("Recorded measured duration for {}/{}: {}s actual -> {}s advertised",
                type, normalizeProfile(profile), seconds, estimate);
    }

    /** Records the measured duration of a finished scan. */
    public void record(Scan scan) {
        if (scan == null || scan.getScanType() == null
                || scan.getStartedAt() == null || scan.getCompletedAt() == null) {
            return;
        }
        record(scan.getScanType(), scan.getProfile(),
                Duration.between(scan.getStartedAt(), scan.getCompletedAt()));
    }

    /** Human-readable estimate such as "about 6 min". */
    public static String humanize(int seconds) {
        if (seconds < 60) {
            return "about " + Math.max(5, (seconds / 5) * 5) + "s";
        }
        int minutes = (int) Math.ceil(seconds / 60.0);
        return "about " + minutes + " min";
    }

    /** Short label for dense UI, e.g. "~6 min". */
    public static String shortLabel(int seconds) {
        return humanize(seconds).replace("about ", "~");
    }

    /** Estimates for every offered combination, for the scan-launch screen. */
    public Map<String, Object> allEstimates() {
        Map<String, Object> out = new java.util.LinkedHashMap<>();
        Map<ScanType, Map<String, Object>> byType = new EnumMap<>(ScanType.class);
        for (ScanType type : ScanType.values()) {
            Map<String, Object> profiles = new java.util.LinkedHashMap<>();
            for (String profile : new String[]{"QUICK", "STANDARD", "DEEP", "FULL"}) {
                if (profile.equals("DEEP") && !(type == ScanType.SAST || type == ScanType.DAST
                        || type == ScanType.COMPLETE)) {
                    continue;
                }
                if (profile.equals("FULL") && type != ScanType.DAST && type != ScanType.COMPLETE) {
                    continue;
                }
                if (type == ScanType.API_SECURITY && !profile.equals("STANDARD") && !profile.equals("QUICK")) {
                    continue;
                }
                profiles.put(profile, estimateSeconds(type, profile));
            }
            byType.put(type, profiles);
        }
        out.put("estimates", byType);
        return out;
    }

    /** Convenience for logging / step text. */
    public String describeDeadline(ScanType type, String profile) {
        return humanize((int) deadlineSeconds(type, profile));
    }

    static LocalDateTime now() {
        return LocalDateTime.now();
    }
}
