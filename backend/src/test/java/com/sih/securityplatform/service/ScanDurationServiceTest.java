package com.sih.securityplatform.service;

import com.sih.securityplatform.model.ScanType;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The UI advertises a duration before a scan starts. These tests pin down that the advertised
 * number is a real budget, and that it is replaced by measurement once a scan has run.
 */
class ScanDurationServiceTest {

    private ScanDurationService service() {
        return new ScanDurationService(360_000L); // STANDARD dynamic = 360s
    }

    @Test
    @DisplayName("every offered scan type and profile has an estimate")
    void allCombinationsHaveEstimates() {
        ScanDurationService s = service();
        for (ScanType type : ScanType.values()) {
            for (String profile : new String[]{"QUICK", "STANDARD", "DEEP", "FULL"}) {
                int est = s.estimateSeconds(type, profile);
                assertTrue(est > 0, type + "/" + profile + " must have a positive estimate");
            }
        }
    }

    @Test
    @DisplayName("deeper profiles are never advertised as faster than shallower ones")
    void deeperProfilesCostMore() {
        ScanDurationService s = service();
        assertTrue(s.estimateSeconds(ScanType.DAST, "QUICK")
                < s.estimateSeconds(ScanType.DAST, "STANDARD"));
        assertTrue(s.estimateSeconds(ScanType.DAST, "STANDARD")
                < s.estimateSeconds(ScanType.DAST, "DEEP"));
        assertTrue(s.estimateSeconds(ScanType.DAST, "DEEP")
                < s.estimateSeconds(ScanType.DAST, "FULL"));
    }

    @Test
    @DisplayName("a COMPLETE scan is advertised as costing at least its slowest phase")
    void completeScanIsNotCheaperThanItsParts() {
        ScanDurationService s = service();
        long complete = s.estimateSeconds(ScanType.COMPLETE, "STANDARD");
        long staticPart = s.estimateSeconds(ScanType.SAST, "STANDARD");
        long dynamicPart = s.estimateSeconds(ScanType.DAST, "STANDARD");
        assertTrue(complete >= dynamicPart,
                "COMPLETE must not promise less time than the dynamic phase alone needs");
        assertTrue(complete > staticPart, "COMPLETE must allow for the static phase too");
    }

    @Test
    @DisplayName("the deadline always leaves headroom over the advertised estimate")
    void deadlineExceedsEstimate() {
        ScanDurationService s = service();
        for (ScanType type : ScanType.values()) {
            for (String profile : new String[]{"QUICK", "STANDARD", "DEEP", "FULL"}) {
                int est = s.estimateSeconds(type, profile);
                long deadline = s.deadlineSeconds(type, profile);
                assertTrue(deadline > est,
                        type + "/" + profile + " deadline (" + deadline + "s) must exceed its estimate (" + est + "s)");
            }
        }
    }

    @Test
    @DisplayName("the deadline has an absolute floor so a scan can never be abandoned instantly")
    void deadlineHasAFloor() {
        assertTrue(service().deadlineSeconds(ScanType.API_SECURITY, "QUICK") >= 60);
    }

    @Test
    @DisplayName("a real measurement replaces the seed estimate and is rounded up")
    void measurementReplacesEstimate() {
        ScanDurationService s = service();
        int before = s.estimateSeconds(ScanType.DAST, "STANDARD");

        s.record(ScanType.DAST, "STANDARD", Duration.ofSeconds(100));

        int after = s.estimateSeconds(ScanType.DAST, "STANDARD");
        assertTrue(after != before, "the estimate must change once a real duration is known");
        // 100s measured, +10% and rounded up to the next 5s = 110s.
        assertEquals(110, after);
        assertTrue(after >= 100, "the advertised estimate must never under-promise");
    }

    @Test
    @DisplayName("measurements are scoped to the exact type and profile")
    void measurementsAreScoped() {
        ScanDurationService s = service();
        s.record(ScanType.DAST, "STANDARD", Duration.ofSeconds(50));
        assertEquals(55, s.estimateSeconds(ScanType.DAST, "STANDARD"));
        // A different profile must keep its own estimate.
        assertTrue(s.estimateSeconds(ScanType.DAST, "DEEP") > 55);
        assertTrue(s.estimateSeconds(ScanType.SAST, "STANDARD") > 55);
    }

    @Test
    @DisplayName("nonsensical measurements are ignored")
    void ignoresBadMeasurements() {
        ScanDurationService s = service();
        int before = s.estimateSeconds(ScanType.DAST, "STANDARD");
        s.record(ScanType.DAST, "STANDARD", Duration.ZERO);
        s.record(ScanType.DAST, "STANDARD", Duration.ofSeconds(-5));
        assertEquals(before, s.estimateSeconds(ScanType.DAST, "STANDARD"));
    }

    @Test
    @DisplayName("unknown profiles fall back to the standard estimate instead of failing")
    void unknownProfileFallsBack() {
        ScanDurationService s = service();
        assertEquals(s.estimateSeconds(ScanType.DAST, "STANDARD"), s.estimateSeconds(ScanType.DAST, "NONSENSE"));
        assertEquals(s.estimateSeconds(ScanType.DAST, "STANDARD"), s.estimateSeconds(ScanType.DAST, null));
    }

    @Test
    @DisplayName("the estimates payload is shaped for the UI")
    void exposesEstimatePayload() {
        Map<String, Object> payload = service().allEstimates();
        assertNotNull(payload.get("estimates"));
        assertTrue(payload.get("estimates") instanceof Map);
        assertTrue(((Map<?, ?>) payload.get("estimates")).containsKey(ScanType.COMPLETE));
    }

    @Test
    @DisplayName("human labels read naturally")
    void humanLabelsAreReadable() {
        assertTrue(ScanDurationService.humanize(30).contains("s"));
        assertTrue(ScanDurationService.humanize(360).contains("min"));
        assertTrue(ScanDurationService.shortLabel(360).startsWith("~"));
    }
}
