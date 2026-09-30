package com.sih.securityplatform.controller;

import com.sih.securityplatform.model.Finding;
import com.sih.securityplatform.model.FindingCategory;
import com.sih.securityplatform.model.FindingStatus;
import com.sih.securityplatform.model.Severity;
import com.sih.securityplatform.repository.FindingRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Regression test for the findings filter chain.
 *
 * <p>{@code listFindings} used to return on the first non-null filter, so a combined
 * {@code ?severity=LOW&status=VERIFIED} query silently returned every LOW finding regardless of
 * status — the Status dropdown on the Findings page had no effect.
 */
@SpringBootTest
@TestPropertySource(properties = {
        "spring.datasource.url=jdbc:h2:mem:filtertest;DB_CLOSE_DELAY=-1",
        "spring.datasource.driver-class-name=org.h2.Driver",
        "spring.datasource.username=sa",
        "spring.datasource.password=",
        "spring.jpa.hibernate.ddl-auto=create-drop"
})
class FindingControllerFilterTest {

    @Autowired
    private FindingController controller;

    @Autowired
    private FindingRepository repository;

    private Finding seed(Severity severity, FindingStatus status, FindingCategory category) {
        Finding f = new Finding();
        f.setTitle(severity + "/" + status + "/" + category);
        f.setSeverity(severity);
        f.setStatus(status);
        f.setCategory(category);
        f.setSource("TEST");
        f.setDescription("test");
        f.setImpact("test");
        f.setEvidence("test");
        f.setRecommendation("test");
        return repository.save(f);
    }

    @Test
    @Transactional
    @DisplayName("severity and status filters are applied together")
    void combinesSeverityAndStatusFilters() {
        seed(Severity.LOW, FindingStatus.VERIFIED, FindingCategory.CORS);
        seed(Severity.LOW, FindingStatus.NEEDS_REVIEW, FindingCategory.CORS);
        seed(Severity.HIGH, FindingStatus.VERIFIED, FindingCategory.CORS);

        List<Finding> result = controller.listFindings(null, Severity.LOW, null, FindingStatus.VERIFIED);

        assertEquals(1, result.size(), "only the LOW + VERIFIED finding should match");
        assertEquals(Severity.LOW, result.get(0).getSeverity());
        assertEquals(FindingStatus.VERIFIED, result.get(0).getStatus());
    }

    @Test
    @Transactional
    @DisplayName("contradictory filter combination returns nothing")
    void contradictoryFiltersReturnEmpty() {
        seed(Severity.LOW, FindingStatus.NEEDS_REVIEW, FindingCategory.CORS);

        assertTrue(controller.listFindings(null, Severity.LOW, null, FindingStatus.VERIFIED).isEmpty());
    }

    @Test
    @Transactional
    @DisplayName("a single filter still behaves like the old dedicated queries")
    void singleFiltersStillWork() {
        seed(Severity.HIGH, FindingStatus.VERIFIED, FindingCategory.SSRF);
        seed(Severity.LOW, FindingStatus.POTENTIAL, FindingCategory.SSRF);

        assertEquals(1, controller.listFindings(null, Severity.HIGH, null, null).size());
        assertEquals(1, controller.listFindings(null, null, null, FindingStatus.POTENTIAL).size());
        assertEquals(2, controller.listFindings(null, null, FindingCategory.SSRF, null).size());
    }

    @Test
    @Transactional
    @DisplayName("no filters returns everything")
    void noFiltersReturnsAll() {
        seed(Severity.HIGH, FindingStatus.VERIFIED, FindingCategory.SSRF);
        seed(Severity.LOW, FindingStatus.POTENTIAL, FindingCategory.CORS);

        assertEquals(2, controller.listFindings(null, null, null, null).size());
    }
}
