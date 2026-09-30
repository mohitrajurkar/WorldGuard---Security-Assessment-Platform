package com.sih.securityplatform.repository;

import com.sih.securityplatform.model.Finding;
import com.sih.securityplatform.model.FindingCategory;
import com.sih.securityplatform.model.FindingStatus;
import com.sih.securityplatform.model.Severity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface FindingRepository extends JpaRepository<Finding, Long> {

    /**
     * Applies every supplied filter together. A {@code null} argument disables that filter,
     * so callers can combine severity + status + category instead of getting only the
     * first match back.
     */
    @Query("""
            SELECT f FROM Finding f
            WHERE (:scanId IS NULL OR f.scan.id = :scanId)
              AND (:severity IS NULL OR f.severity = :severity)
              AND (:category IS NULL OR f.category = :category)
              AND (:status IS NULL OR f.status = :status)
            """)
    List<Finding> findFiltered(@Param("scanId") Long scanId,
                               @Param("severity") Severity severity,
                               @Param("category") FindingCategory category,
                               @Param("status") FindingStatus status);
}
