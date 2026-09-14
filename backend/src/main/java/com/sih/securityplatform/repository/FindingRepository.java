package com.sih.securityplatform.repository;

import com.sih.securityplatform.model.Finding;
import com.sih.securityplatform.model.FindingCategory;
import com.sih.securityplatform.model.Severity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface FindingRepository extends JpaRepository<Finding, Long> {
    @org.springframework.data.jpa.repository.Query("SELECT f FROM Finding f WHERE f.scan.id = :scanId")
    List<Finding> findByScanId(@org.springframework.data.repository.query.Param("scanId") Long scanId);
    List<Finding> findBySeverity(Severity severity);
    List<Finding> findByCategory(FindingCategory category);
    List<Finding> findByStatus(String status);
    long countBySeverity(Severity severity);
}
