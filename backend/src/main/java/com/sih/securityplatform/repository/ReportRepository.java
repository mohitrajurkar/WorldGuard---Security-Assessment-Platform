package com.sih.securityplatform.repository;

import com.sih.securityplatform.model.Report;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface ReportRepository extends JpaRepository<Report, Long> {
    List<Report> findByScanIdOrderByGeneratedAtDesc(Long scanId);
    List<Report> findAllByOrderByGeneratedAtDesc();
}
