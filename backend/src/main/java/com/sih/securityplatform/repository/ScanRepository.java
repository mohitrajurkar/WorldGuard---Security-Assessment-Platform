package com.sih.securityplatform.repository;

import com.sih.securityplatform.model.Scan;
import com.sih.securityplatform.model.ScanStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface ScanRepository extends JpaRepository<Scan, Long> {
    List<Scan> findAllByOrderByStartedAtDesc();
    List<Scan> findByStatus(ScanStatus status);
}
