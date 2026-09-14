package com.sih.securityplatform.controller;

import com.sih.securityplatform.model.Finding;
import com.sih.securityplatform.model.FindingCategory;
import com.sih.securityplatform.model.Severity;
import com.sih.securityplatform.repository.FindingRepository;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/findings")
@CrossOrigin(origins = "*")
public class FindingController {

    private final FindingRepository findingRepository;

    public FindingController(FindingRepository findingRepository) {
        this.findingRepository = findingRepository;
    }

    @GetMapping
    public List<Finding> listFindings(
            @RequestParam(required = false) Long scanId,
            @RequestParam(required = false) Severity severity,
            @RequestParam(required = false) FindingCategory category,
            @RequestParam(required = false) String status) {

        if (scanId != null) {
            return findingRepository.findByScanId(scanId);
        }
        if (severity != null) {
            return findingRepository.findBySeverity(severity);
        }
        if (category != null) {
            return findingRepository.findByCategory(category);
        }
        if (status != null) {
            return findingRepository.findByStatus(status);
        }
        return findingRepository.findAll();
    }

    @GetMapping("/{id}")
    public ResponseEntity<Finding> getFindingById(@PathVariable Long id) {
        return findingRepository.findById(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @PatchMapping("/{id}/status")
    public ResponseEntity<Finding> updateFindingStatus(
            @PathVariable Long id,
            @RequestBody Map<String, String> body) {
        return findingRepository.findById(id).map(finding -> {
            String newStatus = body.get("status");
            if (newStatus != null) {
                finding.setStatus(newStatus.toUpperCase());
                findingRepository.save(finding);
            }
            return ResponseEntity.ok(finding);
        }).orElse(ResponseEntity.notFound().build());
    }
}
