package com.sih.securityplatform.controller;

import com.sih.securityplatform.model.Finding;
import com.sih.securityplatform.model.FindingCategory;
import com.sih.securityplatform.model.FindingStatus;
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
            @RequestParam(required = false) FindingStatus status) {

        // Every supplied filter is applied together. Previously the controller returned on the
        // first non-null filter, so a combined severity+status query silently ignored `status`.
        if (scanId == null && severity == null && category == null && status == null) {
            return findingRepository.findAll();
        }
        return findingRepository.findFiltered(scanId, severity, category, status);
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
        Finding finding = findingRepository.findById(id).orElse(null);
        if (finding == null) {
            return ResponseEntity.notFound().build();
        }
        String raw = body.get("status");
        if (raw == null || raw.isBlank()) {
            return ResponseEntity.badRequest().build();
        }
        try {
            finding.setStatus(FindingStatus.valueOf(raw.trim().toUpperCase()));
        } catch (IllegalArgumentException e) {
            // An unknown triage state is a client error, not a server error.
            return ResponseEntity.badRequest().build();
        }
        return ResponseEntity.ok(findingRepository.save(finding));
    }
}
