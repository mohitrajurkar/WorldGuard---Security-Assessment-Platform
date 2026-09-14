package com.sih.securityplatform.controller;

import com.sih.securityplatform.dto.ScanRequest;
import com.sih.securityplatform.model.Scan;
import com.sih.securityplatform.repository.ScanRepository;
import com.sih.securityplatform.service.ScanOrchestratorService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.util.List;

@RestController
@RequestMapping("/api/scans")
@CrossOrigin(origins = "*")
public class ScanController {

    private final ScanRepository scanRepository;
    private final ScanOrchestratorService scanOrchestratorService;

    public ScanController(ScanRepository scanRepository, ScanOrchestratorService scanOrchestratorService) {
        this.scanRepository = scanRepository;
        this.scanOrchestratorService = scanOrchestratorService;
    }

    @PostMapping
    public ResponseEntity<Scan> startScan(@RequestBody ScanRequest request) {
        Scan scan = scanOrchestratorService.initiateScan(request);
        return ResponseEntity.ok(scan);
    }

    @GetMapping
    public List<Scan> listScans() {
        return scanRepository.findAllByOrderByStartedAtDesc();
    }

    @GetMapping("/{id}")
    public ResponseEntity<Scan> getScanById(@PathVariable Long id) {
        return scanRepository.findById(id)
                .map(ResponseEntity::ok)
                .orElse(ResponseEntity.notFound().build());
    }

    @GetMapping("/{id}/stream")
    public SseEmitter streamScanProgress(@PathVariable Long id) {
        return scanOrchestratorService.subscribeToScan(id);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteScan(@PathVariable Long id) {
        if (scanRepository.existsById(id)) {
            scanRepository.deleteById(id);
            return ResponseEntity.noContent().build();
        }
        return ResponseEntity.notFound().build();
    }
}
