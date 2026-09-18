package com.sih.securityplatform.controller;

import com.sih.securityplatform.service.ApiScannerService;
import com.sih.securityplatform.service.LeakIXService;
import com.sih.securityplatform.service.SemgrepService;
import com.sih.securityplatform.service.ZapService;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/scanners")
@CrossOrigin(origins = "*")
public class ScannerStatusController {

    private final SemgrepService semgrepService;
    private final ZapService zapService;
    private final ApiScannerService apiScannerService;
    private final LeakIXService leakIXService;

    public ScannerStatusController(
            SemgrepService semgrepService,
            ZapService zapService,
            ApiScannerService apiScannerService,
            LeakIXService leakIXService) {
        this.semgrepService = semgrepService;
        this.zapService = zapService;
        this.apiScannerService = apiScannerService;
        this.leakIXService = leakIXService;
    }

    @GetMapping("/status")
    public Map<String, Object> getScannersStatus() {
        Map<String, Object> response = new HashMap<>();

        Map<String, Object> semgrep = new HashMap<>();
        boolean semgrepAvail = semgrepService.isAvailable();
        semgrep.put("available", semgrepAvail);
        semgrep.put("version", semgrepService.getVersion());
        semgrep.put("label", "Source Code Security (SAST)");
        response.put("semgrep", semgrep);

        Map<String, Object> zap = new HashMap<>();
        boolean zapAvail = zapService.isAvailable();
        zap.put("available", zapAvail);
        zap.put("label", "Running Application Security (DAST)");
        zap.put("endpoint", "http://localhost:8090");
        response.put("zap", zap);

        Map<String, Object> apiScanner = new HashMap<>();
        apiScanner.put("available", true);
        apiScanner.put("label", "API & Defensive Header Engine");
        response.put("apiScanner", apiScanner);

        Map<String, Object> leakix = new HashMap<>();
        boolean leakConfigured = leakIXService.isConfigured();
        leakix.put("available", leakConfigured);
        leakix.put("configured", leakConfigured);
        leakix.put("label", "External Security Intelligence (OSINT)");
        response.put("leakix", leakix);

        return response;
    }
}
