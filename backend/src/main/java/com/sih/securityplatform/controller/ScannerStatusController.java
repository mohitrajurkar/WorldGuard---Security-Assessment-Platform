package com.sih.securityplatform.controller;

import com.sih.securityplatform.service.ApiScannerService;
import com.sih.securityplatform.service.ScanDurationService;
import com.sih.securityplatform.service.StaticAnalysisService;
import com.sih.securityplatform.service.pentest.PentestSuiteClient;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Reports the real availability of the engines that actually perform scans.
 *
 * <p>Previously this endpoint advertised ZAP and LeakIX, neither of which was ever invoked, and
 * hardcoded the API scanner as available. It now reports only engines that a scan can route to.
 */
@RestController
@RequestMapping("/api/scanners")
@CrossOrigin(origins = "*")
public class ScannerStatusController {

    private final PentestSuiteClient pentestSuiteClient;
    private final StaticAnalysisService staticAnalysisService;
    private final ApiScannerService apiScannerService;
    private final ScanDurationService durationService;

    public ScannerStatusController(PentestSuiteClient pentestSuiteClient,
                                   StaticAnalysisService staticAnalysisService,
                                   ApiScannerService apiScannerService,
                                   ScanDurationService durationService) {
        this.pentestSuiteClient = pentestSuiteClient;
        this.staticAnalysisService = staticAnalysisService;
        this.apiScannerService = apiScannerService;
        this.durationService = durationService;
    }

    @GetMapping("/status")
    public Map<String, Object> getScannersStatus() {
        Map<String, Object> response = new LinkedHashMap<>();

        boolean suiteUp = pentestSuiteClient.isAvailable();
        Map<String, Object> dynamic = new LinkedHashMap<>();
        dynamic.put("available", suiteUp);
        dynamic.put("label", "Dynamic Engine (Pentest Suite)");
        dynamic.put("endpoint", pentestSuiteClient.baseUrl());
        dynamic.put("version", "2.0.0");
        response.put("dynamic", dynamic);

        boolean semgrep = staticAnalysisService.isSemgrepAvailable();
        boolean git = staticAnalysisService.isGitAvailable();
        Map<String, Object> staticScan = new LinkedHashMap<>();
        // Static analysis is only truly available if we can fetch the repo at all.
        staticScan.put("available", git);
        staticScan.put("semgrepAvailable", semgrep);
        staticScan.put("gitAvailable", git);
        staticScan.put("version", semgrep ? staticAnalysisService.getSemgrepVersion() : "built-in engine");
        staticScan.put("label", "Static Engine (Source Analysis)");
        staticScan.put("repository", staticAnalysisService.getRepositoryUrl());
        response.put("static", staticScan);

        Map<String, Object> api = new LinkedHashMap<>();
        api.put("available", apiScannerService.isReady());
        api.put("label", "API Probe Engine");
        response.put("apiProbe", api);

        response.put("estimates", durationService.allEstimates().get("estimates"));
        return response;
    }
}
