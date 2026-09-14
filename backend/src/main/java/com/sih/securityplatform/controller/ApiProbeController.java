package com.sih.securityplatform.controller;

import com.sih.securityplatform.dto.ApiProbeRequest;
import com.sih.securityplatform.dto.ApiProbeResult;
import com.sih.securityplatform.service.ApiScannerService;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/probe")
@CrossOrigin(origins = "*")
public class ApiProbeController {

    private final ApiScannerService apiScannerService;

    public ApiProbeController(ApiScannerService apiScannerService) {
        this.apiScannerService = apiScannerService;
    }

    @PostMapping
    public ApiProbeResult probeEndpoint(@RequestBody ApiProbeRequest request) {
        return apiScannerService.probeEndpoint(request);
    }
}
