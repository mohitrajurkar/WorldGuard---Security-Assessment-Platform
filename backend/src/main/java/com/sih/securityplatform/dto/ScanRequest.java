package com.sih.securityplatform.dto;

import com.sih.securityplatform.model.ScanType;

public class ScanRequest {
    private ScanType scanType = ScanType.COMPLETE;
    private String targetUrl = "https://worldmonitor.app";
    private String sourcePath;
    private boolean isDemo = false;

    public ScanRequest() {}

    public ScanType getScanType() {
        return scanType;
    }

    public void setScanType(ScanType scanType) {
        this.scanType = scanType;
    }

    public String getTargetUrl() {
        return targetUrl;
    }

    public void setTargetUrl(String targetUrl) {
        this.targetUrl = targetUrl;
    }

    public String getSourcePath() {
        return sourcePath;
    }

    public void setSourcePath(String sourcePath) {
        this.sourcePath = sourcePath;
    }

    public boolean isDemo() {
        return isDemo;
    }

    public void setDemo(boolean demo) {
        isDemo = demo;
    }
}
