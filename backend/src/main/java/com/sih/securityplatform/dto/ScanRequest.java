package com.sih.securityplatform.dto;

import com.sih.securityplatform.model.ScanType;

public class ScanRequest {
    private ScanType scanType = ScanType.DAST;
    private String scanProfile = "STANDARD";
    private String targetUrl = "https://worldmonitor.app";
    private boolean isDemo = false;
    private boolean authorizedConfirmation = false;

    public ScanRequest() {}

    public ScanType getScanType() { return scanType; }
    public void setScanType(ScanType scanType) { this.scanType = scanType; }

    public String getScanProfile() { return scanProfile; }
    public void setScanProfile(String scanProfile) { this.scanProfile = scanProfile; }

    public String getTargetUrl() { return targetUrl; }
    public void setTargetUrl(String targetUrl) { this.targetUrl = targetUrl; }

    public boolean isDemo() { return isDemo; }
    public void setDemo(boolean demo) { isDemo = demo; }

    public boolean isAuthorizedConfirmation() { return authorizedConfirmation; }
    public void setAuthorizedConfirmation(boolean authorizedConfirmation) {
        this.authorizedConfirmation = authorizedConfirmation;
    }
}
