package com.sih.securityplatform.dto;

import com.sih.securityplatform.model.ScanType;

public class ScanRequest {
    private ScanType scanType = ScanType.COMPLETE;
    private String targetUrl = "http://localhost:3000";
    private String sourcePath;
    private boolean isDemo = false;

    private boolean enableSemgrep = true;
    private boolean enableApiSecurity = true;
    private boolean enableZap = true;
    private boolean enableLeakix = false;

    private String authorizedDomain;
    private boolean authorizedConfirmation = false;

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

    public boolean isEnableSemgrep() {
        return enableSemgrep;
    }

    public void setEnableSemgrep(boolean enableSemgrep) {
        this.enableSemgrep = enableSemgrep;
    }

    public boolean isEnableApiSecurity() {
        return enableApiSecurity;
    }

    public void setEnableApiSecurity(boolean enableApiSecurity) {
        this.enableApiSecurity = enableApiSecurity;
    }

    public boolean isEnableZap() {
        return enableZap;
    }

    public void setEnableZap(boolean enableZap) {
        this.enableZap = enableZap;
    }

    public boolean isEnableLeakix() {
        return enableLeakix;
    }

    public void setEnableLeakix(boolean enableLeakix) {
        this.enableLeakix = enableLeakix;
    }

    public String getAuthorizedDomain() {
        return authorizedDomain;
    }

    public void setAuthorizedDomain(String authorizedDomain) {
        this.authorizedDomain = authorizedDomain;
    }

    public boolean isAuthorizedConfirmation() {
        return authorizedConfirmation;
    }

    public void setAuthorizedConfirmation(boolean authorizedConfirmation) {
        this.authorizedConfirmation = authorizedConfirmation;
    }
}
