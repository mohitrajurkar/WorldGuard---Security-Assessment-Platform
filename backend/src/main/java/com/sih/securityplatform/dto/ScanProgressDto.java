package com.sih.securityplatform.dto;

import com.sih.securityplatform.model.ScanStatus;

public class ScanProgressDto {
    private Long scanId;
    private ScanStatus status;
    private int progressPercent;
    private String currentStep;
    private int findingsCount;
    private Integer currentScore;

    public ScanProgressDto() {}

    public ScanProgressDto(Long scanId, ScanStatus status, int progressPercent, String currentStep, int findingsCount, Integer currentScore) {
        this.scanId = scanId;
        this.status = status;
        this.progressPercent = progressPercent;
        this.currentStep = currentStep;
        this.findingsCount = findingsCount;
        this.currentScore = currentScore;
    }

    public Long getScanId() {
        return scanId;
    }

    public void setScanId(Long scanId) {
        this.scanId = scanId;
    }

    public ScanStatus getStatus() {
        return status;
    }

    public void setStatus(ScanStatus status) {
        this.status = status;
    }

    public int getProgressPercent() {
        return progressPercent;
    }

    public void setProgressPercent(int progressPercent) {
        this.progressPercent = progressPercent;
    }

    public String getCurrentStep() {
        return currentStep;
    }

    public void setCurrentStep(String currentStep) {
        this.currentStep = currentStep;
    }

    public int getFindingsCount() {
        return findingsCount;
    }

    public void setFindingsCount(int findingsCount) {
        this.findingsCount = findingsCount;
    }

    public Integer getCurrentScore() {
        return currentScore;
    }

    public void setCurrentScore(Integer currentScore) {
        this.currentScore = currentScore;
    }
}
