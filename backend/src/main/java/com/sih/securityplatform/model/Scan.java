package com.sih.securityplatform.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import com.fasterxml.jackson.annotation.JsonManagedReference;

@Entity
@Table(name = "scans")
public class Scan {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private ScanType scanType = ScanType.DAST;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private ScanStatus status = ScanStatus.PENDING;

    private String targetUrl = "https://worldmonitor.app";
    private String sourcePath;

    // External Scanner Integration Fields (Pentest Suite)
    private String externalScanner = "PENTEST_SUITE";
    private String externalScanId;
    private String rawResultLocation;
    private String rawResultFormat = "JSON";
    private String profile = "STANDARD";
    private boolean authorizedAssessment = true;

    private LocalDateTime startedAt;
    private LocalDateTime completedAt;

    private Integer securityScore = 100;
    private int criticalCount;
    private int highCount;
    private int mediumCount;
    private int lowCount;
    private int infoCount;

    private int verifiedCount;
    private int needsReviewCount;
    private int potentialCount;
    private int informationalCount;

    private int progressPercent;
    private String currentStep;

    private boolean isDemo;

    // Error tracking
    private String errorCode;
    @Column(columnDefinition = "TEXT")
    private String errorMessage;
    private LocalDateTime errorTimestamp;

    @OneToMany(mappedBy = "scan", cascade = CascadeType.ALL, orphanRemoval = true, fetch = FetchType.EAGER)
    @JsonManagedReference
    private List<Finding> findings = new ArrayList<>();

    public Scan() {}

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public ScanType getScanType() {
        return scanType;
    }

    public void setScanType(ScanType scanType) {
        this.scanType = scanType;
    }

    public ScanStatus getStatus() {
        return status;
    }

    public void setStatus(ScanStatus status) {
        this.status = status;
    }

    public String getTargetUrl() {
        return targetUrl;
    }

    public void setTargetUrl(String targetUrl) {
        this.targetUrl = targetUrl;
    }

    public String getTarget() {
        return targetUrl;
    }

    public void setTarget(String target) {
        this.targetUrl = target;
    }

    public String getSourcePath() {
        return sourcePath;
    }

    public void setSourcePath(String sourcePath) {
        this.sourcePath = sourcePath;
    }

    public String getExternalScanner() {
        return externalScanner;
    }

    public void setExternalScanner(String externalScanner) {
        this.externalScanner = externalScanner;
    }

    public String getExternalScanId() {
        return externalScanId;
    }

    public void setExternalScanId(String externalScanId) {
        this.externalScanId = externalScanId;
    }

    public String getRawResultLocation() {
        return rawResultLocation;
    }

    public void setRawResultLocation(String rawResultLocation) {
        this.rawResultLocation = rawResultLocation;
    }

    public String getRawResultReference() {
        return rawResultLocation;
    }

    public void setRawResultReference(String rawResultReference) {
        this.rawResultLocation = rawResultReference;
    }

    public String getRawResultFormat() {
        return rawResultFormat;
    }

    public void setRawResultFormat(String rawResultFormat) {
        this.rawResultFormat = rawResultFormat;
    }

    public String getProfile() {
        return profile;
    }

    public void setProfile(String profile) {
        this.profile = profile;
    }

    public boolean isAuthorizedAssessment() {
        return authorizedAssessment;
    }

    public void setAuthorizedAssessment(boolean authorizedAssessment) {
        this.authorizedAssessment = authorizedAssessment;
    }

    public LocalDateTime getStartedAt() {
        return startedAt;
    }

    public void setStartedAt(LocalDateTime startedAt) {
        this.startedAt = startedAt;
    }

    public LocalDateTime getCompletedAt() {
        return completedAt;
    }

    public void setCompletedAt(LocalDateTime completedAt) {
        this.completedAt = completedAt;
    }

    public Integer getSecurityScore() {
        return securityScore;
    }

    public void setSecurityScore(Integer securityScore) {
        this.securityScore = securityScore;
    }

    public int getCriticalCount() {
        return criticalCount;
    }

    public void setCriticalCount(int criticalCount) {
        this.criticalCount = criticalCount;
    }

    public int getHighCount() {
        return highCount;
    }

    public void setHighCount(int highCount) {
        this.highCount = highCount;
    }

    public int getMediumCount() {
        return mediumCount;
    }

    public void setMediumCount(int mediumCount) {
        this.mediumCount = mediumCount;
    }

    public int getLowCount() {
        return lowCount;
    }

    public void setLowCount(int lowCount) {
        this.lowCount = lowCount;
    }

    public int getInfoCount() {
        return infoCount;
    }

    public void setInfoCount(int infoCount) {
        this.infoCount = infoCount;
    }

    public int getVerifiedCount() {
        return verifiedCount;
    }

    public void setVerifiedCount(int verifiedCount) {
        this.verifiedCount = verifiedCount;
    }

    public int getNeedsReviewCount() {
        return needsReviewCount;
    }

    public void setNeedsReviewCount(int needsReviewCount) {
        this.needsReviewCount = needsReviewCount;
    }

    public int getPotentialCount() {
        return potentialCount;
    }

    public void setPotentialCount(int potentialCount) {
        this.potentialCount = potentialCount;
    }

    public int getInformationalCount() {
        return informationalCount;
    }

    public void setInformationalCount(int informationalCount) {
        this.informationalCount = informationalCount;
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

    public boolean isDemo() {
        return isDemo;
    }

    public void setDemo(boolean demo) {
        isDemo = demo;
    }

    public String getErrorCode() {
        return errorCode;
    }

    public void setErrorCode(String errorCode) {
        this.errorCode = errorCode;
    }

    public String getErrorMessage() {
        return errorMessage;
    }

    public void setErrorMessage(String errorMessage) {
        this.errorMessage = errorMessage;
    }

    public LocalDateTime getErrorTimestamp() {
        return errorTimestamp;
    }

    public void setErrorTimestamp(LocalDateTime errorTimestamp) {
        this.errorTimestamp = errorTimestamp;
    }

    public List<Finding> getFindings() {
        return findings;
    }

    public void setFindings(List<Finding> findings) {
        this.findings = findings;
    }

    public void addFinding(Finding finding) {
        this.findings.add(finding);
        finding.setScan(this);
    }
}
