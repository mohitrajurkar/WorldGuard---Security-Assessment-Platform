package com.sih.securityplatform.dto;

import com.sih.securityplatform.model.Finding;
import com.sih.securityplatform.model.Scan;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class DashboardSummaryDto {
    private int overallSecurityScore = 100;
    private long totalScans;
    private long totalFindings;

    private long verifiedCount;
    private long needsReviewCount;
    private long potentialCount;
    private long informationalCount;

    private long criticalCount;
    private long highCount;
    private long mediumCount;
    private long lowCount;
    private long infoCount;

    private Map<String, Long> categoryDistribution = new HashMap<>();
    private List<Scan> recentScans;
    private List<Finding> topRiskFindings;
    private String targetApp = "World Monitor — Local (http://localhost:3000)";

    public DashboardSummaryDto() {}

    public int getOverallSecurityScore() {
        return overallSecurityScore;
    }

    public void setOverallSecurityScore(int overallSecurityScore) {
        this.overallSecurityScore = overallSecurityScore;
    }

    public long getTotalScans() {
        return totalScans;
    }

    public void setTotalScans(long totalScans) {
        this.totalScans = totalScans;
    }

    public long getTotalFindings() {
        return totalFindings;
    }

    public void setTotalFindings(long totalFindings) {
        this.totalFindings = totalFindings;
    }

    public long getVerifiedCount() {
        return verifiedCount;
    }

    public void setVerifiedCount(long verifiedCount) {
        this.verifiedCount = verifiedCount;
    }

    public long getNeedsReviewCount() {
        return needsReviewCount;
    }

    public void setNeedsReviewCount(long needsReviewCount) {
        this.needsReviewCount = needsReviewCount;
    }

    public long getPotentialCount() {
        return potentialCount;
    }

    public void setPotentialCount(long potentialCount) {
        this.potentialCount = potentialCount;
    }

    public long getInformationalCount() {
        return informationalCount;
    }

    public void setInformationalCount(long informationalCount) {
        this.informationalCount = informationalCount;
    }

    public long getCriticalCount() {
        return criticalCount;
    }

    public void setCriticalCount(long criticalCount) {
        this.criticalCount = criticalCount;
    }

    public long getHighCount() {
        return highCount;
    }

    public void setHighCount(long highCount) {
        this.highCount = highCount;
    }

    public long getMediumCount() {
        return mediumCount;
    }

    public void setMediumCount(long mediumCount) {
        this.mediumCount = mediumCount;
    }

    public long getLowCount() {
        return lowCount;
    }

    public void setLowCount(long lowCount) {
        this.lowCount = lowCount;
    }

    public long getInfoCount() {
        return infoCount;
    }

    public void setInfoCount(long infoCount) {
        this.infoCount = infoCount;
    }

    public Map<String, Long> getCategoryDistribution() {
        return categoryDistribution;
    }

    public void setCategoryDistribution(Map<String, Long> categoryDistribution) {
        this.categoryDistribution = categoryDistribution;
    }

    public List<Scan> getRecentScans() {
        return recentScans;
    }

    public void setRecentScans(List<Scan> recentScans) {
        this.recentScans = recentScans;
    }

    public List<Finding> getTopRiskFindings() {
        return topRiskFindings;
    }

    public void setTopRiskFindings(List<Finding> topRiskFindings) {
        this.topRiskFindings = topRiskFindings;
    }

    public String getTargetApp() {
        return targetApp;
    }

    public void setTargetApp(String targetApp) {
        this.targetApp = targetApp;
    }
}
