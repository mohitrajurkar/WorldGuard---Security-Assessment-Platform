package com.sih.securityplatform.dto;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ApiProbeResult {
    private int statusCode;
    private String statusText;
    private long responseTimeMs;
    private Map<String, String> responseHeaders = new HashMap<>();
    private String responseBody;
    private List<String> securityAlerts = new ArrayList<>();
    private List<String> positiveControls = new ArrayList<>();
    private int securityGradeScore;

    public ApiProbeResult() {}

    public int getStatusCode() {
        return statusCode;
    }

    public void setStatusCode(int statusCode) {
        this.statusCode = statusCode;
    }

    public String getStatusText() {
        return statusText;
    }

    public void setStatusText(String statusText) {
        this.statusText = statusText;
    }

    public long getResponseTimeMs() {
        return responseTimeMs;
    }

    public void setResponseTimeMs(long responseTimeMs) {
        this.responseTimeMs = responseTimeMs;
    }

    public Map<String, String> getResponseHeaders() {
        return responseHeaders;
    }

    public void setResponseHeaders(Map<String, String> responseHeaders) {
        this.responseHeaders = responseHeaders;
    }

    public String getResponseBody() {
        return responseBody;
    }

    public void setResponseBody(String responseBody) {
        this.responseBody = responseBody;
    }

    public List<String> getSecurityAlerts() {
        return securityAlerts;
    }

    public void setSecurityAlerts(List<String> securityAlerts) {
        this.securityAlerts = securityAlerts;
    }

    public List<String> getPositiveControls() {
        return positiveControls;
    }

    public void setPositiveControls(List<String> positiveControls) {
        this.positiveControls = positiveControls;
    }

    public int getSecurityGradeScore() {
        return securityGradeScore;
    }

    public void setSecurityGradeScore(int securityGradeScore) {
        this.securityGradeScore = securityGradeScore;
    }
}
