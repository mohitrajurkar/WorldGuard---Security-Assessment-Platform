package com.sih.securityplatform.dto;

import java.util.HashMap;
import java.util.Map;

public class ApiProbeRequest {
    private String method = "GET";
    private String url = "https://worldmonitor.app/api/version";
    private Map<String, String> headers = new HashMap<>();
    private String body;

    public ApiProbeRequest() {}

    public String getMethod() {
        return method;
    }

    public void setMethod(String method) {
        this.method = method;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public Map<String, String> getHeaders() {
        return headers;
    }

    public void setHeaders(Map<String, String> headers) {
        this.headers = headers;
    }

    public String getBody() {
        return body;
    }

    public void setBody(String body) {
        this.body = body;
    }
}
