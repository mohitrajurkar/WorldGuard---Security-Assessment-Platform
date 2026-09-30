package com.sih.securityplatform.model;

public enum Severity {
    CRITICAL,
    HIGH,
    MEDIUM,
    LOW,
    INFO,
    UNKNOWN;

    /**
     * Safely normalizes arbitrary scanner severity strings without crashing.
     */
    public static Severity fromString(String val) {
        if (val == null || val.isBlank()) {
            return UNKNOWN;
        }
        String normalized = val.trim().toUpperCase();
        switch (normalized) {
            case "CRITICAL":
                return CRITICAL;
            case "HIGH":
                return HIGH;
            case "MEDIUM":
                return MEDIUM;
            case "LOW":
                return LOW;
            case "INFO":
            case "INFORMATIONAL":
                return INFO;
            default:
                return UNKNOWN;
        }
    }
}
