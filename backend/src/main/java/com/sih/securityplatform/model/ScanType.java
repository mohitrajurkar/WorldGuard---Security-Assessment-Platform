package com.sih.securityplatform.model;

/**
 * The kind of assessment to run.
 */
public enum ScanType {
    /** Static analysis of the World Monitor source code (Semgrep + built-in rules). */
    SAST,
    /** Dynamic web penetration test against a running target (Pentest Suite engine). */
    DAST,
    /** Focused HTTP/API probe of a single endpoint. */
    API_SECURITY,
    /** Full assessment: static + dynamic + API probe, merged into one report. */
    COMPLETE;

    /** True for types that also perform a static source-code pass. */
    public boolean includesStatic() {
        return this == SAST || this == COMPLETE;
    }

    /** True for types that also perform a dynamic/runtime pass. */
    public boolean includesDynamic() {
        return this == DAST || this == COMPLETE;
    }

    /** True for types that also probe a specific API endpoint. */
    public boolean includesApiProbe() {
        return this == API_SECURITY || this == COMPLETE;
    }
}
