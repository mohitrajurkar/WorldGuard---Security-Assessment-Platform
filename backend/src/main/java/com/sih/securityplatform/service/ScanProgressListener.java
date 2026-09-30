package com.sih.securityplatform.service;

/**
 * Receives progress updates from a scan phase so the orchestrator can persist them and
 * stream them to the UI over SSE.
 */
@FunctionalInterface
public interface ScanProgressListener {

    /**
     * @param phase          short phase name, e.g. "Static Analysis"
     * @param progressPercent overall scan progress, 0-100
     * @param step           human-readable description of what is happening right now
     * @param findingsSoFar  number of findings collected so far
     */
    void onProgress(String phase, int progressPercent, String step, int findingsSoFar);

    /** A listener that ignores everything, for phases run without live reporting. */
    ScanProgressListener NOOP = (phase, percent, step, count) -> { };
}
