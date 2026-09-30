package com.sih.securityplatform.controller;

import com.sih.securityplatform.service.pentest.PentestSuiteException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Turns the exceptions raised by the scanning engines into meaningful HTTP responses.
 *
 * <p>Without this, a rejected scan (missing authorization confirmation, blocked target,
 * malformed payload) surfaced as a bare {@code 500 Internal Server Error} with no body,
 * so the UI could only tell the user "Failed to start scan".
 */
@RestControllerAdvice
public class ApiExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(ApiExceptionHandler.class);

    /** Target rejected by the SSRF / authorization policy. */
    @ExceptionHandler(SecurityException.class)
    public ResponseEntity<Map<String, Object>> handleSecurityException(SecurityException e) {
        log.warn("Scan request rejected by security policy: {}", e.getMessage());
        return build(HttpStatus.FORBIDDEN, "SCAN_REJECTED", e.getMessage());
    }

    /** Malformed request payload or unusable target. */
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, Object>> handleIllegalArgument(IllegalArgumentException e) {
        log.warn("Scan request rejected: {}", e.getMessage());
        return build(HttpStatus.BAD_REQUEST, "INVALID_REQUEST", e.getMessage());
    }

    /** The external scanner engine refused or failed the request. */
    @ExceptionHandler(PentestSuiteException.class)
    public ResponseEntity<Map<String, Object>> handlePentestSuiteException(PentestSuiteException e) {
        log.warn("Pentest Suite error [{}]: {}", e.getErrorCode(), e.getMessage());
        return build(HttpStatus.SERVICE_UNAVAILABLE, e.getErrorCode(), e.getMessage());
    }

    /** Unparseable JSON body, or an enum value that does not exist. */
    @ExceptionHandler({HttpMessageNotReadableException.class, MethodArgumentTypeMismatchException.class})
    public ResponseEntity<Map<String, Object>> handleBadRequest(Exception e) {
        return build(HttpStatus.BAD_REQUEST, "INVALID_REQUEST",
                "Request could not be parsed. Check that field values are valid.");
    }

    private ResponseEntity<Map<String, Object>> build(HttpStatus status, String code, String message) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("status", status.value());
        body.put("error", status.getReasonPhrase());
        body.put("code", code);
        body.put("message", message != null ? message : "Request could not be completed.");
        return ResponseEntity.status(status).body(body);
    }
}
