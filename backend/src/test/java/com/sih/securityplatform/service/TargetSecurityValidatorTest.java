package com.sih.securityplatform.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class TargetSecurityValidatorTest {

    private TargetSecurityValidator validator;

    @BeforeEach
    public void setUp() {
        validator = new TargetSecurityValidator(true);
    }

    @Test
    public void testValidHttpAndHttpsTargets() {
        assertDoesNotThrow(() -> validator.validateTarget("https://worldmonitor.app", true));
        assertDoesNotThrow(() -> validator.validateTarget("http://localhost:3000", true));
    }

    @Test
    public void testRejectsMissingAuthorization() {
        SecurityException ex = assertThrows(SecurityException.class, () ->
                validator.validateTarget("https://worldmonitor.app", false));
        assertTrue(ex.getMessage().contains("Authorized assessment confirmation is mandatory"));
    }

    @Test
    public void testRejectsEmptyTarget() {
        assertThrows(IllegalArgumentException.class, () ->
                validator.validateTarget("", true));
        assertThrows(IllegalArgumentException.class, () ->
                validator.validateTarget(null, true));
    }

    @Test
    public void testRejectsInvalidScheme() {
        SecurityException ex1 = assertThrows(SecurityException.class, () ->
                validator.validateTarget("file:///etc/passwd", true));
        assertTrue(ex1.getMessage().contains("Target scheme not permitted"));

        SecurityException ex2 = assertThrows(SecurityException.class, () ->
                validator.validateTarget("ftp://example.com", true));
        assertTrue(ex2.getMessage().contains("Target scheme not permitted"));
    }

    @Test
    public void testRejectsCloudMetadataSSRF() {
        SecurityException ex = assertThrows(SecurityException.class, () ->
                validator.validateTarget("http://169.254.169.254/latest/meta-data/", true));
        assertTrue(ex.getMessage().contains("metadata"));
    }
}
