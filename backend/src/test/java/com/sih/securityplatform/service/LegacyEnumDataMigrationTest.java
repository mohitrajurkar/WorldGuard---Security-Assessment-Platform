package com.sih.securityplatform.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;

import javax.sql.DataSource;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Regression test for the orphaned-enum crash.
 *
 * <p>An earlier schema revision persisted {@code ScanType.COMPLETE}. Hibernate's
 * {@code ddl-auto: update} never rewrites stored data, so those rows survived and made every
 * query against {@code scans} fail with
 * {@code IllegalArgumentException: No enum constant ...ScanType.COMPLETE} — a 500 on
 * {@code /api/dashboard} and {@code /api/scans}, which left the whole UI blank.
 */
class LegacyEnumDataMigrationTest {

    private JdbcTemplate jdbcTemplate;
    private LegacyEnumDataMigration migration;

    @BeforeEach
    void setUp() {
        DataSource ds = new DriverManagerDataSource(
                "jdbc:h2:mem:migration_" + System.nanoTime() + ";DB_CLOSE_DELAY=-1", "sa", "");
        jdbcTemplate = new JdbcTemplate(ds);

        jdbcTemplate.execute("""
                CREATE TABLE scans (
                    id BIGINT PRIMARY KEY,
                    scan_type VARCHAR(32) NOT NULL,
                    status VARCHAR(32) NOT NULL
                )""");
        jdbcTemplate.execute("""
                CREATE TABLE findings (
                    id BIGINT PRIMARY KEY,
                    severity VARCHAR(32),
                    category VARCHAR(64),
                    status VARCHAR(32)
                )""");

        migration = new LegacyEnumDataMigration(jdbcTemplate);
    }

    @Test
    @DisplayName("legacy ScanType.COMPLETE rows stay COMPLETE, which is valid again")
    void keepsCompleteScanType() {
        jdbcTemplate.update("INSERT INTO scans (id, scan_type, status) VALUES (1, 'COMPLETE', 'COMPLETED')");
        jdbcTemplate.update("INSERT INTO scans (id, scan_type, status) VALUES (2, 'DAST', 'COMPLETED')");

        migration.run(null);

        assertEquals(List.of("COMPLETE", "DAST"),
                jdbcTemplate.queryForList("SELECT scan_type FROM scans ORDER BY id", String.class));
    }

    @Test
    @DisplayName("every scan row is readable by a strict enum parser after migration")
    void allScanTypesAreValidAfterMigration() {
        jdbcTemplate.update("INSERT INTO scans (id, scan_type, status) VALUES (1, 'complete', 'completed')");
        jdbcTemplate.update("INSERT INTO scans (id, scan_type, status) VALUES (2, 'TOTALLY_BOGUS', 'COMPLETED')");
        jdbcTemplate.update("INSERT INTO scans (id, scan_type, status) VALUES (3, ' sast ', 'COMPLETED')");

        migration.run(null);

        for (String raw : jdbcTemplate.queryForList("SELECT scan_type FROM scans", String.class)) {
            // This is exactly what Hibernate does when it hydrates the entity: case-sensitive.
            com.sih.securityplatform.model.ScanType.valueOf(raw);
        }
        for (String raw : jdbcTemplate.queryForList("SELECT status FROM scans", String.class)) {
            com.sih.securityplatform.model.ScanStatus.valueOf(raw);
        }
    }

    @Test
    @DisplayName("unknown finding enum values fall back to safe defaults")
    void repairsFindingEnums() {
        jdbcTemplate.update("INSERT INTO findings (id, severity, category, status) VALUES (1, 'BOGUS', 'NOPE', 'WAT')");

        migration.run(null);

        assertEquals("UNKNOWN",
                jdbcTemplate.queryForObject("SELECT severity FROM findings WHERE id = 1", String.class));
        assertEquals("CONFIGURATION",
                jdbcTemplate.queryForObject("SELECT category FROM findings WHERE id = 1", String.class));
        assertEquals("NEEDS_REVIEW",
                jdbcTemplate.queryForObject("SELECT status FROM findings WHERE id = 1", String.class));
    }

    @Test
    @DisplayName("valid data and NULLs are left untouched, and re-running is a no-op")
    void isIdempotentAndPreservesValidData() {
        jdbcTemplate.update("INSERT INTO scans (id, scan_type, status) VALUES (1, 'SAST', 'COMPLETED')");
        jdbcTemplate.update("INSERT INTO scans (id, scan_type, status) VALUES (2, 'DAST', 'COMPLETED')");
        jdbcTemplate.update("INSERT INTO findings (id, severity, category, status) VALUES (1, 'CRITICAL', 'SSRF', 'VERIFIED')");
        jdbcTemplate.update("INSERT INTO findings (id, severity, category, status) VALUES (2, NULL, NULL, NULL)");

        migration.run(null);
        migration.run(null); // must stay safe on every boot

        assertEquals("SAST", jdbcTemplate.queryForObject("SELECT scan_type FROM scans WHERE id = 1", String.class));
        assertEquals("DAST", jdbcTemplate.queryForObject("SELECT scan_type FROM scans WHERE id = 2", String.class));
        assertEquals("CRITICAL", jdbcTemplate.queryForObject("SELECT severity FROM findings WHERE id = 1", String.class));
        assertTrue(jdbcTemplate.queryForObject("SELECT severity FROM findings WHERE id = 2", String.class) == null,
                "NULL severity must stay NULL");
    }

    @Test
    @DisplayName("missing tables are skipped instead of failing startup")
    void toleratesMissingTables() {
        JdbcTemplate empty = new JdbcTemplate(new DriverManagerDataSource(
                "jdbc:h2:mem:empty_" + System.nanoTime() + ";DB_CLOSE_DELAY=-1", "sa", ""));
        new LegacyEnumDataMigration(empty).run(null); // must not throw
    }
}
