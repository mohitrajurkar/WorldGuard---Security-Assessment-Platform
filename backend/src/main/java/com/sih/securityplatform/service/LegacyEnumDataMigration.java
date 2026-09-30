package com.sih.securityplatform.service;

import com.sih.securityplatform.model.FindingCategory;
import com.sih.securityplatform.model.FindingStatus;
import com.sih.securityplatform.model.ScanStatus;
import com.sih.securityplatform.model.ScanType;
import com.sih.securityplatform.model.Severity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/**
 * Repairs legacy enum values left behind in the database by earlier schema revisions.
 *
 * <p>Hibernate's {@code ddl-auto: update} only creates and alters tables — it never rewrites
 * stored data. Enums are persisted with {@code @Enumerated(EnumType.STRING)}, so renaming or
 * removing a constant (for example {@code ScanType.COMPLETE} -&gt; {@code ScanType.DAST}) leaves
 * orphaned rows behind. Hibernate then throws {@code IllegalArgumentException: No enum constant}
 * while reading them, which turns every endpoint that touches those tables into a 500.
 *
 * <p>This migration runs once at startup and is a no-op on a healthy database. All statements are
 * plain portable SQL so the same code repairs both the PostgreSQL and the H2 profile.
 */
@Component
@Order(0)
public class LegacyEnumDataMigration implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(LegacyEnumDataMigration.class);

    private final JdbcTemplate jdbcTemplate;

    public LegacyEnumDataMigration(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    /**
     * Legacy value -&gt; replacement. Only values with a defensible successor are remapped
     * individually; everything else falls through to the column's default constant.
     *
     * <p>Note: no remap is needed for {@code ScanType}. An older revision persisted the
     * "Complete Audit" profile as {@code COMPLETE}, which is now the real {@link ScanType#COMPLETE}
     * value, so those rows are valid again and must be left alone.
     */
    private static final Map<String, String> LEGACY_SCAN_TYPES = Map.of();

    @Override
    public void run(ApplicationArguments args) {
        try {
            repairEnums();
        } catch (Exception e) {
            // Never block application startup on a repair failure.
            log.error("Legacy enum data migration failed: {}", e.getMessage(), e);
        }
    }

    private void repairEnums() {
        int total = 0;

        total += repair("scans", "scan_type", enumNames(ScanType.values()), LEGACY_SCAN_TYPES, ScanType.DAST.name());
        total += repair("scans", "status", enumNames(ScanStatus.values()), Map.of(), ScanStatus.FAILED.name());
        total += repair("findings", "severity", enumNames(Severity.values()), Map.of(), Severity.UNKNOWN.name());
        total += repair("findings", "category", enumNames(FindingCategory.values()), Map.of(), FindingCategory.CONFIGURATION.name());
        total += repair("findings", "status", enumNames(FindingStatus.values()), Map.of(), FindingStatus.NEEDS_REVIEW.name());

        if (total == 0) {
            log.info("Legacy enum data check passed — no orphaned enum values found.");
        } else {
            log.warn("Legacy enum data migration repaired {} orphaned row(s) left by an earlier schema revision.", total);
        }
    }

    /**
     * Rewrites any value in {@code table.column} that is no longer a valid enum constant.
     *
     * @return number of rows updated
     */
    private int repair(String table, String column, Set<String> validValues,
                       Map<String, String> legacyMapping, String fallbackValue) {
        if (!tableExists(table) || !columnExists(table, column)) {
            return 0;
        }

        // Hibernate reads these columns with Enum.valueOf, which is case-sensitive. A stored
        // 'sast' or 'Sast' is just as unreadable as 'BOGUS', so casing is repaired first.
        int updated = normaliseCase(table, column);

        // Then remap values that an earlier schema revision used under a different name.
        updated += remap(table, column, legacyMapping);

        // Anything still unrecognised falls back to a safe default.
        updated += remapUnknown(table, column, validValues, fallbackValue);

        return updated;
    }

    /** Forces stored enum values into the exact upper-case form Hibernate expects. */
    private int normaliseCase(String table, String column) {
        return execute("UPDATE " + table + " SET " + column + " = UPPER(TRIM(" + column + "))"
                + " WHERE " + column + " IS NOT NULL AND " + column + " <> UPPER(TRIM(" + column + "))");
    }

    private int remap(String table, String column, Map<String, String> legacyMapping) {
        if (legacyMapping.isEmpty()) {
            return 0;
        }
        int updated = 0;
        for (Map.Entry<String, String> entry : legacyMapping.entrySet()) {
            updated += execute(
                    "UPDATE " + table + " SET " + column + " = ? WHERE UPPER(TRIM(" + column + ")) = ?",
                    entry.getValue(), entry.getKey());
        }
        return updated;
    }

    private int remapUnknown(String table, String column, Set<String> validValues, String fallbackValue) {
        List<Object> allowed = new ArrayList<>(validValues);

        // NULL is already handled by the entity defaults; only repair non-null garbage.
        String sql = "UPDATE " + table + " SET " + column + " = ? WHERE " + column
                + " IS NOT NULL AND UPPER(TRIM(" + column + ")) NOT IN ("
                + placeholders(allowed.size()) + ")";
        return execute(sql, prepend(fallbackValue, allowed));
    }

    private int execute(String sql, Object... args) {
        try {
            return jdbcTemplate.update(sql, args);
        } catch (Exception e) {
            log.debug("Skipping statement [{}]: {}", sql, e.getMessage());
            return 0;
        }
    }

    private boolean tableExists(String table) {
        try {
            Integer count = jdbcTemplate.queryForObject(
                    "SELECT COUNT(*) FROM information_schema.tables WHERE UPPER(table_name) = ?",
                    Integer.class, table.toUpperCase());
            return count != null && count > 0;
        } catch (Exception e) {
            return false;
        }
    }

    private boolean columnExists(String table, String column) {
        try {
            Integer count = jdbcTemplate.queryForObject(
                    "SELECT COUNT(*) FROM information_schema.columns WHERE UPPER(table_name) = ? AND UPPER(column_name) = ?",
                    Integer.class, table.toUpperCase(), column.toUpperCase());
            return count != null && count > 0;
        } catch (Exception e) {
            return false;
        }
    }

    private static String placeholders(int count) {
        return String.join(", ", Collections.nCopies(count, "?"));
    }

    private static Object[] prepend(Object first, List<Object> rest) {
        Object[] args = new Object[rest.size() + 1];
        args[0] = first;
        for (int i = 0; i < rest.size(); i++) {
            args[i + 1] = rest.get(i);
        }
        return args;
    }

    private static Set<String> enumNames(Enum<?>[] values) {
        Set<String> names = new TreeSet<>();
        for (Enum<?> value : values) {
            names.add(value.name());
        }
        return new LinkedHashSet<>(names);
    }
}
