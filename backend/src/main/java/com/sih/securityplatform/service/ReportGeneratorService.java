package com.sih.securityplatform.service;

import com.lowagie.text.Document;
import com.lowagie.text.Element;
import com.lowagie.text.Font;
import com.lowagie.text.FontFactory;
import com.lowagie.text.PageSize;
import com.lowagie.text.Paragraph;
import com.lowagie.text.Phrase;
import com.lowagie.text.pdf.PdfPCell;
import com.lowagie.text.pdf.PdfPTable;
import com.lowagie.text.pdf.PdfWriter;
import com.sih.securityplatform.model.Finding;
import com.sih.securityplatform.model.FindingStatus;
import com.sih.securityplatform.model.Scan;
import com.sih.securityplatform.model.ScanStatus;
import com.sih.securityplatform.model.Severity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.awt.Color;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Produces the PDF security report.
 *
 * <p>The report is written for a developer who has to actually fix the problems, so it is
 * organised around action rather than around scanning jargon:
 * <ol>
 *   <li>Score and verdict, with the reasoning shown</li>
 *   <li>A prioritised fix list — what to change, where, and why it matters</li>
 *   <li>One section per distinct issue, with evidence and a concrete remediation</li>
 *   <li>Coverage and limitations, so partial results are never mistaken for a clean bill of health</li>
 * </ol>
 */
@Service
public class ReportGeneratorService {

    private static final Logger log = LoggerFactory.getLogger(ReportGeneratorService.class);
    private static final DateTimeFormatter DT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private static final Color INK = new Color(15, 23, 42);
    private static final Color ACCENT = new Color(30, 64, 175);
    private static final Color MUTED = new Color(100, 116, 139);
    private static final Color ZEBRA = new Color(248, 250, 252);
    private static final Color LINE = new Color(203, 213, 225);
    private static final Color GOOD_BG = new Color(240, 253, 244);
    private static final Color GOOD_LINE = new Color(134, 239, 172);
    private static final Color CODE_BG = new Color(30, 41, 59);

    private final String reportsDir;

    public ReportGeneratorService(@Value("${security.platform.reports-dir:./reports}") String reportsDir) {
        this.reportsDir = reportsDir;
        try {
            Files.createDirectories(Paths.get(reportsDir));
        } catch (Exception e) {
            log.warn("Could not create reports directory {}: {}", reportsDir, e.getMessage());
        }
    }

    // ── Public API ─────────────────────────────────────────────────────────────

    /** Renders the report and returns the PDF bytes. */
    public byte[] generatePdfReport(Scan scan) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Document doc = new Document(PageSize.A4, 42, 42, 48, 48);
        PdfWriter.getInstance(doc, out);
        doc.open();

        List<Finding> findings = safeFindings(scan);
        Map<Severity, Integer> bySeverity = countBySeverity(findings);
        Map<String, Integer> byStatus = countByStatus(findings);
        int score = scan.getSecurityScore() != null ? scan.getSecurityScore() : 100;

        header(doc, scan);
        verdict(doc, scan, score, bySeverity, findings.size());
        executiveSummary(doc, scan, score, bySeverity, byStatus, findings.size());
        fixList(doc, findings);
        detailSections(doc, findings);
        coverage(doc, scan, findings);

        doc.close();
        return out.toByteArray();
    }

    /**
     * Renders and stores the report for a scan, returning the file.
     * Called automatically when a scan completes so the download link always resolves.
     */
    public File ensureReport(Scan scan) throws Exception {
        File file = new File(reportsDir, "WorldGuard_Report_Scan_" + scan.getId() + ".pdf");
        byte[] pdf = generatePdfReport(scan);
        try (FileOutputStream fos = new FileOutputStream(file)) {
            fos.write(pdf);
        }
        log.debug("Stored report for scan {} at {}", scan.getId(), file.getAbsolutePath());
        return file;
    }

    // ── Sections ───────────────────────────────────────────────────────────────

    private void header(Document doc, Scan scan) throws Exception {
        doc.add(new Paragraph("WorldGuard Security Assessment", titleFont()));
        doc.add(new Paragraph(
                "Target: " + nvl(scan.getTargetUrl()) + "    •    Type: " + nvl(scan.getScanType())
                        + "    •    Generated: " + LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm")),
                muted()));
        doc.add(rule());
    }

    private void verdict(Document doc, Scan scan, int score, Map<Severity, Integer> bySeverity, int total)
            throws Exception {
        PdfPTable row = new PdfPTable(new float[]{2.1f, 1f, 1f, 1f, 1f, 1f});
        row.setWidthPercentage(100);
        row.setSpacingBefore(10);
        row.setSpacingAfter(4);

        // NOTE: both the label and the value cell must be added, or the row renders empty.
        scoreCell(row, "SECURITY SCORE", score + "/100", grade(score), scoreBg(score));
        scoreCell(row, "CRITICAL", String.valueOf(bySeverity.getOrDefault(Severity.CRITICAL, 0)),
                "blockers", sevBg(Severity.CRITICAL));
        scoreCell(row, "HIGH", String.valueOf(bySeverity.getOrDefault(Severity.HIGH, 0)),
                "fix next", sevBg(Severity.HIGH));
        scoreCell(row, "MEDIUM", String.valueOf(bySeverity.getOrDefault(Severity.MEDIUM, 0)),
                "schedule", sevBg(Severity.MEDIUM));
        scoreCell(row, "LOW", String.valueOf(bySeverity.getOrDefault(Severity.LOW, 0)),
                "backlog", sevBg(Severity.LOW));
        scoreCell(row, "TOTAL", String.valueOf(total), "findings", ZEBRA);
        doc.add(row);
        doc.add(new Paragraph(verdictText(score, bySeverity, total), verdictFont(score)));
    }

    private void executiveSummary(Document doc, Scan scan, int score, Map<Severity, Integer> bySeverity,
                                  Map<String, Integer> byStatus, int total) throws Exception {
        section(doc, "1. Summary");

        StringBuilder narrative = new StringBuilder();
        narrative.append("The assessment scored ").append(score).append("/100 (").append(grade(score)).append("). ");
        int crit = bySeverity.getOrDefault(Severity.CRITICAL, 0);
        int high = bySeverity.getOrDefault(Severity.HIGH, 0);
        if (crit == 0 && high == 0) {
            narrative.append("No critical or high severity issues were confirmed. ");
        } else {
            narrative.append(crit).append(" critical and ").append(high)
                    .append(" high severity issue(s) need attention first. ");
        }
        narrative.append("A total of ").append(total).append(" issue(s) were recorded across the scanned surface.");
        doc.add(new Paragraph(narrative.toString(), body()));

        PdfPTable facts = new PdfPTable(2);
        facts.setWidthPercentage(100);
        facts.setSpacingBefore(6);
        kv(facts, "Scan status", nvl(scan.getStatus()));
        kv(facts, "Scan type", nvl(scan.getScanType()));
        kv(facts, "Profile", nvl(scan.getProfile()));
        kv(facts, "Engines", nvl(scan.getExternalScanner()));
        kv(facts, "Started", scan.getStartedAt() != null ? scan.getStartedAt().format(DT) : "N/A");
        kv(facts, "Completed", scan.getCompletedAt() != null ? scan.getCompletedAt().format(DT) : "N/A");
        kv(facts, "Duration", duration(scan));
        kv(facts, "Confirmed issues", String.valueOf(byStatus.getOrDefault("VERIFIED", 0)));
        kv(facts, "Needs review", String.valueOf(byStatus.getOrDefault("NEEDS_REVIEW", 0)));
        kv(facts, "Potential", String.valueOf(byStatus.getOrDefault("POTENTIAL", 0)));
        if (scan.getErrorMessage() != null && !scan.getErrorMessage().isBlank()) {
            kv(facts, "Phase notes", scan.getErrorMessage());
        }
        doc.add(facts);
    }

    private void fixList(Document doc, List<Finding> findings) throws Exception {
        section(doc, "2. Prioritised Fix List");
        doc.add(new Paragraph(
                "Ordered by severity, then by confidence. Each row is one concrete change to make.",
                muted()));

        List<Finding> ranked = rank(findings);
        if (ranked.isEmpty()) {
            doc.add(callout("No issues require action from this assessment.", GOOD_BG, GOOD_LINE, body()));
            return;
        }

        PdfPTable table = new PdfPTable(new float[]{0.4f, 0.8f, 3.4f, 2.4f, 1.2f});
        table.setWidthPercentage(100);
        table.setSpacingBefore(6);

        headerCell(table, "#");
        headerCell(table, "SEV");
        headerCell(table, "Issue");
        headerCell(table, "Where");
        headerCell(table, "Effort");

        int n = 0;
        for (Finding f : ranked) {
            n++;
            bodyCell(table, String.valueOf(n));
            PdfPCell sev = new PdfPCell(new Phrase(f.getSeverity().name(), sevFont(f.getSeverity())));
            sev.setBackgroundColor(sevBg(f.getSeverity()));
            sev.setHorizontalAlignment(Element.ALIGN_CENTER);
            sev.setPadding(4);
            sev.setBorderColor(LINE);
            table.addCell(sev);
            bodyCell(table, truncate(f.getTitle(), 95));
            bodyCell(table, location(f));
            bodyCell(table, effort(f));
        }
        doc.add(table);

        doc.add(new Paragraph(" ", muted()));
        int totalMinutes = findings.stream()
                .mapToInt(f -> f.getRemediationTimeMinutes() == null ? 30 : f.getRemediationTimeMinutes())
                .sum();
        doc.add(new Paragraph("Estimated total remediation effort: ~" + humanMinutes(totalMinutes) + ".", body()));
    }

    private void detailSections(Document doc, List<Finding> findings) throws Exception {
        section(doc, "3. Issue Details");
        if (findings.isEmpty()) {
            doc.add(new Paragraph("No issues were detected.", body()));
            return;
        }

        List<Finding> ranked = rank(findings);
        int idx = 0;
        for (Finding f : ranked) {
            idx++;
            doc.add(issueHeader(idx, f));

            PdfPTable meta = new PdfPTable(2);
            meta.setWidthPercentage(100);
            meta.setSpacingAfter(4);
            kv(meta, "Severity", nvl(f.getSeverity()));
            kv(meta, "CVSS", f.getCvssScore() != null ? String.valueOf(f.getCvssScore()) : "N/A");
            kv(meta, "CWE", nvl(f.getCwe()));
            kv(meta, "OWASP", nvl(f.getOwaspCategory()));
            kv(meta, "Category", f.getCategory() != null ? f.getCategory().name() : "N/A");
            kv(meta, "Confidence", nvl(f.getStatus()));
            kv(meta, "Source", nvl(f.getSource()));
            doc.add(meta);

            if (f.getFilePath() != null && !f.getFilePath().isBlank()) {
                doc.add(new Paragraph("Location: " + f.getFilePath()
                        + (f.getLineNumber() != null ? ":" + f.getLineNumber() : ""), codeFont(INK)));
            }
            if (f.getEndpoint() != null && !f.getEndpoint().isBlank()) {
                doc.add(new Paragraph("Endpoint: " + f.getMethod() + " " + f.getEndpoint()
                        + (notBlank(f.getParameter()) ? "  (parameter: " + f.getParameter() + ")" : ""), codeFont(INK)));
            }

            labelled(doc, "What is wrong", f.getWhatIsTheIssue() != null ? f.getWhatIsTheIssue() : f.getDescription());
            labelled(doc, "Why it matters", f.getWhyDoesItMatter() != null ? f.getWhyDoesItMatter() : f.getImpact());
            if (notBlank(f.getImpact()) && f.getImpact() != null && !f.getImpact().equals(f.getWhyDoesItMatter())) {
                labelled(doc, "Impact", f.getImpact());
            }

            if (notBlank(f.getEvidence())) {
                doc.add(label("Evidence"));
                doc.add(codeBox(truncate(f.getEvidence(), 900), ZEBRA, LINE, codeFont(INK)));
            }
            if (notBlank(f.getPoc())) {
                doc.add(label("How to reproduce"));
                doc.add(codeBox(truncate(f.getPoc(), 900), ZEBRA, LINE, codeFont(INK)));
            }
            if (notBlank(f.getReproductionSteps()) && !f.getReproductionSteps().equals(f.getPoc())) {
                labelled(doc, "Steps", f.getReproductionSteps());
            }
            if (notBlank(f.getRecommendation())) {
                doc.add(label("How to fix it"));
                doc.add(callout(f.getRecommendation(), GOOD_BG, GOOD_LINE, body()));
            }
            doc.add(new Paragraph(" ", muted()));
        }
    }

    private void coverage(Document doc, Scan scan, List<Finding> findings) throws Exception {
        section(doc, "4. Coverage & Limitations");

        Map<String, Integer> bySource = findings.stream()
                .filter(f -> notBlank(f.getSource()))
                .collect(Collectors.groupingBy(Finding::getSource, LinkedHashMap::new, Collectors.summingInt(x -> 1)));

        if (!bySource.isEmpty()) {
            doc.add(new Paragraph("Findings by detecting engine:", bold()));
            PdfPTable t = new PdfPTable(2);
            t.setWidthPercentage(60);
            for (Map.Entry<String, Integer> e : bySource.entrySet()) {
                kv(t, e.getKey(), String.valueOf(e.getValue()));
            }
            doc.add(t);
            doc.add(new Paragraph(" ", muted()));
        }

        List<String> notes = new ArrayList<>();
        notes.add("This report reflects only what the enabled engines could observe. Absence of a "
                + "finding is not proof that a class of vulnerability is absent.");
        if (scan.getStatus() == ScanStatus.FAILED) {
            notes.add("The scan did not complete successfully. Results are incomplete and must not be "
                    + "treated as a clean result.");
        } else if (scan.getStatus() == ScanStatus.COMPLETED
                && notBlank(scan.getErrorMessage()) && scan.getErrorMessage().contains("Phase issues")) {
            notes.add("One or more scan phases reported problems, so coverage is reduced. See 'Phase notes' above.");
        }
        if (findings.stream().anyMatch(f -> f.getStatus() == FindingStatus.POTENTIAL)) {
            notes.add("Items marked POTENTIAL come from static pattern matching and have not been "
                    + "confirmed at runtime. Review them before scheduling work.");
        }
        for (String n : notes) {
            doc.add(new Paragraph("• " + n, body()));
        }

        doc.add(new Paragraph(" ", muted()));
        doc.add(rule());
        doc.add(new Paragraph("Generated by WorldGuard — SIH26163. All testing is non-destructive and "
                + "performed against an explicitly authorised target.", muted()));
    }

    // ── Layout helpers ─────────────────────────────────────────────────────────

    private void scoreCell(PdfPTable table, String label, String value, String caption, Color bg) {
        PdfPCell lc = new PdfPCell(new Phrase(label, FontFactory.getFont(FontFactory.HELVETICA_BOLD, 7f, MUTED)));
        lc.setBackgroundColor(bg);
        lc.setHorizontalAlignment(Element.ALIGN_CENTER);
        lc.setPadding(5);
        lc.setBorderColor(LINE);

        PdfPCell vc = new PdfPCell();
        vc.addElement(new Phrase(value, FontFactory.getFont(FontFactory.HELVETICA_BOLD, 14, INK)));
        vc.addElement(new Phrase(caption, FontFactory.getFont(FontFactory.HELVETICA, 7f, MUTED)));
        vc.setHorizontalAlignment(Element.ALIGN_CENTER);
        vc.setPadding(5);
        vc.setBorderColor(LINE);

        // Both cells are required; adding only the label leaves the score invisible.
        table.addCell(lc);
        table.addCell(vc);
    }

    private void kv(PdfPTable t, String key, String value) {
        PdfPCell k = new PdfPCell(new Phrase(key, FontFactory.getFont(FontFactory.HELVETICA_BOLD, 8, INK)));
        k.setBackgroundColor(ZEBRA);
        k.setPadding(4);
        k.setBorderColor(LINE);
        t.addCell(k);

        PdfPCell v = new PdfPCell(new Phrase(value, FontFactory.getFont(FontFactory.HELVETICA, 8, INK)));
        v.setPadding(4);
        v.setBorderColor(LINE);
        t.addCell(v);
    }

    private void headerCell(PdfPTable t, String text) {
        PdfPCell c = new PdfPCell(new Phrase(text, FontFactory.getFont(FontFactory.HELVETICA_BOLD, 7, MUTED)));
        c.setBackgroundColor(ZEBRA);
        c.setPadding(4);
        c.setBorderColor(LINE);
        t.addCell(c);
    }

    private void bodyCell(PdfPTable t, String text) {
        PdfPCell c = new PdfPCell(new Phrase(text, body()));
        c.setPadding(4);
        c.setBorderColor(LINE);
        t.addCell(c);
    }

    private Paragraph issueHeader(int idx, Finding f) {
        Paragraph p = new Paragraph(idx + ". " + f.getTitle(), FontFactory.getFont(FontFactory.HELVETICA_BOLD, 10, INK));
        p.setSpacingBefore(10);
        p.setSpacingAfter(3);
        return p;
    }

    private void section(Document doc, String title) throws Exception {
        Paragraph p = new Paragraph(title, FontFactory.getFont(FontFactory.HELVETICA_BOLD, 12, ACCENT));
        p.setSpacingBefore(14);
        p.setSpacingAfter(6);
        doc.add(p);
    }

    private void labelled(Document doc, String label, String text) throws Exception {
        if (!notBlank(text)) {
            return;
        }
        doc.add(label(label));
        doc.add(new Paragraph(text, body()));
    }

    private Paragraph label(String text) {
        Paragraph p = new Paragraph(text, FontFactory.getFont(FontFactory.HELVETICA_BOLD, 8.5f, INK));
        p.setSpacingBefore(5);
        p.setSpacingAfter(2);
        return p;
    }

    private PdfPTable codeBox(String text, Color bg, Color border, Font font) {
        PdfPTable box = new PdfPTable(1);
        box.setWidthPercentage(100);
        box.setSpacingAfter(4);
        PdfPCell c = new PdfPCell(new Phrase(text, font));
        c.setBackgroundColor(bg);
        c.setBorderColor(border);
        c.setPadding(6);
        box.addCell(c);
        return box;
    }

    private PdfPTable callout(String text, Color bg, Color border, Font font) {
        return codeBox(text, bg, border, font);
    }

    private Paragraph rule() {
        Paragraph p = new Paragraph("─".repeat(96), muted());
        p.setSpacingBefore(4);
        return p;
    }

    // ── Data helpers ───────────────────────────────────────────────────────────

    private List<Finding> safeFindings(Scan scan) {
        List<Finding> f = scan.getFindings();
        return f == null ? List.of() : new ArrayList<>(f);
    }

    private List<Finding> rank(List<Finding> findings) {
        List<Finding> copy = new ArrayList<>(findings);
        copy.sort(Comparator
                .comparingInt((Finding f) -> severityRank(f.getSeverity()))
                .thenComparingInt(f -> -confidenceRank(f.getStatus()))
                .thenComparing(f -> nvl(f.getFilePath() != null ? f.getFilePath() : f.getEndpoint())));
        return copy;
    }

    private int severityRank(Severity s) {
        if (s == null) return 9;
        return switch (s) {
            case CRITICAL -> 0;
            case HIGH -> 1;
            case MEDIUM -> 2;
            case LOW -> 3;
            case INFO -> 4;
            default -> 5;
        };
    }

    private int confidenceRank(FindingStatus s) {
        if (s == null) return 0;
        return switch (s) {
            case VERIFIED -> 3;
            case NEEDS_REVIEW, EXTERNAL_INTELLIGENCE -> 2;
            case POTENTIAL -> 1;
            default -> 0;
        };
    }

    private Map<Severity, Integer> countBySeverity(List<Finding> findings) {
        Map<Severity, Integer> m = new LinkedHashMap<>();
        for (Severity s : Severity.values()) {
            m.put(s, 0);
        }
        for (Finding f : findings) {
            m.merge(f.getSeverity() == null ? Severity.UNKNOWN : f.getSeverity(), 1, Integer::sum);
        }
        return m;
    }

    private Map<String, Integer> countByStatus(List<Finding> findings) {
        Map<String, Integer> m = new LinkedHashMap<>();
        for (Finding f : findings) {
            m.merge(f.getStatus() == null ? "UNSET" : f.getStatus().name(), 1, Integer::sum);
        }
        return m;
    }

    private String location(Finding f) {
        if (notBlank(f.getFilePath())) {
            return f.getFilePath() + (f.getLineNumber() != null ? ":" + f.getLineNumber() : "");
        }
        if (notBlank(f.getEndpoint())) {
            return (notBlank(f.getMethod()) ? f.getMethod() + " " : "") + f.getEndpoint();
        }
        return nvl(f.getTarget());
    }

    private String effort(Finding f) {
        int m = f.getRemediationTimeMinutes() == null ? 30 : f.getRemediationTimeMinutes();
        if (m < 60) {
            return "~" + m + " min";
        }
        return "~" + humanMinutes(m);
    }

    private String humanMinutes(int minutes) {
        if (minutes < 60) {
            return minutes + " min";
        }
        int h = minutes / 60;
        int m = minutes % 60;
        return m == 0 ? h + " h" : h + " h " + m + " min";
    }

    private String duration(Scan scan) {
        if (scan.getStartedAt() == null || scan.getCompletedAt() == null) {
            return "N/A";
        }
        Duration d = Duration.between(scan.getStartedAt(), scan.getCompletedAt());
        long s = Math.max(0, d.getSeconds());
        if (s < 60) {
            return s + "s";
        }
        long m = s / 60;
        long rem = s % 60;
        return m + "m " + rem + "s";
    }

    private String grade(int score) {
        if (score >= 90) return "A — strong";
        if (score >= 80) return "B — good";
        if (score >= 70) return "C — needs work";
        if (score >= 50) return "D — poor";
        return "F — critical";
    }

    private String verdictText(int score, Map<Severity, Integer> sev, int total) {
        String base;
        if (score >= 90) {
            base = "Strong posture. Keep the controls below under regression testing.";
        } else if (score >= 80) {
            base = "Generally sound, with a small number of issues to close out.";
        } else if (score >= 70) {
            base = "Acceptable but drifting — schedule the Medium and Low items.";
        } else if (score >= 50) {
            base = "Significant exposure. Prioritise the High items this sprint.";
        } else {
            base = "Serious exposure. Treat the Critical items as an incident and fix before release.";
        }
        int crit = sev.getOrDefault(Severity.CRITICAL, 0);
        if (crit > 0) {
            base += " " + crit + " critical issue(s) require immediate attention.";
        }
        return base + (total == 0 ? " No issues were recorded." : "");
    }

    private Color scoreBg(int score) {
        if (score >= 80) return GOOD_BG;
        if (score >= 60) return new Color(254, 249, 195);
        return new Color(254, 226, 226);
    }

    private Color sevBg(Severity s) {
        if (s == null) return Color.WHITE;
        return switch (s) {
            case CRITICAL -> new Color(254, 202, 202);
            case HIGH -> new Color(254, 215, 170);
            case MEDIUM -> new Color(253, 246, 178);
            case LOW -> new Color(187, 247, 208);
            default -> ZEBRA;
        };
    }

    private Font sevFont(Severity s) {
        Color c = switch (s == null ? Severity.INFO : s) {
            case CRITICAL -> new Color(153, 27, 27);
            case HIGH -> new Color(154, 52, 18);
            case MEDIUM -> new Color(120, 53, 15);
            case LOW -> new Color(22, 101, 52);
            default -> MUTED;
        };
        return FontFactory.getFont(FontFactory.HELVETICA_BOLD, 7, c);
    }

    private Font verdictFont(int score) {
        Color c = score >= 80 ? new Color(21, 128, 61) : score >= 60 ? new Color(180, 83, 9) : new Color(185, 28, 28);
        return FontFactory.getFont(FontFactory.HELVETICA_BOLD, 9, c);
    }

    private Font titleFont() {
        return FontFactory.getFont(FontFactory.HELVETICA_BOLD, 19, INK);
    }

    private Font body() {
        return FontFactory.getFont(FontFactory.HELVETICA, 8.5f, new Color(51, 65, 85));
    }

    private Font bold() {
        return FontFactory.getFont(FontFactory.HELVETICA_BOLD, 8.5f, INK);
    }

    private Font muted() {
        return FontFactory.getFont(FontFactory.HELVETICA, 7.5f, MUTED);
    }

    private Font codeFont(Color c) {
        return FontFactory.getFont(FontFactory.COURIER, 7.5f, c);
    }

    private String truncate(String s, int max) {
        if (s == null) {
            return "";
        }
        String flat = s.replaceAll("\\s+", " ").trim();
        return flat.length() <= max ? flat : flat.substring(0, max) + "…";
    }

    private boolean notBlank(String s) {
        return s != null && !s.isBlank();
    }

    private String nvl(Object o) {
        if (o == null) {
            return "N/A";
        }
        String s = o.toString();
        return s.isBlank() ? "N/A" : s;
    }
}
