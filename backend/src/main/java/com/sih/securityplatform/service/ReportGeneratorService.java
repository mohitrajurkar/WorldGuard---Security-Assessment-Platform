package com.sih.securityplatform.service;

import com.lowagie.text.*;
import com.lowagie.text.Font;
import com.lowagie.text.pdf.*;
import com.sih.securityplatform.model.Finding;
import com.sih.securityplatform.model.FindingStatus;
import com.sih.securityplatform.model.Scan;
import com.sih.securityplatform.repository.ReportRepository;
import org.springframework.stereotype.Service;

import java.awt.*;
import java.io.ByteArrayOutputStream;
import java.time.format.DateTimeFormatter;
import java.util.List;

@Service
public class ReportGeneratorService {

    private final ReportRepository reportRepository;

    public ReportGeneratorService(ReportRepository reportRepository) {
        this.reportRepository = reportRepository;
    }

    public byte[] generatePdfReport(Scan scan) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        Document document = new Document(PageSize.A4, 36, 36, 40, 40);
        PdfWriter.getInstance(document, baos);

        document.open();

        // Professional Typography Fonts
        Font titleFont = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 20, new Color(15, 23, 42));
        Font subTitleFont = FontFactory.getFont(FontFactory.HELVETICA, 11, new Color(100, 116, 139));
        Font sectionFont = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 13, new Color(30, 41, 59));
        Font boldFont = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 9, Color.BLACK);
        Font normalFont = FontFactory.getFont(FontFactory.HELVETICA, 9, new Color(51, 65, 85));
        Font evidenceFont = FontFactory.getFont(FontFactory.COURIER, 8, new Color(30, 41, 59));

        // Header Title
        Paragraph title = new Paragraph("WorldGuard Security Assessment Report", titleFont);
        title.setSpacingAfter(3);
        document.add(title);

        Paragraph sub = new Paragraph("Smart India Hackathon 2026 (SIH26163) — Authorized Security Evaluation", subTitleFont);
        sub.setSpacingAfter(14);
        document.add(sub);

        // Metadata Table
        PdfPTable metaTable = new PdfPTable(4);
        metaTable.setWidthPercentage(100);
        metaTable.setSpacingAfter(14);

        addCell(metaTable, "Target:", boldFont, new Color(241, 245, 249));
        addCell(metaTable, scan.getTargetUrl(), normalFont, Color.WHITE);
        addCell(metaTable, "Scan Type:", boldFont, new Color(241, 245, 249));
        addCell(metaTable, scan.getScanType().name(), normalFont, Color.WHITE);

        addCell(metaTable, "Assessment Date:", boldFont, new Color(241, 245, 249));
        addCell(metaTable, scan.getStartedAt() != null ? scan.getStartedAt().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm")) : "N/A", normalFont, Color.WHITE);
        addCell(metaTable, "Security Score:", boldFont, new Color(241, 245, 249));
        Color scoreColor = scan.getSecurityScore() >= 80 ? new Color(220, 252, 231) : scan.getSecurityScore() >= 60 ? new Color(254, 240, 138) : new Color(254, 226, 226);
        addCell(metaTable, scan.getSecurityScore() + " / 100", boldFont, scoreColor);

        document.add(metaTable);

        // 1. Executive Summary
        Paragraph execHeader = new Paragraph("1. Executive Summary", sectionFont);
        execHeader.setSpacingAfter(5);
        document.add(execHeader);

        int total = scan.getFindings() != null ? scan.getFindings().size() : 0;
        Paragraph execText = new Paragraph(
                "This report documents the results of an authorized, evidence-backed security assessment of the World Monitor application. " +
                "The assessment was conducted against " + scan.getTargetUrl() + " combining static source analysis (Semgrep), " +
                "running application testing (OWASP ZAP), and safe API security probes. " +
                "Overall Platform Security Score is " + scan.getSecurityScore() + " / 100. " +
                "Total findings observed: " + total + " (" +
                scan.getVerifiedCount() + " Verified, " +
                scan.getNeedsReviewCount() + " Needs Review, " +
                scan.getPotentialCount() + " Potential).", normalFont);
        execText.setSpacingAfter(12);
        document.add(execText);

        // 2. Finding Summary Table
        Paragraph sumHeader = new Paragraph("2. Finding Classification Summary", sectionFont);
        sumHeader.setSpacingAfter(5);
        document.add(sumHeader);

        PdfPTable countTable = new PdfPTable(4);
        countTable.setWidthPercentage(100);
        countTable.setSpacingAfter(14);

        addCell(countTable, "VERIFIED", boldFont, new Color(254, 226, 226));
        addCell(countTable, "NEEDS REVIEW", boldFont, new Color(254, 240, 138));
        addCell(countTable, "POTENTIAL", boldFont, new Color(224, 231, 255));
        addCell(countTable, "INFORMATIONAL", boldFont, new Color(241, 245, 249));

        addCell(countTable, String.valueOf(scan.getVerifiedCount()), boldFont, Color.WHITE);
        addCell(countTable, String.valueOf(scan.getNeedsReviewCount()), boldFont, Color.WHITE);
        addCell(countTable, String.valueOf(scan.getPotentialCount()), boldFont, Color.WHITE);
        addCell(countTable, String.valueOf(scan.getInformationalCount()), boldFont, Color.WHITE);

        document.add(countTable);

        // 3. Detailed Verified Findings
        Paragraph verHeader = new Paragraph("3. Verified Security Findings", sectionFont);
        verHeader.setSpacingAfter(6);
        document.add(verHeader);

        List<Finding> verifiedFindings = scan.getFindings().stream()
                .filter(f -> f.getStatus() == FindingStatus.VERIFIED)
                .toList();

        if (verifiedFindings.isEmpty()) {
            Paragraph noVer = new Paragraph("No verified vulnerabilities were detected during this evaluation.", normalFont);
            noVer.setSpacingAfter(12);
            document.add(noVer);
        } else {
            for (Finding f : verifiedFindings) {
                document.add(renderFindingTable(f, boldFont, normalFont, evidenceFont));
            }
        }

        // 4. Potential & Review Findings
        Paragraph potHeader = new Paragraph("4. Potential & Review Findings (Manual Verification Required)", sectionFont);
        potHeader.setSpacingAfter(6);
        document.add(potHeader);

        List<Finding> otherFindings = scan.getFindings().stream()
                .filter(f -> f.getStatus() != FindingStatus.VERIFIED)
                .toList();

        if (otherFindings.isEmpty()) {
            Paragraph noPot = new Paragraph("No additional potential issues detected.", normalFont);
            noPot.setSpacingAfter(12);
            document.add(noPot);
        } else {
            for (Finding f : otherFindings) {
                document.add(renderFindingTable(f, boldFont, normalFont, evidenceFont));
            }
        }

        // 5. Assessment Limitations & Tools Used
        Paragraph limitHeader = new Paragraph("5. Assessment Limitations & Tools Used", sectionFont);
        limitHeader.setSpacingAfter(5);
        document.add(limitHeader);

        Paragraph limitText = new Paragraph(
                "Assessment Scope: Safe, non-destructive security evaluation. No brute-force, denial-of-service, or third-party exploits were attempted. " +
                "Tools Employed: Semgrep Static AST Rules (Source Code), OWASP ZAP (Dynamic Web Behavior), WorldGuard Custom API Security Suite, and LeakIX External OSINT. " +
                "Potential findings represent scanner indicators requiring manual architectural review before verification.", normalFont);
        limitText.setSpacingAfter(10);
        document.add(limitText);

        document.close();
        return baos.toByteArray();
    }

    private PdfPTable renderFindingTable(Finding f, Font boldFont, Font normalFont, Font evidenceFont) {
        PdfPTable table = new PdfPTable(2);
        table.setWidthPercentage(100);
        table.setSpacingBefore(4);
        table.setSpacingAfter(10);
        table.setWidths(new float[]{28f, 72f});

        Color headerBg = switch (f.getSeverity()) {
            case CRITICAL -> new Color(254, 226, 226);
            case HIGH -> new Color(255, 237, 213);
            case MEDIUM -> new Color(254, 249, 195);
            case LOW -> new Color(239, 246, 255);
            default -> new Color(241, 245, 249);
        };

        PdfPCell titleCell = new PdfPCell(new Phrase("[" + f.getSeverity() + " - " + f.getStatus() + "] " + f.getTitle(), boldFont));
        titleCell.setColspan(2);
        titleCell.setBackgroundColor(headerBg);
        titleCell.setPadding(5);
        table.addCell(titleCell);

        addCell(table, "Affected Component:", boldFont, Color.WHITE);
        addCell(table, f.getAffectedComponent(), normalFont, Color.WHITE);

        addCell(table, "Source:", boldFont, Color.WHITE);
        addCell(table, f.getSource(), normalFont, Color.WHITE);

        addCell(table, "What is the Issue?", boldFont, Color.WHITE);
        addCell(table, f.getWhatIsTheIssue(), normalFont, Color.WHITE);

        addCell(table, "Why Does It Matter?", boldFont, Color.WHITE);
        addCell(table, f.getWhyDoesItMatter(), normalFont, Color.WHITE);

        addCell(table, "Evidence:", boldFont, Color.WHITE);
        String ev = f.getEvidence() != null && !f.getEvidence().isBlank() ? f.getEvidence() : "Direct scanner observation.";
        addCell(table, ev, evidenceFont, new Color(248, 250, 252));

        addCell(table, "Recommended Fix:", boldFont, Color.WHITE);
        addCell(table, f.getRecommendation(), normalFont, Color.WHITE);

        return table;
    }

    private void addCell(PdfPTable table, String text, Font font, Color bgColor) {
        PdfPCell cell = new PdfPCell(new Phrase(text != null ? text : "", font));
        cell.setBackgroundColor(bgColor);
        cell.setPadding(4);
        cell.setBorderColor(new Color(226, 232, 240));
        table.addCell(cell);
    }
}
