package com.sih.securityplatform.service;

import com.lowagie.text.*;
import com.lowagie.text.Font;
import com.lowagie.text.pdf.*;
import com.sih.securityplatform.model.Finding;
import com.sih.securityplatform.model.Report;
import com.sih.securityplatform.model.Scan;
import com.sih.securityplatform.repository.ReportRepository;
import org.springframework.stereotype.Service;

import java.awt.*;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

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

        // Fonts
        Font titleFont = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 22, new Color(15, 23, 42));
        Font subTitleFont = FontFactory.getFont(FontFactory.HELVETICA, 12, new Color(100, 116, 139));
        Font sectionFont = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 14, new Color(30, 41, 59));
        Font boldFont = FontFactory.getFont(FontFactory.HELVETICA_BOLD, 10, Color.BLACK);
        Font normalFont = FontFactory.getFont(FontFactory.HELVETICA, 10, new Color(51, 65, 85));
        Font monoFont = FontFactory.getFont(FontFactory.COURIER, 9, new Color(30, 41, 59));

        // Header
        Paragraph title = new Paragraph("World Monitor Security Assessment Report", titleFont);
        title.setSpacingAfter(4);
        document.add(title);

        Paragraph sub = new Paragraph("Smart India Hackathon 2026 — Problem Statement SIH26163", subTitleFont);
        sub.setSpacingAfter(15);
        document.add(sub);

        // Metadata Table
        PdfPTable metaTable = new PdfPTable(4);
        metaTable.setWidthPercentage(100);
        metaTable.setSpacingAfter(15);

        addCell(metaTable, "Target Application:", boldFont, Color.LIGHT_GRAY);
        addCell(metaTable, scan.getTargetUrl(), normalFont, Color.WHITE);
        addCell(metaTable, "Scan Mode:", boldFont, Color.LIGHT_GRAY);
        addCell(metaTable, scan.getScanType().name(), normalFont, Color.WHITE);

        addCell(metaTable, "Scan Date:", boldFont, Color.LIGHT_GRAY);
        addCell(metaTable, scan.getStartedAt() != null ? scan.getStartedAt().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm")) : "N/A", normalFont, Color.WHITE);
        addCell(metaTable, "Security Score:", boldFont, Color.LIGHT_GRAY);
        addCell(metaTable, scan.getSecurityScore() + " / 100", boldFont, scan.getSecurityScore() > 70 ? new Color(220, 252, 231) : new Color(254, 226, 226));

        document.add(metaTable);

        // Executive Summary
        Paragraph execHeader = new Paragraph("Executive Summary", sectionFont);
        execHeader.setSpacingAfter(6);
        document.add(execHeader);

        Paragraph execText = new Paragraph(
                "This security assessment was conducted against the World Monitor geopolitical intelligence platform architecture. " +
                "The analysis combines Static Application Security Testing (SAST), Dynamic Application Security Testing (DAST), " +
                "and Edge API vulnerability probes. Total Findings Identified: " + scan.getFindings().size() +
                " (Critical: " + scan.getCriticalCount() + ", High: " + scan.getHighCount() +
                ", Medium: " + scan.getMediumCount() + ", Low: " + scan.getLowCount() + ").", normalFont);
        execText.setSpacingAfter(15);
        document.add(execText);

        // Findings Breakdown Section
        Paragraph findingsHeader = new Paragraph("Detailed Security Findings", sectionFont);
        findingsHeader.setSpacingAfter(10);
        document.add(findingsHeader);

        for (Finding f : scan.getFindings()) {
            PdfPTable fTable = new PdfPTable(2);
            fTable.setWidthPercentage(100);
            fTable.setSpacingBefore(6);
            fTable.setSpacingAfter(10);
            fTable.setWidths(new float[]{25f, 75f});

            Color headerColor = switch (f.getSeverity()) {
                case CRITICAL -> new Color(239, 68, 68);
                case HIGH -> new Color(249, 115, 22);
                case MEDIUM -> new Color(234, 179, 8);
                case LOW -> new Color(59, 130, 246);
                default -> new Color(100, 116, 139);
            };

            PdfPCell titleCell = new PdfPCell(new Phrase("[" + f.getSeverity() + "] " + f.getTitle(), FontFactory.getFont(FontFactory.HELVETICA_BOLD, 10, Color.WHITE)));
            titleCell.setColspan(2);
            titleCell.setBackgroundColor(headerColor);
            titleCell.setPadding(6);
            fTable.addCell(titleCell);

            addCell(fTable, "Category / Source", boldFont, Color.WHITE);
            addCell(fTable, f.getCategory() + " (" + f.getSource() + ")", normalFont, Color.WHITE);

            addCell(fTable, "CWE / CVSS", boldFont, Color.WHITE);
            addCell(fTable, (f.getCwe() != null ? f.getCwe() : "N/A") + " | CVSS: " + (f.getCvssScore() != null ? f.getCvssScore() : "N/A"), normalFont, Color.WHITE);

            addCell(fTable, "Location", boldFont, Color.WHITE);
            addCell(fTable, (f.getEndpoint() != null ? f.getEndpoint() : f.getFilePath() + (f.getLineNumber() != null ? ":" + f.getLineNumber() : "")), monoFont, Color.WHITE);

            addCell(fTable, "Description", boldFont, Color.WHITE);
            addCell(fTable, f.getDescription(), normalFont, Color.WHITE);

            addCell(fTable, "Impact", boldFont, Color.WHITE);
            addCell(fTable, f.getImpact(), normalFont, Color.WHITE);

            if (f.getEvidence() != null && !f.getEvidence().isBlank()) {
                addCell(fTable, "Technical Evidence", boldFont, Color.WHITE);
                addCell(fTable, f.getEvidence(), monoFont, new Color(248, 250, 252));
            }

            addCell(fTable, "Recommended Fix", boldFont, Color.WHITE);
            addCell(fTable, f.getRecommendation(), normalFont, new Color(240, 253, 244));

            document.add(fTable);
        }

        document.close();

        // Save report metadata
        byte[] pdfBytes = baos.toByteArray();
        saveReportRecord(scan.getId(), pdfBytes.length);

        return pdfBytes;
    }

    private void addCell(PdfPTable table, String text, Font font, Color bgColor) {
        PdfPCell cell = new PdfPCell(new Phrase(text != null ? text : "", font));
        cell.setBackgroundColor(bgColor);
        cell.setPadding(5);
        table.addCell(cell);
    }

    private void saveReportRecord(Long scanId, long size) {
        try {
            Report report = new Report();
            report.setScanId(scanId);
            report.setTitle("World Monitor Security Assessment - Scan #" + scanId);
            report.setGeneratedAt(LocalDateTime.now());
            report.setFormat("PDF");
            report.setFileSize(size);
            report.setFilePath("/api/reports/scan/" + scanId + "/download");
            reportRepository.save(report);
        } catch (Exception ignored) {}
    }
}
