package com.sih.securityplatform.model;

import jakarta.persistence.*;
import com.fasterxml.jackson.annotation.JsonBackReference;

@Entity
@Table(name = "findings")
public class Finding {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "scan_id")
    @JsonBackReference
    private Scan scan;

    @Column(nullable = false)
    private String title;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Severity severity = Severity.MEDIUM;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private FindingCategory category = FindingCategory.CONFIGURATION;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private FindingStatus status = FindingStatus.NEEDS_REVIEW;

    private String source = "PENTEST_SUITE";
    private String scanner = "PENTEST_SUITE";
    private String externalFindingId;

    private String target;
    private String endpoint;
    private String method = "GET";
    private String parameter;
    private String filePath;
    private Integer lineNumber;

    @Column(columnDefinition = "TEXT")
    private String whatIsTheIssue;

    @Column(columnDefinition = "TEXT")
    private String whyDoesItMatter;

    @Column(columnDefinition = "TEXT")
    private String description;

    @Column(columnDefinition = "TEXT")
    private String impact;

    @Column(columnDefinition = "TEXT")
    private String evidence;

    @Column(columnDefinition = "TEXT")
    private String recommendation;

    @Column(columnDefinition = "TEXT")
    private String reproductionSteps;

    @Column(columnDefinition = "TEXT")
    private String poc; // Proof of Concept: Request, Response, Payload, Observed Result

    @Column(columnDefinition = "TEXT")
    private String httpRequest;

    @Column(columnDefinition = "TEXT")
    private String httpResponse;

    @Column(columnDefinition = "TEXT")
    private String rawTechnicalDetails;

    @Column(columnDefinition = "TEXT")
    private String rawFinding;

    private String cwe;
    private String owaspCategory;
    private Double cvssScore;
    private String cvssVector;
    private String fingerprint;
    private Integer remediationTimeMinutes = 30;

    public Finding() {}

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public Scan getScan() {
        return scan;
    }

    public void setScan(Scan scan) {
        this.scan = scan;
    }

    public Long getScanId() {
        return scan != null ? scan.getId() : null;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public Severity getSeverity() {
        return severity;
    }

    public void setSeverity(Severity severity) {
        this.severity = severity;
    }

    public FindingCategory getCategory() {
        return category;
    }

    public void setCategory(FindingCategory category) {
        this.category = category;
    }

    public FindingStatus getStatus() {
        return status;
    }

    public void setStatus(FindingStatus status) {
        this.status = status;
    }

    public String getSource() {
        return source;
    }

    public void setSource(String source) {
        this.source = source;
    }

    public String getScanner() {
        return scanner;
    }

    public void setScanner(String scanner) {
        this.scanner = scanner;
    }

    public String getExternalFindingId() {
        return externalFindingId;
    }

    public void setExternalFindingId(String externalFindingId) {
        this.externalFindingId = externalFindingId;
    }

    public String getScannerFindingId() {
        return externalFindingId;
    }

    public void setScannerFindingId(String scannerFindingId) {
        this.externalFindingId = scannerFindingId;
    }

    public String getTarget() {
        return target;
    }

    public void setTarget(String target) {
        this.target = target;
    }

    public String getEndpoint() {
        return endpoint;
    }

    public void setEndpoint(String endpoint) {
        this.endpoint = endpoint;
    }

    public String getMethod() {
        return method;
    }

    public void setMethod(String method) {
        this.method = method;
    }

    public String getParameter() {
        return parameter;
    }

    public void setParameter(String parameter) {
        this.parameter = parameter;
    }

    public String getFilePath() {
        return filePath;
    }

    public void setFilePath(String filePath) {
        this.filePath = filePath;
    }

    public Integer getLineNumber() {
        return lineNumber;
    }

    public void setLineNumber(Integer lineNumber) {
        this.lineNumber = lineNumber;
    }

    public String getWhatIsTheIssue() {
        return whatIsTheIssue;
    }

    public void setWhatIsTheIssue(String whatIsTheIssue) {
        this.whatIsTheIssue = whatIsTheIssue;
    }

    public String getWhyDoesItMatter() {
        return whyDoesItMatter;
    }

    public void setWhyDoesItMatter(String whyDoesItMatter) {
        this.whyDoesItMatter = whyDoesItMatter;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getImpact() {
        return impact;
    }

    public void setImpact(String impact) {
        this.impact = impact;
    }

    public String getEvidence() {
        return evidence;
    }

    public void setEvidence(String evidence) {
        this.evidence = evidence;
    }

    public String getRecommendation() {
        return recommendation;
    }

    public void setRecommendation(String recommendation) {
        this.recommendation = recommendation;
    }

    public String getReproductionSteps() {
        return reproductionSteps;
    }

    public void setReproductionSteps(String reproductionSteps) {
        this.reproductionSteps = reproductionSteps;
    }

    public String getPoc() {
        return poc;
    }

    public void setPoc(String poc) {
        this.poc = poc;
    }

    public String getHttpRequest() {
        return httpRequest;
    }

    public void setHttpRequest(String httpRequest) {
        this.httpRequest = httpRequest;
    }

    public String getHttpResponse() {
        return httpResponse;
    }

    public void setHttpResponse(String httpResponse) {
        this.httpResponse = httpResponse;
    }

    public String getRawTechnicalDetails() {
        return rawTechnicalDetails;
    }

    public void setRawTechnicalDetails(String rawTechnicalDetails) {
        this.rawTechnicalDetails = rawTechnicalDetails;
    }

    public String getRawFinding() {
        return rawFinding;
    }

    public void setRawFinding(String rawFinding) {
        this.rawFinding = rawFinding;
    }

    public String getCwe() {
        return cwe;
    }

    public void setCwe(String cwe) {
        this.cwe = cwe;
    }

    public String getOwaspCategory() {
        return owaspCategory;
    }

    public void setOwaspCategory(String owaspCategory) {
        this.owaspCategory = owaspCategory;
    }

    public Double getCvssScore() {
        return cvssScore;
    }

    public void setCvssScore(Double cvssScore) {
        this.cvssScore = cvssScore;
    }

    public String getCvssVector() {
        return cvssVector;
    }

    public void setCvssVector(String cvssVector) {
        this.cvssVector = cvssVector;
    }

    public String getFingerprint() {
        return fingerprint;
    }

    public void setFingerprint(String fingerprint) {
        this.fingerprint = fingerprint;
    }

    public Integer getRemediationTimeMinutes() {
        return remediationTimeMinutes;
    }

    public void setRemediationTimeMinutes(Integer remediationTimeMinutes) {
        this.remediationTimeMinutes = remediationTimeMinutes;
    }
}
