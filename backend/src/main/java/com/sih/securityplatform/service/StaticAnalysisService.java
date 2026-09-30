package com.sih.securityplatform.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sih.securityplatform.model.Finding;
import com.sih.securityplatform.model.FindingCategory;
import com.sih.securityplatform.model.Severity;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * Static analysis phase: clones the World Monitor repository and scans its source code.
 *
 * <p>Two engines run over the same clone:
 * <ol>
 *   <li><b>Semgrep</b> — real rule engine, when the CLI is installed. Bounded by the phase
 *       deadline so it can never outlive the scan.</li>
 *   <li><b>Built-in pattern engine</b> — always runs. Catches the specific insecure idioms that
 *       matter for this codebase (hardcoded secrets, unsanitised {@code innerHTML}, {@code eval},
 *       wildcard CORS, auth tokens in localStorage).</li>
 * </ol>
 *
 * <p>Findings come only from actual analysis of the cloned code. This service never fabricates
 * findings, because a security report that invents its own results is worse than no report.
 */
@Service
public class StaticAnalysisService {

    private static final Logger log = LoggerFactory.getLogger(StaticAnalysisService.class);

    /** The upstream repository that every static scan analyses. */
    public static final String GITHUB_REPO = "https://github.com/koala73/worldmonitor.git";

    /** Upper bound on captured Semgrep output, to survive a runaway registry pull. */
    private static final int MAX_SEMGREP_OUTPUT = 80_000_000;

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final String localRulesPath;

    private volatile String cachedSemgrepVersion;
    private volatile boolean semgrepChecked;

    public StaticAnalysisService(
            @Value("${security.platform.semgrep-rules-path:}") String localRulesPath) {
        this.localRulesPath = localRulesPath;
        if (localRulesPath != null && !localRulesPath.isBlank()) {
            log.info("Static analysis configured with local Semgrep rules: {}", localRulesPath);
        } else {
            log.info("No local Semgrep rule pack configured; the built-in pattern engine will be used.");
        }
    }

    // ── Engine availability (reported by /api/scanners/status) ─────────────────

    /** True when the Semgrep CLI is installed and runnable. */
    public boolean isSemgrepAvailable() {
        return getSemgrepVersion() != null;
    }

    /** Semgrep version string, or {@code null} when the CLI is not installed. */
    public synchronized String getSemgrepVersion() {
        if (semgrepChecked) {
            return cachedSemgrepVersion;
        }
        semgrepChecked = true;
        try {
            Process p = new ProcessBuilder("semgrep", "--version")
                    .redirectErrorStream(true).start();
            String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8).trim();
            if (p.waitFor(20, TimeUnit.SECONDS) && p.exitValue() == 0 && !out.isBlank()) {
                cachedSemgrepVersion = out.split("\\R")[0].trim();
            }
        } catch (Exception e) {
            cachedSemgrepVersion = null;
        }
        return cachedSemgrepVersion;
    }

    /** True when the git CLI is available (required to fetch the repository). */
    public boolean isGitAvailable() {
        try {
            Process p = new ProcessBuilder("git", "--version")
                    .redirectErrorStream(true).start();
            return p.waitFor(15, TimeUnit.SECONDS) && p.exitValue() == 0;
        } catch (Exception e) {
            return false;
        }
    }

    /** True when a local Semgrep rules file was configured and exists. */
    public boolean hasLocalRules() {
        return localRulesPath != null && !localRulesPath.isBlank() && new File(localRulesPath).isFile();
    }

    public String getRepositoryUrl() {
        return GITHUB_REPO;
    }

    // ── Phase entry point ──────────────────────────────────────────────────────

    /**
     * Runs the static phase and returns findings from the cloned source.
     *
     * @param deadlineSeconds hard budget; the phase stops early and returns what it has
     */
    public List<Finding> runStaticPhase(long deadlineSeconds, ScanProgressListener listener) {
        List<Finding> findings = new ArrayList<>();
        long start = System.currentTimeMillis();
        long deadlineMs = deadlineSeconds * 1000L;
        long deadlineNanos = System.nanoTime() + deadlineMs * 1_000_000L;

        listener.onProgress("Static", 4, "Fetching World Monitor source from GitHub", 0);

        Path cloneDir;
        try {
            cloneDir = cloneRepository((int) Math.min(120L, Math.max(30L, deadlineSeconds / 2)));
        } catch (Exception e) {
            log.error("Could not clone {}: {}", GITHUB_REPO, e.getMessage());
            listener.onProgress("Static", 8, "Repository clone failed: " + e.getMessage(), 0);
            throw new IllegalStateException(
                    "Unable to fetch the World Monitor source repository (" + GITHUB_REPO + "): " + e.getMessage(), e);
        }

        try {
            listener.onProgress("Static", 18, "Scanning source tree with built-in security patterns", 0);
            runBuiltInStaticEngine(cloneDir.toString(), findings, deadlineNanos);
            listener.onProgress("Static", 32, "Built-in patterns matched " + findings.size() + " issue(s)", findings.size());

            if (isSemgrepAvailable() && System.currentTimeMillis() - start < deadlineMs) {
                int remaining = (int) Math.max(30, (deadlineMs - (System.currentTimeMillis() - start)) / 1000);
                listener.onProgress("Static", 40,
                        "Running Semgrep " + cachedSemgrepVersion + " (budget " + remaining + "s)", findings.size());
                runSemgrep(cloneDir.toString(), findings, remaining);
                listener.onProgress("Static", 60, "Semgrep analysis complete — " + findings.size() + " issue(s) total",
                        findings.size());
            } else if (!isSemgrepAvailable()) {
                listener.onProgress("Static", 40,
                        "Semgrep CLI not installed — built-in pattern engine only", findings.size());
            } else {
                listener.onProgress("Static", 60, "Semgrep skipped to stay within the scan budget", findings.size());
            }
        } finally {
            deleteQuietly(cloneDir.toFile());
        }

        log.info("Static analysis complete — {} finding(s) from {}", findings.size(), GITHUB_REPO);
        return findings;
    }

    // ── Repository ─────────────────────────────────────────────────────────────

    private Path cloneRepository(int timeoutSeconds) throws Exception {
        if (!isGitAvailable()) {
            throw new IllegalStateException("The 'git' command is not available on PATH.");
        }
        Path tmpDir = Files.createTempDirectory("worldguard_sast_");
        log.info("Cloning {} into {}", GITHUB_REPO, tmpDir);

        // Output goes to a file so a stalled clone cannot block on a pipe read.
        Path logFile = Files.createTempFile("worldguard_clone_", ".log");
        ProcessBuilder pb = new ProcessBuilder(
                "git", "clone", "--depth", "1", "--single-branch", "--quiet", GITHUB_REPO, tmpDir.toString());
        pb.redirectErrorStream(true);
        pb.redirectOutput(logFile.toFile());
        Process p = pb.start();

        if (!p.waitFor(timeoutSeconds, TimeUnit.SECONDS)) {
            p.destroyForcibly();
            throw new IllegalStateException("git clone timed out after " + timeoutSeconds + "s");
        }
        if (p.exitValue() != 0) {
            String output = Files.exists(logFile) ? Files.readString(logFile) : "";
            Files.deleteIfExists(logFile);
            throw new IllegalStateException("git clone failed: " + output);
        }
        Files.deleteIfExists(logFile);
        return tmpDir;
    }

    // ── Semgrep ────────────────────────────────────────────────────────────────

    private void runSemgrep(String sourcePath, List<Finding> findings, int timeoutSeconds) {
        List<String> cmd = new ArrayList<>(List.of(
                "semgrep", "scan", "--json",
                "--timeout", "30",
                "--max-memory", "1024",
                "--quiet"));

        // Prefer the checked-in rule pack; fall back to Semgrep's registry rules.
        if (hasLocalRules()) {
            // --config auto is incompatible with --metrics off, so opt out of telemetry only
            // when we are running our own rules and do not need the registry.
            cmd.add("--metrics");
            cmd.add("off");
            cmd.add("--config");
            cmd.add(localRulesPath);
        } else {
            cmd.add("--config");
            cmd.add("auto");
        }
        cmd.add(sourcePath);

        Process p = null;
        // Semgrep writes to a file rather than a pipe. Reading a pipe with a blocking
        // readLine() would hang forever if the process stalled, because waitFor(timeout) is only
        // reached *after* the stream is drained. A file can be polled and abandoned safely.
        Path outputFile = null;
        try {
            outputFile = Files.createTempFile("worldguard_semgrep_", ".json");
            ProcessBuilder pb = new ProcessBuilder(cmd);
            // Semgrep draws a banner on stderr. Merging it into stdout corrupts the JSON payload.
            pb.redirectErrorStream(false);
            pb.redirectError(ProcessBuilder.Redirect.DISCARD);
            pb.redirectOutput(outputFile.toFile());
            p = pb.start();

            if (!p.waitFor(timeoutSeconds, TimeUnit.SECONDS)) {
                p.destroyForcibly();
                log.warn("Semgrep exceeded its {}s budget; keeping results collected so far", timeoutSeconds);
            }

            parseSemgrepJson(readCapped(outputFile), findings);
        } catch (Exception e) {
            log.warn("Semgrep execution failed: {}", e.getMessage());
        } finally {
            if (p != null && p.isAlive()) {
                p.destroyForcibly();
            }
            if (outputFile != null) {
                try {
                    Files.deleteIfExists(outputFile);
                } catch (Exception ignored) {
                    // Temp file cleanup is best-effort.
                }
            }
        }
    }

    /** Reads at most {@link #MAX_SEMGREP_OUTPUT} characters of the captured output. */
    private String readCapped(Path file) {
        try (BufferedReader r = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
            StringBuilder out = new StringBuilder();
            char[] buffer = new char[8192];
            int read;
            while (out.length() < MAX_SEMGREP_OUTPUT && (read = r.read(buffer)) != -1) {
                out.append(buffer, 0, read);
            }
            return out.toString();
        } catch (Exception e) {
            log.warn("Could not read Semgrep output: {}", e.getMessage());
            return "";
        }
    }

    private void parseSemgrepJson(String json, List<Finding> findings) {
        if (json == null || json.isBlank()) {
            return;
        }
        int start = locateJsonStart(json);
        if (start < 0) {
            log.warn("No Semgrep JSON payload found in output ({} chars)", json.length());
            return;
        }
        try {
            JsonNode root = objectMapper.readTree(json.substring(start));
            JsonNode results = root.path("results");
            if (!results.isArray()) {
                log.warn("Semgrep payload had no 'results' array");
                return;
            }
            int parsed = 0;
            for (JsonNode res : results) {
                Finding f = toFinding(res);
                if (f != null) {
                    findings.add(f);
                    parsed++;
                }
            }
            log.info("Semgrep reported {} result(s), {} converted to findings", results.size(), parsed);
        } catch (Exception e) {
            log.warn("Could not parse Semgrep output: {}", e.getMessage());
        }
    }

    /**
     * Semgrep writes a progress banner to stdout before the JSON payload, so the first '{' in
     * the stream is almost never the start of the document. Locating the brace that opens the
     * object containing "results" is what makes the output actually parseable.
     */
    private int locateJsonStart(String json) {
        int resultsAt = json.indexOf("\"results\"");
        if (resultsAt > 0) {
            for (int i = resultsAt; i >= 0; i--) {
                if (json.charAt(i) == '{') {
                    return i;
                }
            }
        }
        // Fall back to the first brace on its own line, which is how semgrep emits the document.
        for (int i = 0; i < json.length(); i++) {
            if (json.charAt(i) == '{' && (i == 0 || json.charAt(i - 1) == '\n')) {
                return i;
            }
        }
        return json.indexOf('{');
    }

    private Finding toFinding(JsonNode res) {
        String ruleId = res.path("check_id").asText("semgrep.rule");
        if (ruleId.isBlank()) {
            return null;
        }
        JsonNode extra = res.path("extra");
        String filePath = res.path("path").asText("");
        int line = res.path("start").path("line").asInt(1);
        String message = extra.path("message").asText("");
        String code = extra.path("lines").asText("").trim();

        Finding f = new Finding();
        f.setTitle(humanTitle(ruleId, message));
        f.setSource("Semgrep");
        f.setScanner("SEMGREP");
        f.setFilePath(cleanPath(filePath));
        f.setLineNumber(line);
        f.setTarget(GITHUB_REPO);
        f.setSeverity(severity(extra.path("severity").asText("WARNING").toUpperCase()));
        f.setCategory(category(ruleId, message));
        f.setStatus(com.sih.securityplatform.model.FindingStatus.POTENTIAL);
        f.setCwe(cwe(extra.path("metadata"), ruleId, message));
        f.setCvssScore(cvss(f.getSeverity()));
        f.setDescription(message.isBlank() ? "Semgrep rule matched in source code." : message);
        f.setWhatIsTheIssue("Static analysis matched rule \"" + ruleId + "\" in " + f.getFilePath() + ".");
        f.setWhyDoesItMatter("Unvalidated or insecure code patterns can become exploitable once the surrounding logic is reachable.");
        f.setEvidence(code.isBlank() ? filePath + ":" + line : code);
        f.setImpact("May allow an attacker to abuse this code path, depending on how the value is later used.");
        f.setRecommendation("Review this location and apply the fix described in the rule documentation.");
        f.setReproductionSteps("Open " + f.getFilePath() + " at line " + line + " and trace how the value is used.");
        f.setRawTechnicalDetails("Rule: " + ruleId + "\nMetadata: " + extra.path("metadata").toString());
        return f;
    }

    // ── Built-in pattern engine ────────────────────────────────────────────────

    /**
     * Walks the cloned tree and applies the built-in patterns.
     *
     * @param deadlineNanos {@link System#nanoTime()} value at which to stop, or 0 for no limit.
     *                      Reading thousands of files is not instant on every filesystem, and an
     *                      unbounded walk is the one way this phase can overrun its budget.
     */
    public void runBuiltInStaticEngine(String sourcePath, List<Finding> findings, long deadlineNanos) {
        if (sourcePath == null || sourcePath.isBlank()) {
            return;
        }
        File dir = new File(sourcePath);
        if (!dir.isDirectory()) {
            return;
        }
        int processed = 0;
        try (Stream<Path> paths = Files.walk(dir.toPath(), 10)) {
            for (Path p : (Iterable<Path>) paths.filter(Files::isRegularFile)::iterator) {
                if (deadlineNanos > 0 && (++processed & 0xFF) == 0 && System.nanoTime() > deadlineNanos) {
                    log.warn("Built-in pattern scan stopped early after {} files to stay within the scan budget",
                            processed);
                    return;
                }
                scanFile(p, findings);
            }
        } catch (Exception e) {
            log.warn("Built-in scan error: {}", e.getMessage());
        }
    }

    private void scanFile(Path file, List<Finding> findings) {
        String name = file.getFileName().toString();
        // Skip lockfiles, minified bundles and vendored dependencies — they produce noise only.
        if (name.endsWith(".min.js") || name.endsWith(".map") || name.endsWith(".lock")
                || name.equals("package-lock.json") || name.endsWith(".d.ts")) {
            return;
        }
        if (!(name.endsWith(".ts") || name.endsWith(".tsx") || name.endsWith(".js")
                || name.endsWith(".jsx") || name.endsWith(".mjs") || name.endsWith(".cjs"))) {
            return;
        }
        if (isNoiseFile(file, name)) {
            return;
        }

        List<String> lines;
        try {
            lines = Files.readAllLines(file);
        } catch (Exception e) {
            return;
        }
        if (lines.size() > 20_000) {
            return;
        }

        String relPath = cleanPath(file.toString());
        if (relPath.length() > 400) {
            relPath = file.getFileName().toString();
        }

        Pattern secretPattern = Pattern.compile(
                "(?i)(API_KEY|SECRET|TOKEN|PASSWORD|PRIVATE_KEY|AUTH_TOKEN)\\s*[:=]\\s*['\"][A-Za-z0-9_\\-.]{10,}['\"]");
        Pattern innerHtmlPattern = Pattern.compile("\\.innerHTML\\s*=\\s*");
        Pattern evalPattern = Pattern.compile("\\beval\\s*\\(");
        Pattern postMsgPattern = Pattern.compile("postMessage\\s*\\([^,]+,\\s*['\"]\\*['\"]\\)");
        Pattern corsWildcard = Pattern.compile(
                "['\"]\\*['\"]\\s*\\)|Access-Control-Allow-Origin['\"]?\\s*[:,=]\\s*['\"]\\*['\"]");
        Pattern localStorageAuth = Pattern.compile(
                "localStorage\\.setItem\\(['\"][^'\"]*(?:token|auth|session|user|secret)[^'\"]*['\"]");

        for (int i = 0; i < lines.size(); i++) {
            String line = lines.get(i);
            String trimmed = line.trim();
            if (trimmed.startsWith("//") || trimmed.startsWith("*") || trimmed.startsWith("/*")) {
                continue;
            }
            int ln = i + 1;

            if (secretPattern.matcher(line).find() && !looksLikePlaceholder(line)) {
                add(findings, "Hardcoded Secret or API Credential in Source", Severity.CRITICAL,
                        FindingCategory.AUTHENTICATION, relPath, ln, trimmed,
                        "A credential appears to be hardcoded in source code.",
                        "Anyone with repository access can read the credential and use it directly against the backing service.",
                        "Move the value into a server-side environment variable or secret manager and rotate the exposed key.",
                        "CWE-798", 9.0);
            }
            if (innerHtmlPattern.matcher(line).find() && !line.contains("DOMPurify") && !line.contains("sanitize")) {
                add(findings, "Unsanitised innerHTML Assignment (XSS)", Severity.HIGH,
                        FindingCategory.INJECTION, relPath, ln, trimmed,
                        "innerHTML is assigned without sanitisation.",
                        "If the assigned value contains attacker-controlled data this is a stored or reflected XSS sink.",
                        "Use textContent for plain text, or DOMPurify.sanitize() before assigning markup.",
                        "CWE-79", 7.5);
            }
            if (evalPattern.matcher(line).find()) {
                add(findings, "Dynamic Code Execution via eval()", Severity.HIGH,
                        FindingCategory.INJECTION, relPath, ln, trimmed,
                        "eval() executes a string as code.",
                        "If any part of the string is user-influenced, this becomes arbitrary script execution in the browser.",
                        "Replace eval() with JSON.parse() or a structured parser.",
                        "CWE-95", 8.1);
            }
            if (postMsgPattern.matcher(line).find()) {
                add(findings, "postMessage Sent With Wildcard Target Origin", Severity.MEDIUM,
                        FindingCategory.CONFIGURATION, relPath, ln, trimmed,
                        "postMessage is sent with a '*' target origin.",
                        "Any cross-origin frame can receive the message, leaking data to embedded third parties.",
                        "Send to an explicit origin and verify event.origin in the receiver.",
                        "CWE-345", 5.3);
            }
            if (corsWildcard.matcher(line).find() && line.toLowerCase(Locale.ROOT).contains("origin")) {
                add(findings, "Permissive CORS Policy (Wildcard Origin)", Severity.HIGH,
                        FindingCategory.CORS, relPath, ln, trimmed,
                        "The CORS policy allows a wildcard origin.",
                        "A wildcard lets any website read authenticated responses from this origin.",
                        "Replace '*' with an explicit allow-list of trusted origins.",
                        "CWE-942", 7.2);
            }
            if (localStorageAuth.matcher(line).find()) {
                add(findings, "Sensitive Token Stored in localStorage", Severity.MEDIUM,
                        FindingCategory.INFORMATION_DISCLOSURE, relPath, ln, trimmed,
                        "Session or auth data is persisted in localStorage.",
                        "Any XSS on the page can read and exfiltrate it; localStorage is not encrypted.",
                        "Store session tokens in HttpOnly, Secure, SameSite cookies instead.",
                        "CWE-922", 5.9);
            }
        }
    }

    // ── Mapping helpers ────────────────────────────────────────────────────────

    /**
     * Test files and fixtures are full of deliberately fake secrets, env stubs and permissive
     * CORS literals. Treating them as real findings buries the report in noise — on this
     * repository that alone accounted for hundreds of bogus CRITICAL hits.
     */
    private boolean isNoiseFile(Path file, String name) {
        if (file.toString().contains("node_modules")) {
            return true;
        }
        if (name.contains(".test.") || name.contains(".spec.") || name.endsWith("Test.ts")
                || name.endsWith("Test.tsx") || name.endsWith("Tests.ts")) {
            return true;
        }
        String p = file.toString().replace('\\', '/').toLowerCase(Locale.ROOT);
        for (String marker : new String[]{"/test/", "/tests/", "/__tests__/", "/spec/", "/specs/",
                "/e2e/", "/fixtures/", "/__mocks__/", "/mocks/", "/examples/", "/example/",
                "/scripts/", "/docs/"}) {
            if (p.contains(marker)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Rejects obvious stand-ins that are not real credentials. Without this, literals such as
     * {@code 'test-token'} or {@code 'changeme'} are reported as leaked production secrets.
     */
    private boolean looksLikePlaceholder(String line) {
        String l = line.toLowerCase(Locale.ROOT);
        for (String marker : new String[]{"test", "example", "placeholder", "changeme", "change-me",
                "dummy", "fake", "sample", "your-", "your_", "xxx", "todo", "fixme", "mock",
                "redacted", "not-a-real", "localhost"}) {
            if (l.contains(marker)) {
                return true;
            }
        }
        // process.env.X = '...' is test bootstrap, not a hardcoded secret.
        if (l.contains("process.env.")) {
            return true;
        }
        return false;
    }

    private void add(List<Finding> findings, String title, Severity severity, FindingCategory category,
                     String filePath, int line, String evidence, String description, String impact,
                     String recommendation, String cwe, double cvss) {
        Finding f = new Finding();
        f.setTitle(title);
        f.setSeverity(severity);
        f.setCategory(category);
        f.setSource("Static Analysis");
        f.setScanner("WORLDGUARD_SAST");
        f.setFilePath(filePath);
        f.setLineNumber(line);
        f.setEvidence(evidence);
        f.setDescription(description);
        f.setWhatIsTheIssue(description);
        f.setWhyDoesItMatter(impact);
        f.setImpact(impact);
        f.setRecommendation(recommendation);
        f.setReproductionSteps("Open " + filePath + " at line " + line + ".");
        f.setCwe(cwe);
        f.setCvssScore(cvss);
        f.setTarget(GITHUB_REPO);
        f.setStatus(com.sih.securityplatform.model.FindingStatus.POTENTIAL);
        findings.add(f);
    }

    private String humanTitle(String ruleId, String message) {
        String[] parts = ruleId.split("\\.");
        String tail = parts[parts.length - 1].replace('-', ' ').replace('_', ' ').trim();
        String title = "Potential " + Character.toUpperCase(tail.charAt(0)) + tail.substring(1);
        return title.length() > 110 ? title.substring(0, 110) : title;
    }

    private Severity severity(String sev) {
        if (sev.contains("ERROR") || sev.contains("CRIT")) return Severity.HIGH;
        if (sev.contains("WARN") || sev.contains("MED")) return Severity.MEDIUM;
        if (sev.contains("LOW")) return Severity.LOW;
        return Severity.INFO;
    }

    private FindingCategory category(String ruleId, String message) {
        String c = (ruleId + " " + message).toLowerCase(Locale.ROOT);
        if (c.contains("cors") || c.contains("origin")) return FindingCategory.CORS;
        if (c.contains("xss") || c.contains("inject") || c.contains("innerhtml") || c.contains("sanitiz")) {
            return FindingCategory.INJECTION;
        }
        if (c.contains("ssrf")) return FindingCategory.SSRF;
        if (c.contains("secret") || c.contains("credential") || c.contains("hardcoded") || c.contains("token")) {
            return FindingCategory.AUTHENTICATION;
        }
        if (c.contains("header") || c.contains("csp")) return FindingCategory.SECURITY_HEADERS;
        if (c.contains("tls") || c.contains("ssl") || c.contains("crypto")) return FindingCategory.CRYPTOGRAPHY;
        if (c.contains("path") || c.contains("traversal") || c.contains("lfi")) return FindingCategory.INJECTION;
        return FindingCategory.CODE_QUALITY;
    }

    private String cwe(JsonNode metadata, String ruleId, String message) {
        JsonNode cweNode = metadata.path("cwe");
        if (cweNode.isArray() && cweNode.size() > 0) {
            return cweNode.get(0).asText();
        }
        if (cweNode.isTextual() && !cweNode.asText().isBlank()) {
            return cweNode.asText();
        }
        String c = (ruleId + " " + message).toLowerCase(Locale.ROOT);
        if (c.contains("secret") || c.contains("credential")) return "CWE-798";
        if (c.contains("xss") || c.contains("innerhtml")) return "CWE-79";
        if (c.contains("cors")) return "CWE-942";
        if (c.contains("ssrf")) return "CWE-918";
        if (c.contains("eval")) return "CWE-95";
        if (c.contains("sql")) return "CWE-89";
        return "CWE-1035";
    }

    private double cvss(Severity s) {
        return switch (s) {
            case CRITICAL -> 9.1;
            case HIGH -> 7.5;
            case MEDIUM -> 5.5;
            case LOW -> 3.1;
            default -> 1.0;
        };
    }

    /**
     * Turns an absolute path inside a temporary clone into a repository-relative one.
     *
     * <p>The clone lives in a temp directory with a random name, so simply searching for the
     * repository name does not work. Everything after the clone root is what a developer needs
     * to act on, so the path is trimmed to the repository layout.
     */
    private String cleanPath(String path) {
        if (path == null) {
            return "";
        }
        String p = path.replace('\\', '/');

        // Prefer a known marker inside the repository.
        int idx = p.indexOf("worldmonitor/");
        if (idx >= 0) {
            return p.substring(idx + "worldmonitor/".length());
        }

        // Otherwise strip any temporary clone root, e.g.
        // /tmp/worldguard_sast_1234/api/_cors.js -> api/_cors.js
        int clone = p.indexOf("worldguard_sast_");
        if (clone >= 0) {
            int rest = clone + "worldguard_sast_".length();
            int slash = p.indexOf('/', rest);
            return slash >= 0 ? p.substring(slash + 1) : p.substring(rest);
        }
        int wm = p.indexOf("/wm_sast_");
        if (wm >= 0) {
            int rest = wm + "/wm_sast_".length();
            int slash = p.indexOf('/', rest);
            return slash >= 0 ? p.substring(slash + 1) : p.substring(rest);
        }

        // Last resort: keep the last two path segments.
        String[] parts = p.split("/");
        return parts.length <= 2 ? p : parts[parts.length - 2] + "/" + parts[parts.length - 1];
    }

    private void deleteQuietly(File dir) {
        try {
            File[] files = dir.listFiles();
            if (files != null) {
                for (File f : files) {
                    if (f.isDirectory()) {
                        deleteQuietly(f);
                    } else {
                        f.delete();
                    }
                }
            }
            dir.delete();
        } catch (Exception ignored) {
            // Temp clone cleanup is best-effort.
        }
    }
}
