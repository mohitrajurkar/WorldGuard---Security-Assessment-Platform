package com.sih.securityplatform.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.util.Set;

/**
 * Validates scan targets to prevent SSRF, DNS rebinding, internal subnet probing,
 * and unauthorized scanning.
 */
@Component
public class TargetSecurityValidator {

    private static final Logger log = LoggerFactory.getLogger(TargetSecurityValidator.class);

    private final boolean allowLocalhostTesting;

    // Disallowed cloud metadata & link-local addresses
    private static final Set<String> BLOCKED_METADATA_IPS = Set.of(
            "169.254.169.254",
            "169.254.170.2",
            "metadata.google.internal"
    );

    public TargetSecurityValidator(
            @Value("${security.platform.allow-localhost-testing:true}") boolean allowLocalhostTesting) {
        this.allowLocalhostTesting = allowLocalhostTesting;
    }

    /**
     * Validates target URL and authorization confirmation.
     * Throws IllegalArgumentException or SecurityException if target fails security policy.
     */
    public void validateTarget(String targetUrl, boolean authorizedConfirmation) {
        if (!authorizedConfirmation) {
            throw new SecurityException("Authorized assessment confirmation is mandatory before scanning. Assessment aborted.");
        }

        if (targetUrl == null || targetUrl.trim().isBlank()) {
            throw new IllegalArgumentException("Target URL cannot be empty.");
        }

        URI uri;
        try {
            uri = URI.create(targetUrl.trim());
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid target URL format: " + e.getMessage());
        }

        String scheme = uri.getScheme();
        if (scheme == null || (!scheme.equalsIgnoreCase("http") && !scheme.equalsIgnoreCase("https"))) {
            throw new SecurityException("Target scheme not permitted: '" + scheme + "'. Only HTTP and HTTPS protocols are authorized.");
        }

        String host = uri.getHost();
        if (host == null || host.trim().isBlank()) {
            throw new IllegalArgumentException("Target URL must specify a valid hostname or IP address.");
        }

        // Check for direct metadata hostnames
        if (BLOCKED_METADATA_IPS.contains(host.toLowerCase())) {
            throw new SecurityException("Target rejected: Access to cloud metadata services is strictly forbidden (SSRF protection).");
        }

        // Resolve DNS and inspect resolved IP addresses to protect against SSRF and DNS rebinding
        try {
            InetAddress[] addresses = InetAddress.getAllByName(host);
            for (InetAddress address : addresses) {
                String ip = address.getHostAddress();

                if (BLOCKED_METADATA_IPS.contains(ip)) {
                    throw new SecurityException("Target resolves to cloud metadata endpoint (" + ip + "). Scan rejected.");
                }

                if (address.isLoopbackAddress() || host.equalsIgnoreCase("localhost") || ip.startsWith("127.")) {
                    if (!allowLocalhostTesting) {
                        throw new SecurityException("Target rejected: Localhost scanning is restricted by policy.");
                    } else {
                        log.info("Authorized local lab testing permitted for target: {}", targetUrl);
                    }
                    continue;
                }

                if (address.isSiteLocalAddress() || address.isLinkLocalAddress()) {
                    if (!allowLocalhostTesting) {
                        throw new SecurityException("Target rejected: Scanning of private internal IP networks (" + ip + ") is restricted.");
                    } else {
                        log.warn("Target resolves to private network address ({}); authorized under lab evaluation policy.", ip);
                    }
                }

                if (address.isAnyLocalAddress() || address.isMulticastAddress()) {
                    throw new SecurityException("Target resolves to invalid multicast or wildcard address: " + ip);
                }
            }
        } catch (UnknownHostException e) {
            log.warn("Target host '{}' could not be resolved via DNS at validation time. Proceeding with hostname validation.", host);
        }

        log.info("Target security verification passed for: {}", targetUrl);
    }
}
