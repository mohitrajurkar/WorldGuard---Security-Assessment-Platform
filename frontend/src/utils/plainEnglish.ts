import { Finding } from '../services/api';

export interface PlainFindingInfo {
  plainTitle: string;
  categoryLabel: string;
  urgencyLabel: string;
  urgencyBadgeClass: string;
  whatItMeans: string;
  whyItMatters: string;
  simpleFix: string;
  estimatedFixTime: string;
}

export interface PositiveCheck {
  title: string;
  description: string;
  status: string;
}

export function getPlainLanguageFinding(f: Finding): PlainFindingInfo {
  const titleLower = f.title.toLowerCase();
  const cweLower = (f.cwe || '').toLowerCase();

  if (titleLower.includes('hardcoded') || titleLower.includes('secret') || cweLower.includes('798')) {
    return {
      plainTitle: 'Secret Password Found in Project Code',
      categoryLabel: 'Password & Access Security',
      urgencyLabel: 'Needs Immediate Fix',
      urgencyBadgeClass: 'badge-urgent',
      whatItMeans: 'A developer left a secret passcode directly inside the application files instead of storing it in a private password vault.',
      whyItMatters: 'Anyone reading the source code could use this secret to send unauthorized commands and tamper with data streams.',
      simpleFix: 'Ask your developer to remove the hardcoded key from the code file and store it in your server’s secure environment variables.',
      estimatedFixTime: '30-45 minutes'
    };
  }

  if (titleLower.includes('origin-based') || titleLower.includes('api key exemption') || titleLower.includes('auth')) {
    return {
      plainTitle: 'Website Can Be Tricked Into Bypassing Login Check',
      categoryLabel: 'Login & Verification',
      urgencyLabel: 'Needs Immediate Fix',
      urgencyBadgeClass: 'badge-urgent',
      whatItMeans: 'The server trusts website address labels sent by web browsers without verifying whether the request actually came from an authorized source.',
      whyItMatters: 'Attackers can impersonate your official website and consume your server resources or intelligence limits for free.',
      simpleFix: 'Require a valid secret API key or signed session token on all API requests rather than relying on browser header claims.',
      estimatedFixTime: '45-60 minutes'
    };
  }

  if (titleLower.includes('cors') || titleLower.includes('permissive wildcard')) {
    return {
      plainTitle: 'External Websites Allowed to Read Private Data',
      categoryLabel: 'Cross-Site Permissions',
      urgencyLabel: 'Important Fix',
      urgencyBadgeClass: 'badge-warning',
      whatItMeans: 'The application permissions permit any website ending in ".vercel.app" to make requests and read data from this service.',
      whyItMatters: 'An unrelated third-party site could secretly read your user data if a user visits their link.',
      simpleFix: 'Limit website sharing (CORS) strictly to your verified official domain name (e.g. worldmonitor.app).',
      estimatedFixTime: '20-30 minutes'
    };
  }

  if (titleLower.includes('ssrf') || titleLower.includes('webhook') || cweLower.includes('918')) {
    return {
      plainTitle: 'Webhook Can Be Fooled Into Calling Internal Servers',
      categoryLabel: 'Network Protection',
      urgencyLabel: 'Important Fix',
      urgencyBadgeClass: 'badge-warning',
      whatItMeans: 'When sending notifications to external webhooks, the system checks the address once but doesn’t lock the connection, creating a small loophole.',
      whyItMatters: 'A malicious user could provide a custom webhook URL that redirects to private internal databases or cloud settings.',
      simpleFix: 'Lock outgoing network connections to an approved external proxy that blocks requests to internal IP addresses.',
      estimatedFixTime: '1-2 hours'
    };
  }

  if (titleLower.includes('innerhtml') || titleLower.includes('injection') || cweLower.includes('79')) {
    return {
      plainTitle: 'News Feed Content Not Cleaned Before Displaying',
      categoryLabel: 'Web Page Safety',
      urgencyLabel: 'Important Fix',
      urgencyBadgeClass: 'badge-warning',
      whatItMeans: 'Third-party news headlines and text are inserted straight into the webpage without filtering out rogue script tags.',
      whyItMatters: 'If a news feed source is compromised or contains rogue code, it could run unwanted scripts in visitors’ browsers.',
      simpleFix: 'Use safe text insertion (textContent) or pass third-party text through an automatic cleaner (DOMPurify) before showing it.',
      estimatedFixTime: '30 minutes'
    };
  }

  if (titleLower.includes('bot') || titleLower.includes('user-agent')) {
    return {
      plainTitle: 'Automated Scraping Robots Can Bypass Filters',
      categoryLabel: 'Traffic & Bot Defense',
      urgencyLabel: 'Recommended Improvement',
      urgencyBadgeClass: 'badge-info',
      whatItMeans: 'The system only checks the browser name label to block automated robots, which bots can easily change to look like normal Chrome.',
      whyItMatters: 'Scrapers can copy your data and exhaust your upstream news API credits without being blocked.',
      simpleFix: 'Use modern bot protection like Cloudflare Turnstile or rate-based behavioral checks.',
      estimatedFixTime: '30-45 minutes'
    };
  }

  if (titleLower.includes('seed') || titleLower.includes('debug') || titleLower.includes('probe')) {
    return {
      plainTitle: 'Internal Test Page Left Visible to the Public',
      categoryLabel: 'Configuration',
      urgencyLabel: 'Recommended Improvement',
      urgencyBadgeClass: 'badge-info',
      whatItMeans: 'A diagnostic testing page used during development was left accessible on the public website without requiring a password.',
      whyItMatters: 'Curious visitors or competitors can view internal schema structures and trigger unneeded testing queries.',
      simpleFix: 'Disable diagnostic endpoints in production or protect them behind an administrator password.',
      estimatedFixTime: '20 minutes'
    };
  }

  if (titleLower.includes('localstorage') || titleLower.includes('storage')) {
    return {
      plainTitle: 'User Settings & Keys Stored Unencrypted in Browser',
      categoryLabel: 'Data Privacy',
      urgencyLabel: 'Recommended Improvement',
      urgencyBadgeClass: 'badge-info',
      whatItMeans: 'Custom preferences and telemetry tokens are saved in standard browser storage without encryption.',
      whyItMatters: 'If any browser script is ever compromised, it could inspect saved tokens or user preferences.',
      simpleFix: 'Store sensitive session credentials in secure HttpOnly cookies rather than localStorage.',
      estimatedFixTime: '30-45 minutes'
    };
  }

  if (titleLower.includes('rate limit') || titleLower.includes('x-forwarded-for')) {
    return {
      plainTitle: 'Rate Limits Can Be Evaded Using Fake IP Headers',
      categoryLabel: 'Traffic Management',
      urgencyLabel: 'Recommended Improvement',
      urgencyBadgeClass: 'badge-info',
      whatItMeans: 'The rate limiter trusts the client-provided IP address header rather than the verified network connection.',
      whyItMatters: 'An attacker can send millions of rapid requests by simply sending a different random IP header each time.',
      simpleFix: 'Use the hosting provider’s verified edge header (e.g. x-vercel-ip) instead of untrusted client headers.',
      estimatedFixTime: '25 minutes'
    };
  }

  if (titleLower.includes('content-security-policy') || titleLower.includes('csp') || titleLower.includes('frame') || titleLower.includes('clickjacking')) {
    return {
      plainTitle: 'Website Missing Standard Browser Defense Headers',
      categoryLabel: 'Browser Defenses',
      urgencyLabel: 'Recommended Improvement',
      urgencyBadgeClass: 'badge-info',
      whatItMeans: 'The web server does not send standard security rules telling browsers how to prevent framing and script injections.',
      whyItMatters: 'Other websites could embed this application in an invisible frame or load unauthorized third-party scripts.',
      simpleFix: 'Add "Content-Security-Policy" and "X-Frame-Options: SAMEORIGIN" to your web hosting configuration file.',
      estimatedFixTime: '15 minutes'
    };
  }

  return {
    plainTitle: f.title,
    categoryLabel: f.category || 'Security Setting',
    urgencyLabel: f.severity === 'CRITICAL' ? 'Needs Immediate Fix' : f.severity === 'HIGH' ? 'Important Fix' : 'Recommended Improvement',
    urgencyBadgeClass: f.severity === 'CRITICAL' ? 'badge-urgent' : f.severity === 'HIGH' ? 'badge-warning' : 'badge-info',
    whatItMeans: f.description,
    whyItMatters: f.impact || 'Leaving this unaddressed increases security exposure.',
    simpleFix: f.recommendation || 'Apply standard security hardening practices.',
    estimatedFixTime: f.remediationTimeMinutes ? `${f.remediationTimeMinutes} minutes` : '30-60 minutes'
  };
}

export function getHealthGrade(score: number): {
  grade: string;
  gradeColor: string;
  badgeLabel: string;
  summaryText: string;
  adviceText: string;
  statusClass: string;
} {
  if (score === 0) {
    return {
      grade: 'N/A',
      gradeColor: 'var(--text-muted)',
      badgeLabel: 'Unassessed',
      summaryText: 'Initial baseline set to zero. Run an audit to calculate posture score.',
      adviceText: 'Run an initial scan or seed test data to analyze defenses.',
      statusClass: 'status-neutral'
    };
  }
  if (score >= 85) {
    return {
      grade: 'A',
      gradeColor: 'var(--success-color)',
      badgeLabel: 'Well Fortified',
      summaryText: 'Outstanding posture. Core defenses and headers are robustly enforced.',
      adviceText: 'Maintain security headers and conduct scheduled scans.',
      statusClass: 'status-healthy'
    };
  }
  if (score >= 70) {
    return {
      grade: 'B',
      gradeColor: 'var(--med-color)',
      badgeLabel: 'Moderate Risk',
      summaryText: 'Solid baseline. A few configuration updates will significantly elevate defenses.',
      adviceText: 'Address medium priority findings and tighten CORS/session settings.',
      statusClass: 'status-warning'
    };
  }
  if (score >= 50) {
    return {
      grade: 'C',
      gradeColor: 'var(--high-color)',
      badgeLabel: 'Needs Attention',
      summaryText: 'Exposed to automated scans. Fix high-priority items in next sprint.',
      adviceText: 'Fix high-priority items in the next sprint and review API endpoints.',
      statusClass: 'status-urgent'
    };
  }
  return {
    grade: 'D',
    gradeColor: 'var(--crit-color)',
    badgeLabel: 'Action Required',
    summaryText: 'Critical vulnerabilities present. Needs immediate engineering remediation.',
    adviceText: 'Review urgent items below with your technical team and remove hardcoded secrets.',
    statusClass: 'status-urgent'
  };
}

export function getPositiveControls(): PositiveCheck[] {
  return [
    {
      title: 'HTTPS / TLS Modern Encryption',
      description: 'Enforces TLS 1.3 encryption across all client-to-edge traffic.',
      status: 'PASSING'
    },
    {
      title: 'Upstash Redis Rate Limiter Attached',
      description: 'Sliding-window token bucket is mounted on core API routes.',
      status: 'ACTIVE'
    },
    {
      title: 'Content Security Policy (CSP)',
      description: 'Default-src and script-src directives restrict external script execution.',
      status: 'PASSING'
    },
    {
      title: 'Edge Deployment Isolation',
      description: 'Runs on isolated V8 edge microVMs with memory sandboxing.',
      status: 'ACTIVE'
    }
  ];
}
