package com.sih.securityplatform.service;

import com.sih.securityplatform.model.Finding;
import com.sih.securityplatform.model.FindingStatus;
import com.sih.securityplatform.model.Scan;
import com.sih.securityplatform.model.Severity;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * Computes the 0-100 security score and the per-severity / per-status counters.
 *
 * <p>The score has to stay meaningful on a large codebase, so it is derived from weighted
 * <em>risk points</em> run through a saturating curve rather than a linear subtraction.
 *
 * <p>Two properties matter:
 * <ul>
 *   <li><b>Confidence dominates.</b> A confirmed critical costs ~10x an unconfirmed static
 *       pattern match of the same severity, so a noisy rule set cannot masquerade as a breach.</li>
 *   <li><b>It saturates instead of clipping.</b> Deductions follow a diminishing curve, so the
 *       difference between 2 and 4 confirmed criticals is visible, and a long tail of low-value
 *       matches cannot pin the score at exactly 0 and hide everything else.</li>
 * </ul>
 */
@Service
public class RiskScoringService {

    /** Risk weight per severity. */
    private static final double[] SEVERITY_WEIGHT = {
            /*CRITICAL*/ 25.0,
            /*HIGH*/     12.0,
            /*MEDIUM*/    5.0,
            /*LOW*/       1.5,
            /*INFO*/      0.2,
            /*UNKNOWN*/   0.5,
    };

    /** Multiplier per confidence level. Unconfirmed static matches are deliberately cheap. */
    private static final double[] CONFIDENCE_WEIGHT = {
            /*VERIFIED*/               1.00,
            /*NEEDS_REVIEW*/           0.35,
            /*POTENTIAL*/              0.10,
    };

    /**
     * Risk points at which the score has decayed to ~37% of full marks. Tuned so the scale stays
     * readable across the whole range: a single confirmed high-severity issue lands in the 80s,
     * a handful lands in the 40-60s, and only a genuinely bad posture reaches the bottom.
     */
    private static final double HALF_LIFE_POINTS = 45.0;

    /** Below this many points the score is effectively clean. */
    private static final double FLOOR = 2.0;

    private static int severityIndex(Severity s) {
        if (s == null) {
            return 5;
        }
        return switch (s) {
            case CRITICAL -> 0;
            case HIGH -> 1;
            case MEDIUM -> 2;
            case LOW -> 3;
            case INFO -> 4;
            case UNKNOWN -> 5;
        };
    }

    private static int confidenceIndex(FindingStatus s) {
        if (s == null) {
            return 2;
        }
        return switch (s) {
            case VERIFIED -> 0;
            case NEEDS_REVIEW, EXTERNAL_INTELLIGENCE -> 1;
            default -> 2; // POTENTIAL, INFORMATIONAL, FALSE_POSITIVE
        };
    }

    /** Risk points contributed by a single confirmed finding. */
    static double riskPoints(Severity severity, FindingStatus status) {
        if (status == FindingStatus.FALSE_POSITIVE || status == FindingStatus.INFORMATIONAL) {
            return 0;
        }
        return SEVERITY_WEIGHT[severityIndex(severity)] * CONFIDENCE_WEIGHT[confidenceIndex(status)];
    }

    /**
     * Multiplier applied to the n-th unconfirmed finding of a given severity (1-based).
     *
     * <p>Without this, a rule that matches one pattern forty times outweighs a handful of
     * confirmed breaches. That is backwards: forty hits from one unconfirmed pattern are mostly
     * the same underlying weakness observed repeatedly, not forty independent risks. Confirmed
     * findings are never discounted, because each one really is a separate problem.
     */
    private static double unconfirmedRepeatFactor(int ordinalForSeverity) {
        if (ordinalForSeverity <= 1) {
            return 1.0;
        }
        if (ordinalForSeverity <= 3) {
            return 0.35;
        }
        if (ordinalForSeverity <= 10) {
            return 0.12;
        }
        return 0.04;
    }

    public void calculateAndApplyStats(Scan scan, List<Finding> findings) {
        int crit = 0, high = 0, med = 0, low = 0, info = 0;
        int verified = 0, needsReview = 0, potential = 0, informational = 0;
        double points = 0;

        // Counts unconfirmed findings per severity so repeats can be discounted.
        int[] unconfirmedSeen = new int[SEVERITY_WEIGHT.length];

        if (findings != null) {
            for (Finding f : findings) {
                if (f == null) {
                    continue;
                }
                // Count severity. UNKNOWN is folded into INFO so the buckets always sum to the
                // total rather than silently losing a finding.
                Severity sev = f.getSeverity() == null ? Severity.UNKNOWN : f.getSeverity();
                switch (sev) {
                    case CRITICAL -> crit++;
                    case HIGH -> high++;
                    case MEDIUM -> med++;
                    case LOW -> low++;
                    default -> info++; // INFO + UNKNOWN
                }

                FindingStatus st = f.getStatus() == null ? FindingStatus.POTENTIAL : f.getStatus();
                switch (st) {
                    case VERIFIED -> verified++;
                    case NEEDS_REVIEW, EXTERNAL_INTELLIGENCE -> needsReview++;
                    case POTENTIAL -> potential++;
                    case INFORMATIONAL, FALSE_POSITIVE -> informational++;
                }

                int sevIdx = severityIndex(sev);
                if (st == FindingStatus.VERIFIED) {
                    points += riskPoints(sev, st);
                } else if (st != FindingStatus.FALSE_POSITIVE && st != FindingStatus.INFORMATIONAL) {
                    unconfirmedSeen[sevIdx]++;
                    points += riskPoints(sev, st) * unconfirmedRepeatFactor(unconfirmedSeen[sevIdx]);
                }
            }
        }

        scan.setSecurityScore(scoreFor(points));

        scan.setCriticalCount(crit);
        scan.setHighCount(high);
        scan.setMediumCount(med);
        scan.setLowCount(low);
        scan.setInfoCount(info);

        scan.setVerifiedCount(verified);
        scan.setNeedsReviewCount(needsReview);
        scan.setPotentialCount(potential);
        scan.setInformationalCount(informational);
    }

    /**
     * Maps risk points onto 0-100. Diminishing returns keep the scale readable: each additional
     * confirmed critical moves the score less than the one before it, but it never quite stops
     * registering, so an extreme result is still visibly worse than a merely bad one.
     */
    static int scoreFor(double points) {
        if (points <= FLOOR) {
            return 100;
        }
        int score = (int) Math.round(100.0 * Math.exp(-(points - FLOOR) / HALF_LIFE_POINTS));
        return Math.max(0, Math.min(100, score));
    }
}
