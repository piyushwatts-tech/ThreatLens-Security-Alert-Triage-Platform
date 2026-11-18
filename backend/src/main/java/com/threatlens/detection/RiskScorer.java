package com.threatlens.detection;

import com.threatlens.config.ThreatLensProperties;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Explainable risk scoring. Each alert stores the factors that produced its
 * score, so an analyst can see *why* something is CRITICAL.
 *
 * <pre>
 * risk = rule base score
 *      + rule-specific factors (Office parent, privileged account, ...)
 *      + volume       (up to +5, log-scaled event count)
 *      + criticalAsset (+10 if a crown-jewel host/IP is involved)
 *      + mlAnomaly    (+5 / +10 when the ML model agrees it is anomalous)
 *      + correlation  (+10 if the same entity has alerts from other rules in 24h)
 * clamped to 0..100, then banded into LOW / MEDIUM / HIGH / CRITICAL.
 * </pre>
 */
@Component
public class RiskScorer {

    private final Set<String> criticalAssets;

    public RiskScorer(ThreatLensProperties props) {
        this.criticalAssets = props.criticalAssets().stream()
                .map(s -> s.trim().toUpperCase(Locale.ROOT)).collect(Collectors.toSet());
    }

    public Map<String, Integer> factors(Detection d, Double anomalyScore) {
        Map<String, Integer> f = new LinkedHashMap<>();
        f.put("base", d.baseScore());
        d.ruleFactors().forEach((k, v) -> { if (v != 0) f.put(k, v); });
        int volume = (int) Math.min(5, Math.round(2 * Math.log10(Math.max(1, d.events().size()))));
        if (volume > 0) f.put("volume", volume);
        if (isCritical(d.host()) || isCritical(d.dstIp())) f.put("criticalAsset", 10);
        if (anomalyScore != null) {
            if (anomalyScore >= 0.7) f.put("mlAnomaly", 10);
            else if (anomalyScore >= 0.5) f.put("mlAnomaly", 5);
        }
        return f;
    }

    public static int total(Map<String, Integer> factors) {
        int sum = factors.values().stream().mapToInt(Integer::intValue).sum();
        return Math.max(0, Math.min(100, sum));
    }

    private boolean isCritical(String asset) {
        return asset != null && criticalAssets.contains(asset.toUpperCase(Locale.ROOT));
    }
}
