package com.threatlens.detection;

import com.threatlens.domain.SecurityEvent;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A rule hit before it becomes a persisted {@code Alert}.
 *
 * @param groupKey      entity the rule grouped on (e.g. "10.0.5.66->FIN-SRV01"); part of the fingerprint
 * @param baseScore     rule's inherent risk, 0-100, before contextual scoring
 * @param ruleFactors   rule-specific score adjustments, e.g. {"officeParent": 15}
 */
public record Detection(
        String ruleId,
        String title,
        String description,
        MitreTechnique technique,
        int baseScore,
        String groupKey,
        String srcIp,
        String dstIp,
        String host,
        String username,
        List<SecurityEvent> events,
        Map<String, Object> evidence,
        Map<String, Integer> ruleFactors) {

    public Instant firstSeen() {
        return events.getFirst().getEventTime();
    }

    public Instant lastSeen() {
        return events.getLast().getEventTime();
    }

    public String fingerprint() {
        return ruleId + "|" + groupKey + "|" + firstSeen().getEpochSecond();
    }

    public static Builder builder(DetectionRule rule) {
        return new Builder(rule);
    }

    public static final class Builder {
        private final DetectionRule rule;
        private String title, description, groupKey, srcIp, dstIp, host, username;
        private MitreTechnique technique;
        private int baseScore;
        private List<SecurityEvent> events = List.of();
        private final Map<String, Object> evidence = new LinkedHashMap<>();
        private final Map<String, Integer> ruleFactors = new LinkedHashMap<>();

        private Builder(DetectionRule rule) {
            this.rule = rule;
            this.technique = rule.technique();
            this.baseScore = rule.baseScore();
            this.title = rule.name();
        }

        public Builder title(String v) { title = v; return this; }
        public Builder description(String v) { description = v; return this; }
        public Builder technique(MitreTechnique v) { technique = v; return this; }
        public Builder baseScore(int v) { baseScore = v; return this; }
        public Builder groupKey(String v) { groupKey = v; return this; }
        public Builder srcIp(String v) { srcIp = v; return this; }
        public Builder dstIp(String v) { dstIp = v; return this; }
        public Builder host(String v) { host = v; return this; }
        public Builder username(String v) { username = v; return this; }
        public Builder events(List<SecurityEvent> v) { events = List.copyOf(v); return this; }
        public Builder evidence(String k, Object v) { evidence.put(k, v); return this; }
        public Builder factor(String k, int v) { ruleFactors.put(k, v); return this; }

        public Detection build() {
            if (events.isEmpty()) throw new IllegalStateException("detection needs evidence events");
            return new Detection(rule.id(), title, description, technique, baseScore, groupKey,
                    srcIp, dstIp, host, username, events, evidence, ruleFactors);
        }
    }
}
