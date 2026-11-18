package com.threatlens.detection;

import com.threatlens.config.ThreatLensProperties;
import com.threatlens.detection.rules.LogonBruteForceRule;
import com.threatlens.domain.Severity;
import com.threatlens.domain.SecurityEvent;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class RiskScorerTest {

    private final RiskScorer scorer = new RiskScorer(new ThreatLensProperties(null, null, List.of(), List.of("DC01")));

    private Detection bruteForceOn(String host) {
        List<SecurityEvent> evs = new ArrayList<>();
        for (int i = 0; i < 10; i++) evs.add(TestEvents.logon(i, false, "10.0.0.9", "bob", host));
        return new LogonBruteForceRule().evaluate(evs).getFirst();
    }

    @Test
    void criticalAssetAndMlRaiseScore_andFactorsExplainIt() {
        Map<String, Integer> plain = scorer.factors(bruteForceOn("WKS1"), null);
        Map<String, Integer> crown = scorer.factors(bruteForceOn("DC01"), 0.9);
        assertThat(crown).containsEntry("criticalAsset", 10).containsEntry("mlAnomaly", 10);
        assertThat(RiskScorer.total(crown)).isEqualTo(RiskScorer.total(plain) + 20);
    }

    @Test
    void scoreIsClampedAndBanded() {
        assertThat(RiskScorer.total(Map.of("base", 95, "x", 30))).isEqualTo(100);
        assertThat(Severity.fromScore(100)).isEqualTo(Severity.CRITICAL);
        assertThat(Severity.fromScore(70)).isEqualTo(Severity.HIGH);
        assertThat(Severity.fromScore(45)).isEqualTo(Severity.MEDIUM);
        assertThat(Severity.fromScore(44)).isEqualTo(Severity.LOW);
    }
}
