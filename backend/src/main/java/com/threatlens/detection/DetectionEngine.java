package com.threatlens.detection;

import com.threatlens.alert.AlertService;
import com.threatlens.domain.EventType;
import com.threatlens.domain.SecurityEvent;
import com.threatlens.ml.MlClient;
import com.threatlens.repo.AlertRepository;
import com.threatlens.repo.SecurityEventRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Runs every rule over a time range, enriches hits with the ML anomaly score,
 * adds ML-only detections, de-duplicates by fingerprint and hands the result
 * to {@link AlertService} for scoring and persistence.
 */
@Service
public class DetectionEngine {

    private static final Logger log = LoggerFactory.getLogger(DetectionEngine.class);
    private static final int ML_BATCH = 5_000;

    private final List<DetectionRule> rules;
    private final MlAnomalyRule mlRule = new MlAnomalyRule();
    private final SecurityEventRepository events;
    private final AlertRepository alerts;
    private final AlertService alertService;
    private final MlClient ml;

    public DetectionEngine(List<DetectionRule> rules, SecurityEventRepository events, AlertRepository alerts,
                           AlertService alertService, MlClient ml) {
        this.rules = rules.stream().sorted(Comparator.comparing(DetectionRule::id)).toList();
        this.events = events;
        this.alerts = alerts;
        this.alertService = alertService;
        this.ml = ml;
    }

    public record RunResult(int rulesEvaluated, int eventsScanned, int detections, int alertsCreated,
                            int duplicatesSkipped, boolean mlAvailable, int mlAnomalousFlows, long durationMs) {}

    public List<DetectionRule> catalog() {
        List<DetectionRule> all = new ArrayList<>(rules);
        all.add(mlRule);
        return all;
    }

    public RunResult run(Instant from, Instant to) {
        long t0 = System.currentTimeMillis();
        Map<String, List<SecurityEvent>> cache = new HashMap<>();
        Set<Long> scanned = new HashSet<>();
        List<Detection> found = new ArrayList<>();

        for (DetectionRule rule : rules) {
            List<SecurityEvent> evs = load(cache, rule.eventTypes(), from.minus(rule.lookback()), to);
            evs.forEach(e -> scanned.add(e.getId()));
            try {
                rule.evaluate(evs).stream().filter(d -> !d.lastSeen().isBefore(from)).forEach(found::add);
            } catch (RuntimeException ex) {
                log.error("Rule {} failed", rule.id(), ex);  // one broken rule must not stop the others
            }
        }

        // ---- ML stage: score flows, enrich rule hits, find what rules missed
        Map<Long, Double> scores = new HashMap<>();
        boolean mlUp = false;
        double threshold = 0.5;
        List<SecurityEvent> flows = load(cache, Set.of(EventType.NETWORK_FLOW), from, to);
        flows.forEach(e -> scanned.add(e.getId()));
        if (!flows.isEmpty()) {
            mlUp = true;
            for (int i = 0; i < flows.size() && mlUp; i += ML_BATCH) {
                List<SecurityEvent> chunk = flows.subList(i, Math.min(flows.size(), i + ML_BATCH));
                MlClient.ScoreResponse r = ml.score(chunk.stream().map(DetectionEngine::features).toList());
                if (r == null || r.scores() == null || r.scores().size() != chunk.size()) {
                    mlUp = false;
                    break;
                }
                threshold = r.threshold();
                for (int k = 0; k < chunk.size(); k++) scores.put(chunk.get(k).getId(), r.scores().get(k));
            }
        }
        int anomalous = 0;
        if (mlUp) {
            Set<Long> explained = found.stream().flatMap(d -> d.events().stream()).map(SecurityEvent::getId)
                    .collect(Collectors.toSet());
            final double th = threshold;
            List<SecurityEvent> unexplained = flows.stream()
                    .filter(f -> scores.getOrDefault(f.getId(), 0.0) >= th)
                    .filter(f -> !explained.contains(f.getId()))
                    .toList();
            anomalous = (int) scores.values().stream().filter(s -> s >= th).count();
            found.addAll(mlRule.evaluate(unexplained));
        }

        // ---- de-duplicate against what is already stored (idempotent re-runs)
        Map<String, Detection> byFp = new LinkedHashMap<>();
        found.forEach(d -> byFp.putIfAbsent(d.fingerprint(), d));
        Set<String> existing = alerts.findByFingerprintIn(byFp.keySet()).stream()
                .map(a -> a.getFingerprint()).collect(Collectors.toSet());
        List<AlertService.NewAlert> fresh = byFp.values().stream()
                .filter(d -> !existing.contains(d.fingerprint()))
                .map(d -> new AlertService.NewAlert(d, meanScore(d, scores)))
                .toList();
        int created = alertService.createAlerts(fresh);

        RunResult res = new RunResult(rules.size() + 1, scanned.size(),
                byFp.size(), created, byFp.size() - fresh.size(), mlUp, anomalous, System.currentTimeMillis() - t0);
        log.info("Detection run {}..{}: {}", from, to, res);
        return res;
    }

    public RunResult runAll() {
        List<Object[]> range = events.timeRange();
        if (range.isEmpty() || range.getFirst()[0] == null) {
            return new RunResult(rules.size() + 1, 0, 0, 0, 0, false, 0, 0);
        }
        Instant min = (Instant) range.getFirst()[0];
        Instant max = (Instant) range.getFirst()[1];
        return run(min, max.plusSeconds(1));
    }

    private List<SecurityEvent> load(Map<String, List<SecurityEvent>> cache, Set<EventType> types, Instant from, Instant to) {
        String key = new TreeSet<>(types) + "|" + from + "|" + to;
        return cache.computeIfAbsent(key, k ->
                events.findByEventTypeInAndEventTimeBetweenOrderByEventTimeAsc(types, from, to));
    }

    static Map<String, Object> features(SecurityEvent e) {
        Map<String, Object> m = new HashMap<>(e.getAttributes() == null ? Map.of() : e.getAttributes());
        m.put("Destination Port", e.getDstPort());
        m.put("Protocol", e.getProtocol());
        return m;
    }

    private static Double meanScore(Detection d, Map<Long, Double> scores) {
        if (scores.isEmpty()) return null;
        double sum = 0;
        int n = 0;
        for (SecurityEvent e : d.events()) {
            Double s = scores.get(e.getId());
            if (s != null) { sum += s; n++; }
        }
        return n == 0 ? null : Math.round(sum / n * 1000) / 1000.0;
    }

    /** Lookback-aware window used after ingesting a batch. */
    public RunResult runForRange(Instant min, Instant max) {
        return run(min, max.plus(Duration.ofSeconds(1)));
    }
}
