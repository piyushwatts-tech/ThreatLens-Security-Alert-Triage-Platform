package com.threatlens.web;

import com.threatlens.detection.DetectionEngine;
import com.threatlens.domain.AlertStatus;
import com.threatlens.domain.Severity;
import com.threatlens.repo.AlertRepository;
import com.threatlens.repo.SecurityEventRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.sql.Timestamp;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.*;

@RestController
@RequestMapping("/api/stats")
public class StatsController {

    private final AlertRepository alerts;
    private final SecurityEventRepository events;
    private final Map<String, String> ruleNames = new HashMap<>();

    public StatsController(AlertRepository alerts, SecurityEventRepository events, DetectionEngine engine) {
        this.alerts = alerts;
        this.events = events;
        engine.catalog().forEach(r -> ruleNames.put(r.id(), r.name()));
    }

    public record Count(String key, long count) {}
    public record TimelinePoint(Instant bucket, long low, long medium, long high, long critical) {}
    public record Overview(long totalAlerts, long openAlerts, long openCritical, Double meanMinutesToClose,
                           Map<String, Long> bySeverity, Map<String, Long> byStatus, List<Count> byTactic,
                           List<Count> byRule, List<TimelinePoint> timeline, List<Count> eventsBySource) {}

    @GetMapping("/overview")
    public Overview overview(@RequestParam(defaultValue = "hour") String bucket) {
        String b = Set.of("minute", "hour", "day").contains(bucket) ? bucket : "hour";
        Map<String, Long> sev = new LinkedHashMap<>();
        for (Severity s : Severity.values()) sev.put(s.name(), 0L);
        alerts.countBySeverity().forEach(r -> sev.put(r[0].toString(), (Long) r[1]));
        Map<String, Long> st = new LinkedHashMap<>();
        for (AlertStatus s : AlertStatus.values()) st.put(s.name(), 0L);
        alerts.countByStatus().forEach(r -> st.put(r[0].toString(), (Long) r[1]));

        long total = st.values().stream().mapToLong(Long::longValue).sum();
        long open = total - st.get("CLOSED");
        long openCritical = alerts.count((root, q, cb) -> cb.and(
                cb.equal(root.get("severity"), Severity.CRITICAL), cb.notEqual(root.get("status"), AlertStatus.CLOSED)));

        List<Count> tactics = alerts.countByTactic().stream()
                .map(r -> new Count(r[0] == null ? "Unmapped" : r[0].toString(), (Long) r[1])).toList();
        List<Count> rules = alerts.countByRule().stream()
                .map(r -> new Count(r[0] + " " + ruleNames.getOrDefault(r[0].toString(), ""), (Long) r[1])).toList();

        Map<Instant, long[]> tl = new TreeMap<>();
        for (Object[] r : alerts.timeline(b)) {
            Instant t = toInstant(r[0]);
            long[] arr = tl.computeIfAbsent(t, k -> new long[4]);
            arr[Severity.valueOf(r[1].toString()).ordinal()] += ((Number) r[2]).longValue();
        }
        List<TimelinePoint> timeline = tl.entrySet().stream()
                .map(e -> new TimelinePoint(e.getKey(), e.getValue()[0], e.getValue()[1], e.getValue()[2], e.getValue()[3]))
                .toList();

        Map<String, Long> bySource = new TreeMap<>();
        events.countBySourceAndType().forEach(r -> bySource.merge(r[0].toString(), (Long) r[2], Long::sum));
        List<Count> ev = bySource.entrySet().stream().map(e -> new Count(e.getKey(), e.getValue())).toList();

        return new Overview(total, open, openCritical, alerts.meanMinutesToClose(), sev, st, tactics, rules, timeline, ev);
    }

    private static Instant toInstant(Object o) {
        if (o instanceof Instant i) return i;
        if (o instanceof Timestamp t) return t.toInstant();
        if (o instanceof OffsetDateTime odt) return odt.toInstant();
        throw new IllegalStateException("Unexpected timestamp type " + o.getClass());
    }
}
