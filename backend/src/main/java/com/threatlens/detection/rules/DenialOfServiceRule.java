package com.threatlens.detection.rules;

import com.threatlens.detection.*;
import com.threatlens.domain.EventType;
import com.threatlens.domain.SecurityEvent;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.*;

/** Flood of flows against one service (volumetric / application-layer DoS such as LOIC, HOIC, Slowloris). */
@Component
public class DenialOfServiceRule implements DetectionRule {

    static final Duration WINDOW = Duration.ofMinutes(1);
    static final int THRESHOLD = 300;

    public String id() { return "NET-003"; }
    public String name() { return "Denial-of-service flood"; }
    public String description() { return "Abnormally high flow rate against a single service."; }
    public MitreTechnique technique() { return MitreTechnique.NETWORK_DOS; }
    public int baseScore() { return 50; }
    public Set<EventType> eventTypes() { return Set.of(EventType.NETWORK_FLOW); }
    public String logic() { return "count(flows) >= " + THRESHOLD + " by (dst_ip, dst_port) within 1m"; }

    @Override
    public List<Detection> evaluate(List<SecurityEvent> events) {
        List<Detection> out = new ArrayList<>();
        Windows.groupBy(events, e -> e.getDstIp() == null || e.getDstPort() == null ? null : e.getDstIp() + ":" + e.getDstPort())
                .forEach((key, flows) -> {
                    for (List<SecurityEvent> burst : Windows.bursts(flows, WINDOW, THRESHOLD, null)) {
                        SecurityEvent f = burst.getFirst();
                        Map<String, Long> sources = Windows.topCounts(burst, SecurityEvent::getSrcIp, 5);
                        String topSrc = sources.keySet().stream().findFirst().orElse(null);
                        long seconds = Math.max(1, Duration.between(f.getEventTime(), burst.getLast().getEventTime()).toSeconds());
                        long packets = burst.stream().mapToLong(e -> e.getPackets() == null ? 0 : e.getPackets()).sum();
                        out.add(Detection.builder(this)
                                .title("DoS flood on " + key + " (" + burst.size() + " flows)")
                                .description(burst.size() + " flows / " + packets + " packets against " + key + " in " + seconds
                                        + "s from " + Windows.distinct(burst, SecurityEvent::getSrcIp).size() + " source(s).")
                                .groupKey(key).srcIp(topSrc).dstIp(f.getDstIp())
                                .events(burst)
                                .evidence("flows", burst.size())
                                .evidence("packets", packets)
                                .evidence("flowsPerSecond", Math.round(burst.size() * 10.0 / seconds) / 10.0)
                                .evidence("topSources", sources)
                                .factor("volume", burst.size() >= 2000 ? 10 : 0)
                                .build());
                    }
                });
        return out;
    }
}
