package com.threatlens.detection.rules;

import com.threatlens.detection.*;
import com.threatlens.domain.EventType;
import com.threatlens.domain.SecurityEvent;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.*;

/** One source touching many distinct ports on one destination in a short window. */
@Component
public class PortScanRule implements DetectionRule {

    static final Duration WINDOW = Duration.ofMinutes(2);
    static final int DISTINCT_PORTS = 20;

    public String id() { return "NET-001"; }
    public String name() { return "Port scan detected"; }
    public String description() { return "A single source probed many distinct ports on one host, typical of reconnaissance (nmap, masscan)."; }
    public MitreTechnique technique() { return MitreTechnique.NETWORK_SERVICE_DISCOVERY; }
    public int baseScore() { return 35; }
    public Set<EventType> eventTypes() { return Set.of(EventType.NETWORK_FLOW); }
    public String logic() { return "distinct(dst_port) >= " + DISTINCT_PORTS + " by (src_ip, dst_ip) within 2m"; }

    @Override
    public List<Detection> evaluate(List<SecurityEvent> events) {
        List<Detection> out = new ArrayList<>();
        Windows.groupBy(events, e -> e.getSrcIp() == null || e.getDstIp() == null ? null : e.getSrcIp() + "->" + e.getDstIp())
                .forEach((key, flows) -> {
                    for (List<SecurityEvent> burst : Windows.bursts(flows, WINDOW, DISTINCT_PORTS, SecurityEvent::getDstPort)) {
                        Set<Integer> ports = Windows.distinct(burst, SecurityEvent::getDstPort);
                        SecurityEvent f = burst.getFirst();
                        long seconds = Math.max(1, Duration.between(f.getEventTime(), burst.getLast().getEventTime()).toSeconds());
                        out.add(Detection.builder(this)
                                .title("Port scan: " + f.getSrcIp() + " probed " + ports.size() + " ports on " + f.getDstIp())
                                .description(f.getSrcIp() + " connected to " + ports.size() + " distinct ports on " + f.getDstIp()
                                        + " in " + seconds + "s (" + burst.size() + " flows).")
                                .groupKey(key).srcIp(f.getSrcIp()).dstIp(f.getDstIp())
                                .events(burst)
                                .evidence("distinctPorts", ports.size())
                                .evidence("portSample", ports.stream().limit(25).toList())
                                .evidence("durationSeconds", seconds)
                                .evidence("flowsPerSecond", Math.round(burst.size() * 10.0 / seconds) / 10.0)
                                .factor("scanBreadth", ports.size() >= 500 ? 10 : ports.size() >= 100 ? 5 : 0)
                                .build());
                    }
                });
        return out;
    }
}
