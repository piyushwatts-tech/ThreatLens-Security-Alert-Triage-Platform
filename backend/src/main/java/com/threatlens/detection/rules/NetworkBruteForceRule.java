package com.threatlens.detection.rules;

import com.threatlens.detection.*;
import com.threatlens.domain.EventType;
import com.threatlens.domain.SecurityEvent;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.*;

/**
 * Many short connections to an authentication service from one source, the
 * network-side signature of SSH/FTP/RDP password guessing (e.g. Patator, Hydra).
 */
@Component
public class NetworkBruteForceRule implements DetectionRule {

    static final Duration WINDOW = Duration.ofMinutes(2);
    static final int THRESHOLD = 20;
    static final Map<Integer, String> AUTH_PORTS = Map.of(
            21, "FTP", 22, "SSH", 23, "Telnet", 445, "SMB", 1433, "MSSQL",
            3306, "MySQL", 3389, "RDP", 5900, "VNC");

    public String id() { return "NET-002"; }
    public String name() { return "Network brute force against auth service"; }
    public String description() { return "High rate of connections from one source to an authentication service (SSH, FTP, RDP, SMB...)."; }
    public MitreTechnique technique() { return MitreTechnique.BRUTE_FORCE; }
    public int baseScore() { return 40; }
    public Set<EventType> eventTypes() { return Set.of(EventType.NETWORK_FLOW); }
    public String logic() { return "count(flows to auth port) >= " + THRESHOLD + " by (src_ip, dst_ip, dst_port) within 2m"; }

    @Override
    public List<Detection> evaluate(List<SecurityEvent> events) {
        List<Detection> out = new ArrayList<>();
        Windows.groupBy(events, e -> e.getDstPort() != null && AUTH_PORTS.containsKey(e.getDstPort()) && e.getSrcIp() != null
                        ? e.getSrcIp() + "->" + e.getDstIp() + ":" + e.getDstPort() : null)
                .forEach((key, flows) -> {
                    for (List<SecurityEvent> burst : Windows.bursts(flows, WINDOW, THRESHOLD, null)) {
                        SecurityEvent f = burst.getFirst();
                        String svc = AUTH_PORTS.get(f.getDstPort());
                        long seconds = Math.max(1, Duration.between(f.getEventTime(), burst.getLast().getEventTime()).toSeconds());
                        double perMin = Math.round(burst.size() * 600.0 / seconds) / 10.0;
                        out.add(Detection.builder(this)
                                .title(svc + " brute force from " + f.getSrcIp() + " against " + f.getDstIp())
                                .description(burst.size() + " " + svc + " connections from " + f.getSrcIp() + " to "
                                        + f.getDstIp() + ":" + f.getDstPort() + " over " + seconds + "s (" + perMin + "/min).")
                                .groupKey(key).srcIp(f.getSrcIp()).dstIp(f.getDstIp())
                                .events(burst)
                                .evidence("service", svc)
                                .evidence("connections", burst.size())
                                .evidence("connectionsPerMinute", perMin)
                                .evidence("durationSeconds", seconds)
                                .factor("remoteAdminService", Set.of(22, 3389, 5900).contains(f.getDstPort()) ? 5 : 0)
                                .build());
                    }
                });
        return out;
    }
}
