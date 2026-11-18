package com.threatlens.detection;

import com.threatlens.domain.EventType;
import com.threatlens.domain.SecurityEvent;

import java.time.Duration;
import java.util.*;

/**
 * Not a Spring bean on purpose: the engine feeds it only the flows the ML model
 * marked anomalous AND that no signature rule already explained, so it surfaces
 * what the rules miss (e.g. exfiltration over an odd port) rather than duplicating them.
 */
public class MlAnomalyRule implements DetectionRule {

    static final Duration WINDOW = Duration.ofMinutes(5);
    static final int THRESHOLD = 5;

    public String id() { return "ML-001"; }
    public String name() { return "Anomalous network behaviour (ML)"; }
    public String description() { return "Isolation Forest trained on benign CIC-IDS2017 traffic flagged a cluster of flows no signature rule explains."; }
    public MitreTechnique technique() { return MitreTechnique.EXFIL_ALT_PROTOCOL; }
    public int baseScore() { return 40; }
    public Set<EventType> eventTypes() { return Set.of(EventType.NETWORK_FLOW); }
    public String logic() { return "anomaly_score >= model threshold, >= " + THRESHOLD + " flows by (src_ip, dst_ip) within 5m, not covered by a rule"; }

    @Override
    public List<Detection> evaluate(List<SecurityEvent> anomalousFlows) {
        List<Detection> out = new ArrayList<>();
        Windows.groupBy(anomalousFlows, e -> e.getSrcIp() + "->" + e.getDstIp()).forEach((key, flows) -> {
            for (List<SecurityEvent> burst : Windows.bursts(flows, WINDOW, THRESHOLD, null)) {
                SecurityEvent f = burst.getFirst();
                long out_bytes = burst.stream().mapToLong(e -> num(e.getAttributes().get("Total Length of Fwd Packets"))).sum();
                long in_bytes = burst.stream().mapToLong(e -> num(e.getAttributes().get("Total Length of Bwd Packets"))).sum();
                Set<Integer> ports = Windows.distinct(burst, SecurityEvent::getDstPort);
                boolean outbound = isPrivate(f.getSrcIp()) && !isPrivate(f.getDstIp());
                boolean exfilShape = outbound && out_bytes > 5 * Math.max(1, in_bytes);
                Detection.Builder b = Detection.builder(this)
                        .title((exfilShape ? "Possible data exfiltration: " : "Anomalous traffic: ") + f.getSrcIp() + " -> "
                                + f.getDstIp() + ":" + ports.iterator().next())
                        .description(burst.size() + " flows the anomaly model scored as outliers. Sent "
                                + human(out_bytes) + ", received " + human(in_bytes) + " on port(s) " + ports + ".")
                        .groupKey(key).srcIp(f.getSrcIp()).dstIp(f.getDstIp())
                        .events(burst)
                        .evidence("bytesOut", out_bytes)
                        .evidence("bytesIn", in_bytes)
                        .evidence("ports", ports)
                        .evidence("outboundToInternet", outbound)
                        .factor("exfilShape", exfilShape ? 20 : 0);
                if (!exfilShape) {
                    b.technique(new MitreTechnique("T1071", "Application Layer Protocol", "Command and Control"));
                }
                out.add(b.build());
            }
        });
        return out;
    }

    private static long num(Object o) {
        return o instanceof Number n ? n.longValue() : 0;
    }

    static boolean isPrivate(String ip) {
        if (ip == null) return false;
        return ip.startsWith("10.") || ip.startsWith("192.168.") || ip.matches("^172\\.(1[6-9]|2\\d|3[01])\\..*");
    }

    private static String human(long b) {
        if (b > 1 << 20) return String.format("%.1f MB", b / 1048576.0);
        if (b > 1 << 10) return String.format("%.1f KB", b / 1024.0);
        return b + " B";
    }
}
