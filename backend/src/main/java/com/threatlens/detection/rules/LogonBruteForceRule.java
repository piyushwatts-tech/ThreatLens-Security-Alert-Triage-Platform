package com.threatlens.detection.rules;

import com.threatlens.detection.*;
import com.threatlens.domain.EventType;
import com.threatlens.domain.SecurityEvent;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.*;

/** 5+ failed Windows logons (4625) from one IP within 2 minutes. */
@Component
public class LogonBruteForceRule implements DetectionRule {

    public static final Duration WINDOW = Duration.ofMinutes(2);
    public static final int THRESHOLD = 5;

    public String id() { return "WIN-001"; }
    public String name() { return "Repeated failed logons (brute force)"; }
    public String description() { return "Five or more failed logons from the same source within two minutes."; }
    public MitreTechnique technique() { return MitreTechnique.PASSWORD_GUESSING; }
    public int baseScore() { return 30; }
    public Set<EventType> eventTypes() { return Set.of(EventType.LOGON_FAILURE); }
    public String logic() { return "count(EventID 4625) >= " + THRESHOLD + " by IpAddress within 2m"; }

    @Override
    public List<Detection> evaluate(List<SecurityEvent> events) {
        List<Detection> out = new ArrayList<>();
        Windows.groupBy(events, LogonBruteForceRule::source).forEach((src, fails) -> {
            for (List<SecurityEvent> burst : Windows.bursts(fails, WINDOW, THRESHOLD, null)) {
                Set<String> users = Windows.distinct(burst, SecurityEvent::getUsername);
                Set<String> hosts = Windows.distinct(burst, SecurityEvent::getHost);
                SecurityEvent f = burst.getFirst();
                out.add(Detection.builder(this)
                        .title(burst.size() + " failed logons from " + src + (users.size() == 1 ? " for " + users.iterator().next() : ""))
                        .description(burst.size() + " failed logons (4625) from " + src + " against " + String.join(", ", hosts)
                                + " targeting " + users.size() + " account(s) within "
                                + Duration.between(f.getEventTime(), burst.getLast().getEventTime()).toSeconds() + "s.")
                        .groupKey(src).srcIp(f.getSrcIp()).host(hosts.size() == 1 ? hosts.iterator().next() : null)
                        .username(users.size() == 1 ? users.iterator().next() : null)
                        .events(burst)
                        .evidence("failedLogons", burst.size())
                        .evidence("targetAccounts", users)
                        .evidence("targetHosts", hosts)
                        .evidence("subStatus", Windows.topCounts(burst, e -> (String) e.getAttributes().get("SubStatus"), 3))
                        .factor("privilegedAccount", users.stream().anyMatch(LogonBruteForceRule::isPrivileged) ? 10 : 0)
                        .build());
            }
        });
        return out;
    }

    static String source(SecurityEvent e) {
        return e.getSrcIp() != null ? e.getSrcIp() : e.getHost();
    }

    static boolean isPrivileged(String user) {
        String u = user.toLowerCase(Locale.ROOT);
        return u.equals("administrator") || u.equals("admin") || u.startsWith("adm") || u.endsWith("-admin") || u.equals("root");
    }
}
