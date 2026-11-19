package com.threatlens.detection.rules;

import com.threatlens.detection.*;
import com.threatlens.domain.EventType;
import com.threatlens.domain.SecurityEvent;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.*;

/** One source failing against many different accounts - low-and-slow spraying that evades per-account lockout. */
@Component
public class PasswordSprayRule implements DetectionRule {

    static final Duration WINDOW = Duration.ofMinutes(15);
    static final int DISTINCT_ACCOUNTS = 10;

    public String id() { return "WIN-002"; }
    public String name() { return "Password spraying"; }
    public String description() { return "Failed logons against ten or more distinct accounts from one source within 15 minutes."; }
    public MitreTechnique technique() { return MitreTechnique.PASSWORD_SPRAYING; }
    public int baseScore() { return 45; }
    public Set<EventType> eventTypes() { return Set.of(EventType.LOGON_FAILURE); }
    public Duration lookback() { return WINDOW; }
    public String logic() { return "distinct(TargetUserName of 4625) >= " + DISTINCT_ACCOUNTS + " by IpAddress within 15m"; }

    @Override
    public List<Detection> evaluate(List<SecurityEvent> events) {
        List<Detection> out = new ArrayList<>();
        Windows.groupBy(events, LogonBruteForceRule::source).forEach((src, fails) -> {
            for (List<SecurityEvent> burst : Windows.bursts(fails, WINDOW, DISTINCT_ACCOUNTS, SecurityEvent::getUsername)) {
                Set<String> users = Windows.distinct(burst, SecurityEvent::getUsername);
                Set<String> hosts = Windows.distinct(burst, SecurityEvent::getHost);
                SecurityEvent f = burst.getFirst();
                double perAccount = Math.round(burst.size() * 10.0 / users.size()) / 10.0;
                out.add(Detection.builder(this)
                        .title("Password spray from " + src + " across " + users.size() + " accounts")
                        .description(src + " failed to log on as " + users.size() + " different accounts on "
                                + String.join(", ", hosts) + " (" + perAccount + " attempts per account).")
                        .groupKey(src).srcIp(f.getSrcIp()).host(hosts.size() == 1 ? hosts.iterator().next() : null)
                        .events(burst)
                        .evidence("distinctAccounts", users.size())
                        .evidence("accounts", users)
                        .evidence("attemptsPerAccount", perAccount)
                        .evidence("targetHosts", hosts)
                        .factor("breadth", users.size() >= 25 ? 10 : 0)
                        .build());
            }
        });
        return out;
    }
}
