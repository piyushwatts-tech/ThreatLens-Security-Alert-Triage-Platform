package com.threatlens.detection.rules;

import com.threatlens.detection.*;
import com.threatlens.domain.EventType;
import com.threatlens.domain.SecurityEvent;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.*;

/**
 * Correlation rule: a successful logon from a source shortly after that source
 * brute-forced the same account. Strong signal of credential compromise.
 */
@Component
public class LogonAfterBruteForceRule implements DetectionRule {

    static final Duration SUCCESS_WITHIN = Duration.ofMinutes(10);

    public String id() { return "WIN-003"; }
    public String name() { return "Successful logon after brute force"; }
    public String description() { return "A source that just failed repeatedly then logged on successfully: likely compromised credentials."; }
    public MitreTechnique technique() { return MitreTechnique.VALID_ACCOUNTS; }
    public int baseScore() { return 70; }
    public Set<EventType> eventTypes() { return Set.of(EventType.LOGON_FAILURE, EventType.LOGON_SUCCESS); }
    public Duration lookback() { return Duration.ofMinutes(15); }
    public String logic() { return "WIN-001 burst by IpAddress, followed by EventID 4624 from same IpAddress + account within 10m"; }

    @Override
    public List<Detection> evaluate(List<SecurityEvent> events) {
        List<Detection> out = new ArrayList<>();
        Windows.groupBy(events, e -> e.getSrcIp()).forEach((src, evs) -> {
            List<SecurityEvent> fails = evs.stream().filter(e -> e.getEventType() == EventType.LOGON_FAILURE).toList();
            List<SecurityEvent> oks = evs.stream().filter(e -> e.getEventType() == EventType.LOGON_SUCCESS).toList();
            if (fails.isEmpty() || oks.isEmpty()) return;
            for (List<SecurityEvent> burst : Windows.bursts(fails, LogonBruteForceRule.WINDOW, LogonBruteForceRule.THRESHOLD, null)) {
                Set<String> attempted = Windows.distinct(burst, SecurityEvent::getUsername);
                var end = burst.getLast().getEventTime();
                oks.stream()
                        .filter(ok -> !ok.getEventTime().isBefore(burst.getFirst().getEventTime())
                                && !ok.getEventTime().isAfter(end.plus(SUCCESS_WITHIN))
                                && attempted.contains(ok.getUsername()))
                        .findFirst()
                        .ifPresent(ok -> {
                            List<SecurityEvent> all = new ArrayList<>(burst);
                            all.add(ok);
                            all.sort(Comparator.comparing(SecurityEvent::getEventTime));
                            out.add(Detection.builder(this)
                                    .title("Account " + ok.getUsername() + " compromised? Logon succeeded after "
                                            + burst.size() + " failures from " + src)
                                    .description(src + " failed " + burst.size() + " times then logged on as " + ok.getUsername()
                                            + " on " + ok.getHost() + " (logon type " + ok.getAttributes().get("LogonType") + ").")
                                    .groupKey(src + "/" + ok.getUsername()).srcIp(src).host(ok.getHost())
                                    .username(ok.getUsername())
                                    .events(all)
                                    .evidence("failuresBeforeSuccess", burst.size())
                                    .evidence("secondsFromLastFailureToSuccess",
                                            Duration.between(end, ok.getEventTime()).toSeconds())
                                    .evidence("logonType", ok.getAttributes().get("LogonType"))
                                    .factor("privilegedAccount", LogonBruteForceRule.isPrivileged(ok.getUsername()) ? 10 : 0)
                                    .build());
                        });
            }
        });
        return out;
    }
}
