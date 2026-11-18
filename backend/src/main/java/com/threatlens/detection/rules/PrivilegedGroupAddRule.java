package com.threatlens.detection.rules;

import com.threatlens.detection.*;
import com.threatlens.domain.EventType;
import com.threatlens.domain.SecurityEvent;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.*;

/** Account added to a privileged group; higher risk when the account was created minutes earlier. */
@Component
public class PrivilegedGroupAddRule implements DetectionRule {

    static final Duration NEW_ACCOUNT_WINDOW = Duration.ofMinutes(60);

    public String id() { return "WIN-005"; }
    public String name() { return "Account added to privileged group"; }
    public String description() { return "A member was added to Administrators / Domain Admins or similar."; }
    public MitreTechnique technique() { return MitreTechnique.ACCOUNT_MANIPULATION; }
    public int baseScore() { return 40; }
    public Set<EventType> eventTypes() { return Set.of(EventType.ACCOUNT_CREATED, EventType.GROUP_MEMBER_ADDED); }
    public Duration lookback() { return NEW_ACCOUNT_WINDOW; }
    public String logic() { return "EventID 4728/4732/4756 to privileged group; +20 if member created (4720) within 60m"; }

    @Override
    public List<Detection> evaluate(List<SecurityEvent> events) {
        List<Detection> out = new ArrayList<>();
        for (SecurityEvent add : events) {
            if (add.getEventType() != EventType.GROUP_MEMBER_ADDED
                    || !Boolean.TRUE.equals(add.getAttributes().get("PrivilegedGroup"))) continue;
            String member = add.getUsername();
            Optional<SecurityEvent> created = events.stream()
                    .filter(c -> c.getEventType() == EventType.ACCOUNT_CREATED && member != null
                            && member.equalsIgnoreCase(c.getUsername())
                            && !c.getEventTime().isAfter(add.getEventTime())
                            && Duration.between(c.getEventTime(), add.getEventTime()).compareTo(NEW_ACCOUNT_WINDOW) <= 0)
                    .findFirst();
            List<SecurityEvent> ev = new ArrayList<>();
            created.ifPresent(ev::add);
            ev.add(add);
            String group = String.valueOf(add.getAttributes().get("GroupName"));
            String actor = String.valueOf(add.getAttributes().getOrDefault("SubjectUserName", "unknown"));
            out.add(Detection.builder(this)
                    .title((created.isPresent() ? "New account " : "Account ") + member + " added to " + group + " on " + add.getHost())
                    .description(actor + " added " + member + " to the privileged group " + group
                            + (created.isPresent() ? ", " + Duration.between(created.get().getEventTime(), add.getEventTime()).toMinutes()
                            + " min after creating the account. Classic persistence pattern." : "."))
                    .groupKey(add.getHost() + "/" + member + "/" + group)
                    .host(add.getHost()).username(member)
                    .events(ev)
                    .evidence("group", group)
                    .evidence("addedBy", actor)
                    .evidence("accountCreatedRecently", created.isPresent())
                    .factor("freshAccount", created.isPresent() ? 20 : 0)
                    .build());
        }
        return out;
    }
}
