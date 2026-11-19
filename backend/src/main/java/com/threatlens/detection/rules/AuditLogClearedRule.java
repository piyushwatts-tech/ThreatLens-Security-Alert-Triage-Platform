package com.threatlens.detection.rules;

import com.threatlens.detection.*;
import com.threatlens.domain.EventType;
import com.threatlens.domain.SecurityEvent;
import org.springframework.stereotype.Component;

import java.util.*;

/** Security event log cleared (1102) - attackers wiping their tracks. */
@Component
public class AuditLogClearedRule implements DetectionRule {

    public String id() { return "WIN-006"; }
    public String name() { return "Security audit log cleared"; }
    public String description() { return "The Windows Security log was cleared, which destroys forensic evidence."; }
    public MitreTechnique technique() { return MitreTechnique.CLEAR_EVENT_LOGS; }
    public int baseScore() { return 60; }
    public Set<EventType> eventTypes() { return Set.of(EventType.LOG_CLEARED); }
    public String logic() { return "EventID 1102"; }

    @Override
    public List<Detection> evaluate(List<SecurityEvent> events) {
        return events.stream().map(e -> Detection.builder(this)
                .title("Security log cleared on " + e.getHost() + " by " + e.getUsername())
                .description(e.getUsername() + " cleared the Security event log on " + e.getHost() + ".")
                .groupKey(e.getHost())
                .host(e.getHost()).username(e.getUsername())
                .events(List.of(e))
                .evidence("clearedBy", e.getUsername())
                .build()).toList();
    }
}
