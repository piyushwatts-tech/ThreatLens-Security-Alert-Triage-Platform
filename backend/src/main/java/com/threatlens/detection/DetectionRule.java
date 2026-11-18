package com.threatlens.detection;

import com.threatlens.domain.EventType;
import com.threatlens.domain.SecurityEvent;

import java.time.Duration;
import java.util.List;
import java.util.Set;

/**
 * A detection rule. Rules are pure functions over a time-ordered slice of
 * normalized events, which keeps them trivially unit-testable.
 */
public interface DetectionRule {

    String id();

    String name();

    String description();

    MitreTechnique technique();

    int baseScore();

    /** Event types this rule needs; the engine only loads these. */
    Set<EventType> eventTypes();

    /** How far before the evaluation range the engine must look to evaluate windows correctly. */
    default Duration lookback() {
        return Duration.ofMinutes(15);
    }

    /** Human-readable logic, shown in the rule catalog (e.g. "count(4625) >= 5 by IpAddress in 2m"). */
    String logic();

    List<Detection> evaluate(List<SecurityEvent> eventsSortedByTime);
}
